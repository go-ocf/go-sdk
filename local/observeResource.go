package local

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gofrs/uuid"
	"github.com/plgd-dev/go-coap/v2/message"
	codecOcf "github.com/plgd-dev/kit/codec/ocf"
	kitSync "github.com/plgd-dev/kit/sync"
	"github.com/plgd-dev/sdk/local/core"
	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"
)

type observerCodec struct {
	contentFormat message.MediaType
}

// ContentFormat propagates the CoAP media type.
func (c observerCodec) ContentFormat() message.MediaType { return c.contentFormat }

// Encode propagates the payload without any conversions.
func (c observerCodec) Encode(v interface{}) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}

// Decode validates the content format and
// propagates the payload to v as *[]byte without any conversions.
func (c observerCodec) Decode(m *message.Message, v interface{}) error {
	if v == nil {
		return nil
	}
	if m.Body == nil {
		return fmt.Errorf("unexpected empty body")
	}
	p, ok := v.(**message.Message)
	if !ok {
		return fmt.Errorf("expected **message.Message instead of %T", v)
	}
	*p = m
	return nil
}

type observationsHandler struct {
	client *Client
	device *RefDevice
	id     string

	sync.Mutex

	observationID string
	lastMessage   atomic.Value

	observations *kitSync.Map
}

type decodeFunc = func(v interface{}, codec kitNetCoap.Codec) error

type observationHandler struct {
	handler      core.ObservationHandler
	codec        kitNetCoap.Codec
	lock         sync.Mutex
	isClosed     bool
	firstMessage decodeFunc
}

func createDecodeFunc(message *message.Message) decodeFunc {
	var l sync.Mutex
	return func(v interface{}, codec kitNetCoap.Codec) error {
		l.Lock()
		defer l.Unlock()
		_, err := message.Body.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}
		return codec.Decode(message, v)
	}
}

func (h *observationHandler) handleMessageLocked(ctx context.Context, decode decodeFunc) {
	if decode == nil {
		return
	}
	if h.isClosed {
		return
	}

	h.handler.Handle(ctx, func(v interface{}) error {
		return decode(v, h.codec)
	})
}

func (h *observationHandler) HandleMessage(ctx context.Context, decode decodeFunc) {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.firstMessage = nil
	h.handleMessageLocked(ctx, decode)
}

func (h *observationHandler) HandleFirstMessage() {
	h.lock.Lock()
	defer h.lock.Unlock()
	if h.firstMessage == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.handleMessageLocked(ctx, h.firstMessage)
}

func (h *observationHandler) OnClose() {
	h.lock.Lock()
	defer h.lock.Unlock()
	if h.isClosed {
		return
	}
	h.isClosed = true
	h.handler.OnClose()
}

func (h *observationHandler) Error(err error) {
	h.lock.Lock()
	defer h.lock.Unlock()
	if h.isClosed {
		return
	}
	h.isClosed = true
	h.handler.Error(err)
}

func getObservationID(resourceCacheID, resourceObservationID string) string {
	return strings.Join([]string{resourceCacheID, resourceObservationID}, "/")
}

func parseIDs(ID string) (string, string, error) {
	v := strings.Split(ID, "/")
	if len(v) != 2 {
		return "", "", fmt.Errorf("invalid ID")
	}
	return v[0], v[1], nil
}

func (c *Client) ObserveResource(
	ctx context.Context,
	deviceID string,
	href string,
	handler core.ObservationHandler,
	opts ...ObserveOption,
) (observationID string, _ error) {
	cfg := observeOptions{
		codec: codecOcf.VNDOCFCBORCodec{},
	}
	for _, o := range opts {
		cfg = o.applyOnObserve(cfg)
	}
	resourceObservationID, err := uuid.NewV4()
	if err != nil {
		return "", err
	}

	key := uuid.NewV5(uuid.NamespaceURL, deviceID+href).String()
	val, loaded := c.observeResourceCache.LoadOrStoreWithFunc(key, func(value interface{}) interface{} {
		h := value.(*observationsHandler)
		h.Lock()
		return h
	}, func() interface{} {
		h := observationsHandler{
			observations: kitSync.NewMap(),
			client:       c,
			id:           key,
		}
		h.Lock()
		return &h
	})
	h := val.(*observationsHandler)
	defer h.Unlock()
	lastMessage := h.lastMessage.Load()
	var firstMessage decodeFunc
	if lastMessage != nil {
		firstMessage = lastMessage.(decodeFunc)
	}

	obsHandler := observationHandler{
		handler:      handler,
		codec:        cfg.codec,
		firstMessage: firstMessage,
	}
	h.observations.Store(resourceObservationID.String(), &obsHandler)
	if loaded {
		go obsHandler.HandleFirstMessage()
		return getObservationID(key, resourceObservationID.String()), nil
	}

	d, links, err := c.GetRefDevice(ctx, deviceID)
	if err != nil {
		return "", err
	}

	defer d.Release(ctx)

	link, err := core.GetResourceLink(links, href)
	if err != nil {
		return "", err
	}

	observationID, err = d.ObserveResourceWithCodec(ctx, link, observerCodec{contentFormat: cfg.codec.ContentFormat()}, h)
	if err != nil {
		return "", err
	}

	err = c.deviceCache.StoreDeviceToPermanentCache(d)
	if err != nil {
		return "", err
	}

	d.Acquire()
	h.observationID = observationID
	h.device = d

	return getObservationID(key, resourceObservationID.String()), err
}

func (c *Client) StopObservingResource(ctx context.Context, observationID string) error {
	resourceCacheID, internalResourceObservationID, err := parseIDs(observationID)
	if err != nil {
		return err
	}
	var resourceObservationID string
	var deleteDevice *RefDevice
	c.observeResourceCache.ReplaceWithFunc(resourceCacheID, func(oldValue interface{}, oldLoaded bool) (newValue interface{}, delete bool) {
		if !oldLoaded {
			return nil, true
		}
		h := oldValue.(*observationsHandler)
		resourceObservationID = h.observationID
		_, ok := h.observations.PullOut(internalResourceObservationID)
		if !ok {
			return h, false
		}

		if h.observations.Length() == 0 {
			deleteDevice = h.device
			return nil, true
		}
		return h, false
	})
	if deleteDevice == nil {
		return nil
	}
	defer deleteDevice.Release(ctx)
	err = deleteDevice.StopObservingResource(ctx, resourceObservationID)
	c.deviceCache.RemoveDeviceFromPermanentCache(ctx, deleteDevice.DeviceID(), deleteDevice)
	return err
}

func (c *Client) closeObservingResource(ctx context.Context, o *observationsHandler) {
	_, ok := c.observeResourceCache.PullOut(o.id)
	if !ok {
		return
	}
	if o.device != nil {
		defer o.device.Release(ctx)
		o.device.StopObservingResource(ctx, o.observationID)
		c.deviceCache.RemoveDeviceFromPermanentCache(ctx, o.device.DeviceID(), o.device)
	}
}

func (o *observationsHandler) Handle(ctx context.Context, body kitNetCoap.DecodeFunc) {
	var message *message.Message
	err := body(&message)
	if err != nil {
		o.Error(err)
		return
	}
	decode := createDecodeFunc(message)
	o.lastMessage.Store(decode)
	observations := make([]*observationHandler, 0, 4)
	o.observations.Range(func(key, value interface{}) bool {
		observations = append(observations, value.(*observationHandler))
		return true
	})
	for _, h := range observations {
		h.HandleMessage(ctx, decode)
	}
}

func (o *observationsHandler) OnClose() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.client.closeObservingResource(ctx, o)
	for _, h := range o.observations.PullOutAll() {
		h.(*observationHandler).handler.OnClose()
	}
}

func (o *observationsHandler) Error(err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.client.closeObservingResource(ctx, o)
	for _, h := range o.observations.PullOutAll() {
		h.(*observationHandler).handler.Error(err)
	}
}
