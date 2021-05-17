package core

import (
	"context"
	"fmt"
	"sync"

	"github.com/gofrs/uuid"
	"github.com/plgd-dev/kit/codec/ocf"
	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"
	"github.com/plgd-dev/sdk/schema"
	"go.uber.org/atomic"
)

func (d *Device) ObserveResourceWithCodec(
	ctx context.Context,
	link schema.ResourceLink,
	codec kitNetCoap.Codec,
	handler ObservationHandler,
	options ...kitNetCoap.OptionFunc,
) (observationID string, _ error) {
	return d.observeResource(ctx, link, codec, handler, options...)
}

type ObservationHandler interface {
	Handle(ctx context.Context, body kitNetCoap.DecodeFunc)
	OnClose()
	Error(err error)
}

func (d *Device) ObserveResource(
	ctx context.Context,
	link schema.ResourceLink,
	handler ObservationHandler,
	options ...kitNetCoap.OptionFunc,
) (observationID string, _ error) {
	codec := ocf.VNDOCFCBORCodec{}
	return d.ObserveResourceWithCodec(ctx, link, codec, handler, options...)
}

func (d *Device) StopObservingResource(
	ctx context.Context,
	observationID string,
) error {
	v, ok := d.observations.Load(observationID)
	if !ok {
		return MakeNotFound(fmt.Errorf("unknown observation %s", observationID))
	}
	d.observations.Delete(observationID)
	o := v.(*observation)
	err := o.Stop(ctx)
	if err != nil {
		return MakeCanceled(fmt.Errorf("could not cancel observation %s: %w", observationID, err))
	}

	return nil
}

func (d *Device) stopObservations(ctx context.Context) error {
	obs := make([]string, 0, 12)
	d.observations.Range(func(key, value interface{}) bool {
		observationID := key.(string)
		obs = append(obs, observationID)
		return false
	})
	var errors []error
	for _, observationID := range obs {
		err := d.StopObservingResource(ctx, observationID)
		if err != nil {
			errors = append(errors, err)
		}
	}
	if len(errors) > 0 {
		return MakeInternal(fmt.Errorf("%v", errors))
	}
	return nil
}

type observation struct {
	id      string
	handler *observationHandler
	client  *kitNetCoap.ClientCloseHandler

	lock      sync.Mutex
	onCloseID int
	obs       kitNetCoap.Observation
}

func (o *observation) Set(onCloseID int, obs kitNetCoap.Observation) {
	o.lock.Lock()
	defer o.lock.Unlock()

	o.onCloseID = onCloseID
	o.obs = obs
}

func (o *observation) Get() (onCloseID int, obs kitNetCoap.Observation) {
	o.lock.Lock()
	defer o.lock.Unlock()

	return o.onCloseID, o.obs
}

func (o *observation) Stop(ctx context.Context) error {
	onCloseID, obs := o.Get()
	o.client.UnregisterCloseHandler(onCloseID)
	if obs != nil {
		o.handler.close()
		err := obs.Cancel(ctx)
		if err != nil {
			return MakeCanceled(fmt.Errorf("cannot cancel observation %s: %w", o.id, err))
		}
		return err
	}
	return nil
}

func (d *Device) observeResource(
	ctx context.Context, link schema.ResourceLink,
	codec kitNetCoap.Codec,
	handler ObservationHandler,
	options ...kitNetCoap.OptionFunc,
) (observationID string, _ error) {

	_, client, err := d.connectToEndpoints(ctx, link.GetEndpoints())

	if err != nil {
		return "", MakeInternal(fmt.Errorf("cannot observe resource %v: %w", link.Href, err))
	}

	options = append(options, kitNetCoap.WithAccept(codec.ContentFormat()))

	id, err := uuid.NewV4()
	if err != nil {
		return "", MakeInternal(fmt.Errorf("observation id generation failed: %w", err))
	}
	h := observationHandler{handler: handler}
	o := &observation{
		id:      id.String(),
		handler: &h,
		client:  client,
	}
	onCloseID := client.RegisterCloseHandler(func(err error) {
		o.handler.OnClose()
		obsCtx, cancel := context.WithCancel(context.Background())
		cancel()
		d.StopObservingResource(obsCtx, o.id)
	})

	obs, err := client.Observe(ctx, link.Href, codec, &h, options...)
	if err != nil {
		client.UnregisterCloseHandler(o.onCloseID)
		return "", err
	}

	o.Set(onCloseID, obs)

	d.observations.Store(o.id, o)
	return o.id, nil
}

type observationHandler struct {
	mutex    sync.Mutex
	handler  ObservationHandler
	isClosed atomic.Bool
}

func (h *observationHandler) close() {
	h.isClosed.Store(true)
}

func (h *observationHandler) Handle(client *kitNetCoap.Client, body kitNetCoap.DecodeFunc) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if h.isClosed.Load() {
		return
	}
	h.handler.Handle(client.Context(), body)
}

func (h *observationHandler) Error(err error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if h.isClosed.Load() {
		return
	}
	h.isClosed.Store(true)
	h.handler.Error(err)
}

func (h *observationHandler) OnClose() {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if h.isClosed.Load() {
		return
	}
	h.isClosed.Store(true)
	h.handler.OnClose()
}
