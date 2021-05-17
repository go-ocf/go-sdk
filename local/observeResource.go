package local

import (
	"context"
	"fmt"
	"sync"

	codecOcf "github.com/plgd-dev/kit/codec/ocf"
	"github.com/plgd-dev/sdk/local/core"
	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"
)

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
	d, links, err := c.GetRefDevice(ctx, deviceID)
	if err != nil {
		return "", err
	}
	defer d.Release(ctx)
	obsHandler := &observationHandler{
		obs:    handler,
		client: c,
	}

	link, err := core.GetResourceLink(links, href)
	if err != nil {
		return "", err
	}

	observationID, err = d.ObserveResourceWithCodec(ctx, link, cfg.codec, obsHandler)
	if err != nil {
		return "", err
	}

	err = c.deviceCache.StoreDeviceToPermanentCache(d)
	if err != nil {
		return "", err
	}

	d.Acquire()
	obsHandler.Set(observationID)
	c.observeDeviceCacheLock.Lock()
	defer c.observeDeviceCacheLock.Unlock()
	c.observeDeviceCache[observationID] = d

	return observationID, err
}

func (c *Client) popObserveDevice(ctx context.Context, observationID string) (*RefDevice, error) {
	c.observeDeviceCacheLock.Lock()
	defer c.observeDeviceCacheLock.Unlock()
	device, ok := c.observeDeviceCache[observationID]
	if !ok {
		return nil, fmt.Errorf("cannot find observation %v", observationID)
	}
	delete(c.observeDeviceCache, observationID)
	return device, nil
}

func (c *Client) StopObservingResource(ctx context.Context, observationID string) error {
	device, err := c.popObserveDevice(ctx, observationID)
	if err != nil {
		return err
	}
	defer device.Release(ctx)

	err = device.StopObservingResource(ctx, observationID)
	c.deviceCache.RemoveDeviceFromPermanentCache(ctx, device.DeviceID(), device)
	return err
}

type observationHandler struct {
	obs    core.ObservationHandler
	client *Client

	lock          sync.Mutex
	observationID string
}

func (o *observationHandler) Set(observationID string) {
	o.lock.Lock()
	defer o.lock.Unlock()
	o.observationID = observationID
}

func (o *observationHandler) Get() string {
	o.lock.Lock()
	defer o.lock.Unlock()
	return o.observationID
}

func (o *observationHandler) Handle(ctx context.Context, body kitNetCoap.DecodeFunc) {
	o.obs.Handle(ctx, body)
}

func (o *observationHandler) OnClose() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.client.StopObservingResource(ctx, o.Get())
	o.obs.OnClose()
}

func (o *observationHandler) Error(err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.client.StopObservingResource(ctx, o.Get())
	o.obs.Error(err)
}
