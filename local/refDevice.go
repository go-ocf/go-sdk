package local

import (
	"context"

	"github.com/plgd-dev/kit/sync"
	"github.com/plgd-dev/sdk/local/core"
	"github.com/plgd-dev/sdk/pkg/net/coap"
	"github.com/plgd-dev/sdk/schema"
)

type RefDevice struct {
	obj *sync.RefCounter
}

func NewRefDevice(dev *core.Device) *RefDevice {
	return &RefDevice{obj: sync.NewRefCounter(dev, releaseOcfDevice)}
}

func releaseOcfDevice(ctx context.Context, data interface{}) error {
	dev := data.(*core.Device)
	return dev.Close(ctx)
}

func (d *RefDevice) Acquire() {
	d.obj.Acquire()
}

func (d *RefDevice) Release(ctx context.Context) error {
	return d.obj.Release(ctx)
}

func (d *RefDevice) DeviceID() string {
	return d.Device().DeviceID()
}

func (d *RefDevice) Device() *core.Device {
	return d.obj.Data().(*core.Device)
}

func (d *RefDevice) GetDeviceDetails(ctx context.Context, links schema.ResourceLinks, getDetails GetDetailsFunc) (out DeviceDetails, _ error) {
	return getDeviceDetails(ctx, d.Device(), links, getDetails)
}

func (d *RefDevice) GetResourceWithCodec(
	ctx context.Context,
	link schema.ResourceLink,
	codec coap.Codec,
	response interface{},
	options ...coap.OptionFunc) error {
	return d.Device().GetResourceWithCodec(ctx, link, codec, response, options...)
}

func (d *RefDevice) ObserveResourceWithCodec(
	ctx context.Context,
	link schema.ResourceLink,
	codec coap.Codec,
	handler core.ObservationHandler,
	options ...coap.OptionFunc,
) (observationID string, _ error) {
	return d.Device().ObserveResourceWithCodec(ctx, link, codec, handler, options...)
}

func (d *RefDevice) ObserveResource(
	ctx context.Context,
	link schema.ResourceLink,
	handler core.ObservationHandler,
	options ...coap.OptionFunc,
) (observationID string, _ error) {
	return d.Device().ObserveResource(ctx, link, handler, options...)
}

func (d *RefDevice) StopObservingResource(
	ctx context.Context,
	observationID string,
) error {
	return d.Device().StopObservingResource(ctx, observationID)
}

func (d *RefDevice) IsSecured(ctx context.Context) (bool, error) {
	return d.Device().IsSecured(ctx)
}

func (d *RefDevice) UpdateResource(
	ctx context.Context,
	link schema.ResourceLink,
	request interface{},
	response interface{},
	options ...coap.OptionFunc,
) error {
	return d.Device().UpdateResource(ctx, link, request, response, options...)
}

func (d *RefDevice) UpdateResourceWithCodec(
	ctx context.Context,
	link schema.ResourceLink,
	codec coap.Codec,
	request interface{},
	response interface{},
	options ...coap.OptionFunc,
) error {
	return d.Device().UpdateResourceWithCodec(ctx, link, codec, request, response, options...)
}

func (d *RefDevice) Own(
	ctx context.Context,
	links schema.ResourceLinks,
	otmClient core.OTMClient,
	ownOptions ...core.OwnOption,
) error {
	return d.Device().Own(ctx, links, otmClient, ownOptions...)
}

func (d *RefDevice) Disown(
	ctx context.Context,
	links schema.ResourceLinks,
) error {
	return d.Device().Disown(ctx, links)
}

func (d *RefDevice) Provision(ctx context.Context, links schema.ResourceLinks) (*core.ProvisioningClient, error) {
	return d.Device().Provision(ctx, links)
}

func (d *RefDevice) GetEndpoints(ctx context.Context) ([]schema.Endpoint, error) {
	return d.Device().GetEndpoints(ctx)
}

func (d *RefDevice) GetResourceLinks(ctx context.Context, endpoints []schema.Endpoint, options ...coap.OptionFunc) (schema.ResourceLinks, error) {
	return d.Device().GetResourceLinks(ctx, endpoints, options...)
}

func (d *RefDevice) FactoryReset(ctx context.Context, links schema.ResourceLinks) error {
	return d.Device().FactoryReset(ctx, links)
}

func (d *RefDevice) Reboot(ctx context.Context, links schema.ResourceLinks) error {
	return d.Device().Reboot(ctx, links)
}

func (d *RefDevice) GetOwnership(ctx context.Context, links schema.ResourceLinks) (schema.Doxm, error) {
	return d.Device().GetOwnership(ctx, links)
}
