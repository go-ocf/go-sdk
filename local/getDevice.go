package local

import (
	"context"
	"fmt"

	"github.com/plgd-dev/sdk/local/core"
	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"
	"github.com/plgd-dev/sdk/schema"
)

func getLinksRefDevice(ctx context.Context, refDev *RefDevice, disableUDPEndpoints bool) (schema.ResourceLinks, error) {
	endpoints, err := refDev.GetEndpoints(ctx)
	if err != nil {
		return nil, err
	}
	links, err := refDev.GetResourceLinks(ctx, endpoints)
	if err != nil {
		return nil, err
	}
	return patchResourceLinksEndpoints(links, disableUDPEndpoints), nil
}

func getRefDeviceFromCache(ctx context.Context, deviceCache *refDeviceCache,
	deviceID string, disableUDPEndpoints bool) (*RefDevice, schema.ResourceLinks, bool) {
	refDev, ok := deviceCache.GetDevice(ctx, deviceID)
	if ok {
		links, err := getLinksRefDevice(ctx, refDev, disableUDPEndpoints)
		if err != nil {
			refDev.Device().Close(ctx)
			deviceCache.RemoveDevice(ctx, refDev.DeviceID(), refDev)
			refDev.Release(ctx)
			return nil, nil, false
		}
		return refDev, links, true
	}
	return nil, nil, false
}

// GetRefDevice returns device, after using call device.Release to free resources.
func (c *Client) GetRefDevice(
	ctx context.Context,
	deviceID string,
	opts ...GetDeviceOption,
) (*RefDevice, schema.ResourceLinks, error) {
	cfg := getDeviceOptions{
		getDetails:             getDetails,
		discoveryConfiguration: core.DefaultDiscoveryConfiguration(),
	}
	for _, o := range opts {
		cfg = o.applyOnGetDevice(cfg)
	}
	refDev, links, ok := getRefDeviceFromCache(ctx, c.deviceCache, deviceID, c.disableUDPEndpoints)
	if ok {
		return refDev, links, nil
	}
	dev, err := c.client.GetDevice(ctx, cfg.discoveryConfiguration, deviceID)
	if err != nil {
		return nil, nil, err
	}

	newRefDev := NewRefDevice(dev)
	refDev, stored, err := c.deviceCache.TryStoreDeviceToTemporaryCache(newRefDev)
	if err != nil {
		return nil, nil, err
	}
	if !stored {
		newRefDev.Release(ctx)
	}
	links, err = getLinksRefDevice(ctx, refDev, c.disableUDPEndpoints)
	if err != nil {
		refDev.Device().Close(ctx)
		c.deviceCache.RemoveDevice(ctx, refDev.DeviceID(), refDev)
		refDev.Release(ctx)
		return nil, nil, fmt.Errorf("cannot get links for device %v: %w", deviceID, err)
	}
	return refDev, patchResourceLinksEndpoints(links, c.disableUDPEndpoints), nil
}

func (c *Client) GetDevice(ctx context.Context, deviceID string, opts ...GetDeviceOption) (DeviceDetails, error) {
	cfg := getDeviceOptions{
		getDetails: func(ctx context.Context, d *core.Device, links schema.ResourceLinks) (interface{}, error) {
			link := links.GetResourceLinks("oic.wk.d")
			if len(link) == 0 {
				return nil, fmt.Errorf("cannot find device resource at links %+v", links)
			}
			var device schema.Device
			err := d.GetResource(ctx, link[0], &device, kitNetCoap.WithInterface("oic.if.baseline"))
			if err != nil {
				return nil, err
			}
			return &device, nil
		},
	}
	for _, o := range opts {
		cfg = o.applyOnGetDevice(cfg)
	}

	refDev, links, err := c.GetRefDevice(ctx, deviceID)
	if err != nil {
		return DeviceDetails{}, err
	}
	defer refDev.Release(ctx)

	devDetails, err := refDev.GetDeviceDetails(ctx, links, cfg.getDetails)
	if err != nil {
		return DeviceDetails{}, err
	}
	var doxm schema.Doxm
	if devDetails.IsSecured {
		doxm, err = refDev.GetOwnership(ctx, links)
	}
	if err != nil {
		return DeviceDetails{}, err
	}
	ownerID, _ := c.client.GetSdkOwnerID()

	return setOwnership(ownerID, map[string]DeviceDetails{
		devDetails.ID: devDetails,
	}, map[string]schema.Doxm{
		doxm.DeviceID: doxm,
	})[devDetails.ID], nil
}
