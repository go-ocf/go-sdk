package local

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/gofrs/uuid"
	"github.com/plgd-dev/kit/log"
	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"

	kitStrings "github.com/plgd-dev/kit/strings"
	"github.com/plgd-dev/sdk/local/core"
	"github.com/plgd-dev/sdk/schema"
)

func getDetails(ctx context.Context, d *core.Device, links schema.ResourceLinks) (interface{}, error) {
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
}

// GetDevices discovers devices in the local mode.
// The deviceResourceType is applied on the client side, because len(deviceResourceType) > 1 does not work with Iotivity 1.3.
func (c *Client) GetDevices(
	ctx context.Context,
	opts ...GetDevicesOption,
) (map[string]DeviceDetails, error) {
	cfg := getDevicesOptions{
		err:                    func(err error) { log.Error(err) },
		getDetails:             getDetails,
		discoveryConfiguration: core.DefaultDiscoveryConfiguration(),
	}
	for _, o := range opts {
		cfg = o.applyOnGetDevices(cfg)
	}
	getDetails := func(ctx context.Context, d *core.Device, links schema.ResourceLinks) (interface{}, error) {
		return cfg.getDetails(ctx, d, patchResourceLinksEndpoints(links, c.disableUDPEndpoints))
	}

	var m sync.Mutex
	var res []DeviceDetails
	devices := func(d DeviceDetails) {
		m.Lock()
		defer m.Unlock()
		res = append(res, d)
	}

	resOwnerships := make(map[string]schema.Doxm)
	ownerships := func(d schema.Doxm) {
		m.Lock()
		defer m.Unlock()
		resOwnerships[d.DeviceID] = d
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ownershipsHandler := newDiscoveryOwnershipsHandler(ctx, cfg.err, ownerships)
	go c.client.GetOwnerships(ctx, cfg.discoveryConfiguration, core.DiscoverAllDevices, ownershipsHandler)

	handler := newDiscoveryHandler(ctx, cfg.resourceTypes, cfg.err, devices, getDetails, c.deviceCache, c.disableUDPEndpoints)
	if err := c.client.GetDevicesV2(ctx, cfg.discoveryConfiguration, handler); err != nil {
		return nil, err
	}

	m.Lock()
	defer m.Unlock()

	ownerID, _ := c.client.GetSdkOwnerID()

	return setOwnership(ownerID, mergeDevices(res), resOwnerships), nil
}

// GetDevicesWithHandler discovers devices using a CoAP multicast request via UDP.
// Device resources can be queried in DeviceHandler using device.Client,
func (c *Client) GetDevicesWithHandler(ctx context.Context, handler core.DeviceHandlerV2, opts ...GetDevicesWithHandlerOption) error {
	cfg := getDevicesWithHandlerOptions{
		discoveryConfiguration: core.DefaultDiscoveryConfiguration(),
	}
	for _, o := range opts {
		cfg = o.applyOnGetGetDevicesWithHandler(cfg)
	}
	return c.client.GetDevicesV2(ctx, cfg.discoveryConfiguration, handler)
}

// OwnershipStatus describes ownership status of the device
type OwnershipStatus string

const (
	// OwnershipStatus_ReadyToBeOwned the device is ready to be owned.
	OwnershipStatus_ReadyToBeOwned OwnershipStatus = "readytobeowned"
	// OwnershipStatus_Owned the device is owned.
	OwnershipStatus_Owned OwnershipStatus = "owned"
	// OwnershipStatus_OwnedByOther the device is owned by another user.
	OwnershipStatus_OwnedByOther OwnershipStatus = "ownedbyother"
	// OwnershipStatus_Unknown the device is unsecure or cannot obtain his status.
	OwnershipStatus_Unknown OwnershipStatus = "unknown"
)

// DeviceDetails describes a device.
type DeviceDetails struct {
	// ID of the device
	ID string
	// Details result of function which can be set via option WithGetDetails(), by default it is nil.
	Details interface{}
	// IsSecured is secured.
	IsSecured bool
	// Ownership describes ownership of the device, for unsecure device it is nil.
	Ownership *schema.Doxm
	// Resources list of the device resources.
	Resources []schema.ResourceLink
	// Resources list of the device endpoints.
	Endpoints []schema.Endpoint
	// Ownership status
	OwnershipStatus OwnershipStatus
}

func newDiscoveryHandler(
	ctx context.Context,
	typeFilter []string,
	errors func(error),
	devices func(DeviceDetails),
	getDetails GetDetailsFunc,
	deviceCache *refDeviceCache,
	disableUDPEndpoints bool,
) *discoveryHandler {
	return &discoveryHandler{typeFilter: typeFilter, errors: errors, devices: devices, getDetails: getDetails, deviceCache: deviceCache, disableUDPEndpoints: disableUDPEndpoints}
}

type detailsWasSet struct {
	sync.Mutex
	wasSet bool
}

type discoveryHandler struct {
	typeFilter          []string
	errors              func(error)
	devices             func(DeviceDetails)
	getDetails          GetDetailsFunc
	deviceCache         *refDeviceCache
	disableUDPEndpoints bool

	getDetailsWasCalled sync.Map
}

func (h *discoveryHandler) Error(err error) { h.errors(err) }

func getDeviceDetails(ctx context.Context, d *core.Device, links schema.ResourceLinks, getDetails GetDetailsFunc) (out DeviceDetails, _ error) {
	link, ok := links.GetResourceLink("/oic/d")
	var eps []schema.Endpoint
	if ok {
		eps = link.GetEndpoints()
	}

	isSecured, err := d.IsSecured(ctx)
	if err != nil {
		return out, err
	}

	details, err := getDetails(ctx, d, links)
	if err != nil {
		return DeviceDetails{}, err
	}

	return DeviceDetails{
		ID:              d.DeviceID(),
		Details:         details,
		IsSecured:       isSecured,
		Resources:       links,
		Endpoints:       eps,
		OwnershipStatus: OwnershipStatus_Unknown,
	}, nil
}

func (h *discoveryHandler) Handle(ctx context.Context, d *core.Device) {
	newRefDev := NewRefDevice(d)
	refDev, stored, err := h.deviceCache.TryStoreDeviceToTemporaryCache(newRefDev)
	if err != nil {
		return
	}
	defer refDev.Release(ctx)
	links, err := getLinksRefDevice(ctx, refDev, h.disableUDPEndpoints)
	d = refDev.Device()
	if err != nil {
		refDev.Device().Close(ctx)
		h.deviceCache.RemoveDevice(ctx, refDev.DeviceID(), refDev)
		if stored {
			return
		}
		refDev, stored, err = h.deviceCache.TryStoreDeviceToTemporaryCache(newRefDev)
		if !stored {
			newRefDev.Release(ctx)
			return
		}
		if err != nil {
			return
		}
		links, err = getLinksRefDevice(ctx, refDev, h.disableUDPEndpoints)
		if err != nil {
			refDev.Device().Close(ctx)
			h.deviceCache.RemoveDevice(ctx, refDev.DeviceID(), refDev)
			refDev.Release(ctx)
			return
		}
		d = refDev.Device()
	} else if !stored {
		newRefDev.Release(ctx)
	}

	deviceTypes := make(kitStrings.Set, len(d.DeviceTypes()))
	deviceTypes.Add(d.DeviceTypes()...)
	if !deviceTypes.HasOneOf(h.typeFilter...) {
		return
	}

	devDetails, err := h.getDeviceDetails(ctx, d, links)
	if err != nil {
		h.Error(err)
		return
	}

	h.devices(devDetails)
}

func (h *discoveryHandler) getDeviceDetails(ctx context.Context, d *core.Device, links schema.ResourceLinks) (out DeviceDetails, _ error) {
	getDetails := h.getDetails
	v, _ := h.getDetailsWasCalled.LoadOrStore(d.DeviceID(), &detailsWasSet{})
	m := v.(*detailsWasSet)
	m.Lock()
	defer m.Unlock()
	if m.wasSet {
		getDetails = func(context.Context, *core.Device, schema.ResourceLinks) (interface{}, error) {
			return nil, nil
		}
	}
	devDetails, err := getDeviceDetails(ctx, d, links, getDetails)
	if err == nil {
		m.wasSet = true
	}
	return devDetails, err
}

func newDiscoveryOwnershipsHandler(
	ctx context.Context,
	errors func(error),
	ownerships func(schema.Doxm),
) *discoveryOwnershipsHandler {
	return &discoveryOwnershipsHandler{errors: errors, ownerships: ownerships}
}

type discoveryOwnershipsHandler struct {
	errors     func(error)
	ownerships func(schema.Doxm)
}

func (h *discoveryOwnershipsHandler) Handle(ctx context.Context, doxm schema.Doxm) {
	h.ownerships(doxm)
}

func (h *discoveryOwnershipsHandler) Error(err error) { h.errors(err) }

func mergeDevices(list []DeviceDetails) map[string]DeviceDetails {
	m := make(map[string]DeviceDetails, len(list))
	for _, i := range list {
		d, ok := m[i.ID]
		if !ok {
			m[i.ID] = i
			d = i
		} else {
			d.Endpoints = mergeEndpoints(d.Endpoints, i.Endpoints)
		}
		if i.Details != nil {
			d.Details = i.Details
		}
		m[i.ID] = d
	}
	return m
}

func mergeEndpoints(a, b []schema.Endpoint) []schema.Endpoint {
	eps := make([]schema.Endpoint, 0, len(a)+len(b))
	eps = append(eps, a...)
	eps = append(eps, b...)
	sort.SliceStable(eps, func(i, j int) bool { return eps[i].URI < eps[j].URI })
	sort.SliceStable(eps, func(i, j int) bool { return eps[i].Priority < eps[j].Priority })
	out := make([]schema.Endpoint, 0, len(eps))
	var last string
	for _, e := range eps {
		if last != e.URI {
			out = append(out, e)
		}
		last = e.URI
	}
	return out
}

func setOwnership(ownerID string, devs map[string]DeviceDetails, owns map[string]schema.Doxm) map[string]DeviceDetails {
	for _, o := range owns {
		v := o
		d, ok := devs[o.DeviceID]
		if ok && d.Ownership == nil {
			d.Ownership = &v
			switch v.OwnerID {
			case uuid.Nil.String():
				d.OwnershipStatus = OwnershipStatus_ReadyToBeOwned
			case ownerID:
				d.OwnershipStatus = OwnershipStatus_Owned
			default:
				d.OwnershipStatus = OwnershipStatus_OwnedByOther
			}
			devs[o.DeviceID] = d
		}
	}
	return devs
}
