package local

import (
	"context"

	"github.com/plgd-dev/sdk/local/core"
	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"
	"github.com/plgd-dev/sdk/schema"
)

// WithInterface updates/gets resource with interface directly from a device.
func WithInterface(resourceInterface string) ResourceInterfaceOption {
	return ResourceInterfaceOption{
		resourceInterface: resourceInterface,
	}
}

func WithError(err func(error)) ErrorOption {
	return ErrorOption{
		err: err,
	}
}

func WithGetDetails(getDetails func(ctx context.Context, d *core.Device, links schema.ResourceLinks) (interface{}, error)) GetDetailsOption {
	return GetDetailsOption{
		getDetails: getDetails,
	}
}

func WithCodec(codec kitNetCoap.Codec) CodecOption {
	return CodecOption{
		codec: codec,
	}
}

func WithResourceTypes(resourceTypes ...string) ResourceTypesOption {
	return ResourceTypesOption{
		resourceTypes: resourceTypes,
	}
}

// WithActionDuringOwn allows to set deviceID of owned device and other staffo over owner TLS.
func WithActionDuringOwn(actionDuringOwn func(ctx context.Context, client *kitNetCoap.ClientCloseHandler) (string, error)) OwnOption {
	return actionDuringOwnOption{
		actionDuringOwn: actionDuringOwn,
	}
}

// WithOTM allows to set ownership transfer method, by default it is manufacturer.
func WithOTM(otmType OTMType) OwnOption {
	return otmOption{
		otmType: otmType,
	}
}

type ResourceInterfaceOption struct {
	resourceInterface string
}

func (r ResourceInterfaceOption) applyOnGet(opts getOptions) getOptions {
	if r.resourceInterface != "" {
		opts.opts = append(opts.opts, kitNetCoap.WithInterface(r.resourceInterface))
	}
	return opts
}

func (r ResourceInterfaceOption) applyOnUpdate(opts updateOptions) updateOptions {
	if r.resourceInterface != "" {
		opts.opts = append(opts.opts, kitNetCoap.WithInterface(r.resourceInterface))
	}
	return opts
}

type DiscoveryConfigrationOption struct {
	cfg core.DiscoveryConfiguration
}

func (r DiscoveryConfigrationOption) applyOnGetDevice(opts getDeviceOptions) getDeviceOptions {
	opts.discoveryConfiguration = r.cfg
	return opts
}

func (r DiscoveryConfigrationOption) applyOnGetDevices(opts getDevicesOptions) getDevicesOptions {
	opts.discoveryConfiguration = r.cfg
	return opts
}

func (r DiscoveryConfigrationOption) applyOnGetGetDevicesWithHandler(opts getDevicesWithHandlerOptions) getDevicesWithHandlerOptions {
	opts.discoveryConfiguration = r.cfg
	return opts
}

func (r DiscoveryConfigrationOption) applyOnObserveDevices(opts observeDevicesOptions) observeDevicesOptions {
	opts.discoveryConfiguration = r.cfg
	return opts
}

// WithDiscoveryConfigration allows to setup multicast request. By defualt it is send to ipv4 and ipv6.
func WithDiscoveryConfigration(cfg core.DiscoveryConfiguration) DiscoveryConfigrationOption {
	return DiscoveryConfigrationOption{
		cfg: cfg,
	}
}

// GetOption option definition.
type GetOption = interface {
	applyOnGet(opts getOptions) getOptions
}

type getOptions struct {
	opts  []kitNetCoap.OptionFunc
	codec kitNetCoap.Codec
}

type updateOptions struct {
	opts  []kitNetCoap.OptionFunc
	codec kitNetCoap.Codec
}

// UpdateOption option definition.
type UpdateOption = interface {
	applyOnUpdate(opts updateOptions) updateOptions
}

// GetDevicesOption option definition.
type GetDevicesOption = interface {
	applyOnGetDevices(opts getDevicesOptions) getDevicesOptions
}

// GetDeviceOption option definition.
type GetDeviceOption = interface {
	applyOnGetDevice(opts getDeviceOptions) getDeviceOptions
}

type GetDevicesWithHandlerOption = interface {
	applyOnGetGetDevicesWithHandler(opts getDevicesWithHandlerOptions) getDevicesWithHandlerOptions
}

type ObserveDevicesOption = interface {
	applyOnObserveDevices(opts observeDevicesOptions) observeDevicesOptions
}

type ErrorOption struct {
	err func(error)
}

func (r ErrorOption) applyOnGetDevices(opts getDevicesOptions) getDevicesOptions {
	opts.err = r.err
	return opts
}

type GetDetailsFunc = func(context.Context, *core.Device, schema.ResourceLinks) (interface{}, error)

type GetDetailsOption struct {
	getDetails GetDetailsFunc
}

func (r GetDetailsOption) applyOnGetDevices(opts getDevicesOptions) getDevicesOptions {
	opts.getDetails = r.getDetails
	return opts
}

func (r GetDetailsOption) applyOnGetDevice(opts getDeviceOptions) getDeviceOptions {
	opts.getDetails = r.getDetails
	return opts
}

type getDevicesOptions struct {
	resourceTypes          []string
	err                    func(error)
	getDetails             GetDetailsFunc
	discoveryConfiguration core.DiscoveryConfiguration
}

type getDeviceOptions struct {
	getDetails             GetDetailsFunc
	discoveryConfiguration core.DiscoveryConfiguration
}

type getDevicesWithHandlerOptions struct {
	discoveryConfiguration core.DiscoveryConfiguration
}

type observeDevicesOptions struct {
	discoveryConfiguration core.DiscoveryConfiguration
}

type ResourceTypesOption struct {
	resourceTypes []string
}

func (r ResourceTypesOption) applyOnGetDevices(opts getDevicesOptions) getDevicesOptions {
	opts.resourceTypes = r.resourceTypes
	return opts
}

type CodecOption struct {
	codec kitNetCoap.Codec
}

func (r CodecOption) applyOnGet(opts getOptions) getOptions {
	opts.codec = r.codec
	return opts
}

func (r CodecOption) applyOnUpdate(opts updateOptions) updateOptions {
	opts.codec = r.codec
	return opts
}

func (r CodecOption) applyOnObserve(opts observeOptions) observeOptions {
	opts.codec = r.codec
	return opts
}

type observeOptions struct {
	codec kitNetCoap.Codec
}

// ObserveOption option definition.
type ObserveOption = interface {
	applyOnObserve(opts observeOptions) observeOptions
}

type OTMType int

const (
	OTMType_Manufacturer OTMType = 0
	OTMType_JustWorks    OTMType = 1
)

type ownOptions struct {
	opts    []core.OwnOption
	otmType OTMType
}

// OwnOption option definition.
type OwnOption = interface {
	applyOnOwn(opts ownOptions) ownOptions
}

type actionDuringOwnOption struct {
	actionDuringOwn func(ctx context.Context, client *kitNetCoap.ClientCloseHandler) (string, error)
}

func (r actionDuringOwnOption) applyOnOwn(opts ownOptions) ownOptions {
	opts.opts = append(opts.opts, core.WithActionDuringOwn(r.actionDuringOwn))
	return opts
}

type otmOption struct {
	otmType OTMType
}

func (r otmOption) applyOnOwn(opts ownOptions) ownOptions {
	opts.otmType = r.otmType
	return opts
}
