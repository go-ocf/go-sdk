package core

import (
	"context"
	"fmt"

	"github.com/plgd-dev/go-coap/v2/message"
	"github.com/plgd-dev/go-coap/v2/message/codes"
	"github.com/plgd-dev/go-coap/v2/udp/client"
	"github.com/plgd-dev/go-coap/v2/udp/message/pool"

	"github.com/plgd-dev/kit/codec/ocf"
	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"
	"github.com/plgd-dev/sdk/schema"
)

// DiscoverDeviceOwnershipHandler receives devices ownership info.
type DiscoverDeviceOwnershipHandler interface {
	Handle(ctx context.Context, client *client.ClientConn, device schema.Doxm)
	Error(err error)
}

// DiscoverOwnershipStatus type of discover ownership status.
type DiscoverOwnershipStatus int

const (
	// DiscoverAllDevices discovers owned and disowned devices.
	DiscoverAllDevices = DiscoverOwnershipStatus(0)
	// DiscoverOwnedDevices discovers owned devices,
	DiscoverOwnedDevices = DiscoverOwnershipStatus(1)
	// DiscoverDisownedDevices discovers disowned devices,
	DiscoverDisownedDevices = DiscoverOwnershipStatus(2)
)

// DiscoverDeviceOwnership discovers devices using a CoAP multicast request via UDP.
// It waits for device responses until the context is canceled.
func DiscoverDeviceOwnership(
	ctx context.Context,
	conn []*DiscoveryClient,
	status DiscoverOwnershipStatus,
	handler DiscoverDeviceOwnershipHandler,
) error {
	var opt kitNetCoap.OptionFunc
	switch status {
	case DiscoverAllDevices:
		return Discover(ctx, conn, schema.DoxmHref, handleDiscoverOwnershipResponse(ctx, handler))
	case DiscoverOwnedDevices:
		opt = func(m message.Options) message.Options {
			buf := make([]byte, 16)
			opts, _, _ := m.AddString(buf, message.URIQuery, "Owned=TRUE")
			return opts
		}
	case DiscoverDisownedDevices:
		opt = func(m message.Options) message.Options {
			buf := make([]byte, 16)
			opts, _, _ := m.AddString(buf, message.URIQuery, "Owned=FALSE")
			return opts
		}
	default:
		return MakeUnimplemented(fmt.Errorf("unsupported DiscoverOwnershipStatus(%v)", status))
	}

	return Discover(ctx, conn, schema.DoxmHref, handleDiscoverOwnershipResponse(ctx, handler), opt)
}

func handleDiscoverOwnershipResponse(ctx context.Context, handler DiscoverDeviceOwnershipHandler) func(client *client.ClientConn, req *pool.Message) {
	return func(client *client.ClientConn, r *pool.Message) {
		req, err := pool.ConvertTo(r)
		if err != nil {
			handler.Error(fmt.Errorf("request failed: %w", err))
		}

		if req.Code != codes.Content {
			handler.Error(fmt.Errorf("request failed: %s", ocf.Dump(req)))
			return
		}

		var doxm schema.Doxm
		var codec ocf.VNDOCFCBORCodec
		err = codec.Decode(req, &doxm)
		if err != nil {
			handler.Error(fmt.Errorf("decoding %v failed: %w", ocf.DumpHeader(req), err))
			return
		}
		handler.Handle(ctx, client, doxm)
	}
}
