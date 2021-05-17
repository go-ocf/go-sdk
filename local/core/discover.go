package core

import (
	"context"
	"fmt"
	"sync"

	"github.com/plgd-dev/go-coap/v2/message"
	"github.com/plgd-dev/go-coap/v2/net"
	"github.com/plgd-dev/go-coap/v2/udp"
	"github.com/plgd-dev/go-coap/v2/udp/client"
	udpMessage "github.com/plgd-dev/go-coap/v2/udp/message"
	"github.com/plgd-dev/go-coap/v2/udp/message/pool"
	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"
)

// See the section 10.4 on the line 2482 of the Core specification:
// https://openconnectivity.org/specs/OCF_Core_Specification_v2.0.0.pdf
// https://iotivity.org/documentation/linux/programmers-guide
var (
	DiscoveryAddressUDP4 = []string{"224.0.1.187:5683"}
	DiscoveryAddressUDP6 = []string{"[ff02::158]:5683", "[ff03::158]:5683", "[ff05::158]:5683"}
)

type DiscoveryHandler = func(conn *client.ClientConn, req *pool.Message)

type DiscoveryClient struct {
	mcastaddr string
	msgID     uint16
	l         *net.UDPConn
	server    *udp.Server
	wg        sync.WaitGroup
}

func newDiscoveryClient(network, mcastaddr string, msgID uint16, errors func(error)) (*DiscoveryClient, error) {
	l, err := net.NewListenUDP(network, "", net.WithErrors(errors))
	if err != nil {
		return nil, err
	}
	s := udp.NewServer(udp.WithErrors(errors))
	c := &DiscoveryClient{
		mcastaddr: mcastaddr,
		msgID:     uint16(msgID),
		server:    s,
		l:         l,
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		err := s.Serve(l)
		if err != nil {
			errors(err)
		}
	}()
	return c, nil
}

func (d *DiscoveryClient) PublishMsgWithContext(req *pool.Message, discoveryHandler DiscoveryHandler) error {
	req.SetMessageID(d.msgID)
	return d.server.DiscoveryRequest(req, d.mcastaddr, discoveryHandler)
}

func (d *DiscoveryClient) Close() error {
	d.server.Stop()
	err := d.l.Close()
	d.wg.Wait()
	return err
}

// DialDiscoveryAddresses connects to discovery endpoints.
func DialDiscoveryAddresses(ctx context.Context, cfg DiscoveryConfiguration, errors func(error)) []*DiscoveryClient {
	var out []*DiscoveryClient

	// We need to separate messageIDs for upd4 and udp6, because if any docker container has isolated network
	// iotivity-lite gets error EINVAL(22) for sendmsg with UDP6 for some interfaces. If it happens, the device is
	// not discovered and msgid is cached so all other multicast messages from another interfaces are dropped for deduplication.
	msgIDudp4 := udpMessage.GetMID()
	msgIDudp6 := msgIDudp4 + ^uint16(0)/2

	for _, address := range cfg.MulticastAddressUDP4 {
		c, err := newDiscoveryClient("udp4", address, msgIDudp4, errors)
		if err != nil {
			errors(err)
			continue
		}
		out = append(out, c)
	}
	for _, address := range cfg.MulticastAddressUDP6 {
		c, err := newDiscoveryClient("udp6", address, msgIDudp6, errors)
		if err != nil {
			errors(err)
			continue
		}
		out = append(out, c)
	}
	return out
}

// Discover discovers devices using a CoAP multicast request via UDP.
// It waits for device responses until the context is canceled.
// Device resources can be queried in DiscoveryHandler.
// An empty typeFilter queries all resource types.
// Note: Iotivity 1.3 which responds with BadRequest if more than 1 resource type is queried.
func Discover(
	ctx context.Context,
	conn []*DiscoveryClient,
	href string,
	handler DiscoveryHandler,
	options ...kitNetCoap.OptionFunc,
) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errors := make(chan error)

	runDiscovery := runDiscovery(&wg, href, handler, errors, options...)
	for _, c := range conn {
		runDiscovery(ctx, c)
	}

	select {
	case err := <-errors:
		return err
	case <-ctx.Done():
		return nil
	}
}

func runDiscovery(
	wg *sync.WaitGroup,
	href string,
	handler DiscoveryHandler,
	errors chan<- error,
	options ...kitNetCoap.OptionFunc,
) func(ctx context.Context, conn *DiscoveryClient) {
	return func(ctx context.Context, conn *DiscoveryClient) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			opts := make(message.Options, 0, 4)
			for _, o := range options {
				opts = o(opts)
			}
			req, err := client.NewGetRequest(ctx, href, opts...)
			if err != nil {
				errors <- MakeInternal(fmt.Errorf("device discovery request creation failed: %w", err))
				return
			}

			err = conn.PublishMsgWithContext(req, handler)
			if err != nil {
				select {
				case errors <- MakeInternal(fmt.Errorf("device discovery multicast request failed: %w", err)):
				case <-ctx.Done():
				}
				return
			}

			select {
			case <-ctx.Done():
			}
		}()
	}
}
