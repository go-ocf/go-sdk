package resource

import (
	"bytes"
	"context"
	"fmt"

	gocoap "github.com/go-ocf/go-coap"
	"github.com/go-ocf/kit/codec/coap"
	"github.com/go-ocf/kit/net"
	"github.com/go-ocf/kit/sync"
	"github.com/go-ocf/sdk/local/resource/link"
	"github.com/go-ocf/sdk/schema"
)

// Client caches resource links and maintains a pool of connections to devices.
type Client struct {
	linkCache *link.Cache
	pool      *sync.Pool
	codec     Codec
	getAddr   GetAddr
}

type GetAddr = func(*schema.ResourceLink) (net.Addr, error)

// Codec encodes/decodes according to the CoAP content format/media type.
type Codec interface {
	ContentFormat() gocoap.MediaType
	Encode(v interface{}) ([]byte, error)
	Decode(m gocoap.Message, v interface{}) error
}

// Get makes a GET CoAP request over a connection from the client's pool.
func (c *Client) Get(
	ctx context.Context,
	deviceID, href string,
	responseBody interface{},
	options ...func(gocoap.Message),
) error {
	conn, err := c.getConn(ctx, deviceID, href)
	if err != nil {
		return err
	}
	req, err := conn.NewGetRequest(href)
	if err != nil {
		return fmt.Errorf("could create request %s: %v", href, err)
	}
	for _, option := range options {
		option(req)
	}
	resp, err := conn.ExchangeWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("could not query %s: %v", href, err)
	}
	if resp.Code() != gocoap.Content {
		return fmt.Errorf("request failed: %s", coap.Dump(resp))
	}
	if err := c.codec.Decode(resp, responseBody); err != nil {
		return fmt.Errorf("could not decode the query %s: %v", href, err)
	}
	return nil
}

// Post makes a POST CoAP request over a connection from the client's pool.
func (c *Client) Post(
	ctx context.Context,
	deviceID, href string,
	requestBody interface{},
	responseBody interface{},
	options ...func(gocoap.Message),
) error {
	conn, err := c.getConn(ctx, deviceID, href)
	if err != nil {
		return err
	}
	body, err := c.codec.Encode(requestBody)
	if err != nil {
		return fmt.Errorf("could not encode the query %s: %v", href, err)
	}
	req, err := conn.NewPostRequest(href, c.codec.ContentFormat(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("could create request %s: %v", href, err)
	}
	for _, option := range options {
		option(req)
	}
	resp, err := conn.ExchangeWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("could not query %s: %v", href, err)
	}
	if resp.Code() != gocoap.Changed && resp.Code() != gocoap.Valid {
		return fmt.Errorf("request failed: %s", coap.Dump(resp))
	}
	if err := c.codec.Decode(resp, responseBody); err != nil {
		return fmt.Errorf("could not decode the query %s: %v", href, err)
	}
	return nil
}

func (c *Client) getConn(ctx context.Context, deviceID, href string) (*gocoap.ClientConn, error) {
	r, err := c.linkCache.GetOrCreate(ctx, deviceID, href)
	if err != nil {
		return nil, fmt.Errorf("no response from device %s: %v", deviceID, err)
	}
	addr, err := c.getAddr(&r)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint of device %s: %v", deviceID, err)
	}
	conn, err := c.pool.GetOrCreate(ctx, addr.String())
	if err != nil {
		return nil, fmt.Errorf("could not connect to %s: %v", addr.String(), err)
	}
	return conn.(*gocoap.ClientConn), nil
}