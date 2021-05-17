package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/pion/dtls/v2"
	"github.com/plgd-dev/kit/net"
	"github.com/plgd-dev/sdk/pkg/net/coap"
	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"
	"github.com/plgd-dev/sdk/schema"
)

type deviceConfiguration struct {
	dialDTLS  DialDTLS
	dialTLS   DialTLS
	dialUDP   DialUDP
	dialTCP   DialTCP
	errFunc   ErrFunc
	tlsConfig *TLSConfig
}

type Device struct {
	deviceID    string
	deviceTypes []string
	endpoints   schema.Endpoints
	cfg         deviceConfiguration

	conn         map[string]*coap.ClientCloseHandler
	observations *sync.Map
	lock         sync.Mutex
}

// GetCertificateFunc returns certificate for connection
type GetCertificateFunc func() (tls.Certificate, error)

// GetCertificateAuthoritiesFunc returns certificate authorities to verify peers
type GetCertificateAuthoritiesFunc func() ([]*x509.Certificate, error)

type TLSConfig struct {
	// User for communication with owned devices and cloud
	GetCertificate            GetCertificateFunc
	GetCertificateAuthorities GetCertificateAuthoritiesFunc
}

func NewDevice(
	cfg deviceConfiguration,
	deviceID string,
	deviceTypes []string,
	endpoints schema.Endpoints,
) *Device {
	return &Device{
		cfg:          cfg,
		deviceID:     deviceID,
		deviceTypes:  deviceTypes,
		endpoints:    endpoints,
		observations: &sync.Map{},
		conn:         make(map[string]*coap.ClientCloseHandler),
	}
}

func (d *Device) popConnections() []*coap.ClientCloseHandler {
	conns := make([]*coap.ClientCloseHandler, 0, 4)
	d.lock.Lock()
	defer d.lock.Unlock()
	for key, conn := range d.conn {
		conns = append(conns, conn)
		delete(d.conn, key)
	}
	return conns
}

// Close closes open connections to the device.
func (d *Device) Close(ctx context.Context) error {
	var errors []error
	err := d.stopObservations(ctx)
	if err != nil {
		errors = append(errors, err)
	}

	for _, conn := range d.popConnections() {
		err = conn.Close()
		if err != nil {
			errors = append(errors, err)
		}
	}
	if len(errors) > 0 {
		return MakeInternal(fmt.Errorf("cannot close device %v: %v", d.DeviceID(), errors))
	}
	return nil
}

func (d *Device) dialTLS(ctx context.Context, addr string, tlsConfig *TLSConfig, verifyPeerCertificate func(verifyPeerCertificate *x509.Certificate) error, dialOptions ...coap.DialOptionFunc) (*coap.ClientCloseHandler, error) {
	cert, err := tlsConfig.GetCertificate()
	if err != nil {
		return nil, err
	}
	cas, err := tlsConfig.GetCertificateAuthorities()
	if err != nil {
		return nil, err
	}
	rootCAs := x509.NewCertPool()
	for _, ca := range cas {
		rootCAs.AddCert(ca)
	}
	tlsCfg := tls.Config{
		InsecureSkipVerify:    true,
		ClientCAs:             rootCAs,
		Certificates:          []tls.Certificate{cert},
		VerifyPeerCertificate: kitNetCoap.NewVerifyPeerCertificate(rootCAs, verifyPeerCertificate),
	}

	return d.cfg.dialTLS(ctx, addr, &tlsCfg, dialOptions...)
}

func (d *Device) dialDTLS(ctx context.Context, addr string, tlsConfig *TLSConfig, verifyPeerCertificate func(verifyPeerCertificate *x509.Certificate) error, dialOptions ...coap.DialOptionFunc) (*coap.ClientCloseHandler, error) {
	cert, err := tlsConfig.GetCertificate()
	if err != nil {
		return nil, err
	}
	cas, err := tlsConfig.GetCertificateAuthorities()
	if err != nil {
		return nil, err
	}
	rootCAs := x509.NewCertPool()
	for _, ca := range cas {
		rootCAs.AddCert(ca)
	}

	tlsCfg := dtls.Config{
		InsecureSkipVerify:    true,
		ClientCAs:             rootCAs,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM},
		Certificates:          []tls.Certificate{cert},
		VerifyPeerCertificate: kitNetCoap.NewVerifyPeerCertificate(rootCAs, verifyPeerCertificate),
	}
	return d.cfg.dialDTLS(ctx, addr, &tlsCfg, dialOptions...)
}

func (d *Device) getConn(addr string) (c *coap.ClientCloseHandler, ok bool) {
	d.lock.Lock()
	defer d.lock.Unlock()
	c, ok = d.conn[addr]
	if ok {
		if c.Context().Err() == nil {
			return c, ok
		}
		delete(d.conn, addr)
	}
	return
}

func (d *Device) dial(ctx context.Context, addr net.Addr, dialOptions ...coap.DialOptionFunc) (*coap.ClientCloseHandler, error) {
	switch schema.Scheme(addr.GetScheme()) {
	case schema.UDPScheme:
		return d.cfg.dialUDP(ctx, addr.String(), dialOptions...)
	case schema.UDPSecureScheme:
		return d.dialDTLS(ctx, addr.String(), d.cfg.tlsConfig, coap.VerifyIndetityCertificate, dialOptions...)
	case schema.TCPScheme:
		return d.cfg.dialTCP(ctx, addr.String(), dialOptions...)
	case schema.TCPSecureScheme:
		return d.dialTLS(ctx, addr.String(), d.cfg.tlsConfig, coap.VerifyIndetityCertificate, dialOptions...)
	}
	return nil, fmt.Errorf("unknown scheme :%v", addr.GetScheme())
}

func (d *Device) connectToEndpoint(ctx context.Context, endpoint schema.Endpoint) (net.Addr, *coap.ClientCloseHandler, error) {
	const errMsg = "cannot connect to %v: %w"
	addr, err := endpoint.GetAddr()
	if err != nil {
		return net.Addr{}, nil, err
	}

	conn, ok := d.getConn(addr.URL())
	if ok {
		return addr, conn, nil
	}
	c, err := d.dial(ctx, addr)
	if err != nil {
		return net.Addr{}, nil, MakeInternal(fmt.Errorf(errMsg, addr.URL(), err))
	}
	d.lock.Lock()
	defer d.lock.Unlock()
	conn, ok = d.conn[addr.URL()]
	if ok {
		c.Close()
		return addr, conn, nil
	}
	c.RegisterCloseHandler(func(error) {
		d.lock.Lock()
		defer d.lock.Unlock()
		delete(d.conn, addr.URL())
	})
	d.conn[addr.URL()] = c
	return addr, c, nil
}

func (d *Device) connectToEndpoints(ctx context.Context, endpoints []schema.Endpoint) (net.Addr, *coap.ClientCloseHandler, error) {
	errors := make([]error, 0, 4)

	for _, endpoint := range endpoints {
		addr, conn, err := d.connectToEndpoint(ctx, endpoint)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		return addr, conn, nil
	}
	if len(errors) > 0 {
		return net.Addr{}, nil, fmt.Errorf("%v", errors)
	}
	return net.Addr{}, nil, MakeInternal(fmt.Errorf("cannot connect to empty endpoints"))
}

func (d *Device) DeviceID() string {
	d.lock.Lock()
	defer d.lock.Unlock()
	return d.deviceID
}

func (d *Device) setDeviceID(deviceID string) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.deviceID = deviceID
}

func (d *Device) DeviceTypes() []string {
	return d.deviceTypes
}
