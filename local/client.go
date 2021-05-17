package local

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/pion/dtls/v2"

	"github.com/plgd-dev/sdk/local/core"
	"github.com/plgd-dev/sdk/pkg/net/coap"
)

type ApplicationCallback = interface {
	GetRootCertificateAuthorities() ([]*x509.Certificate, error)
	GetManufacturerCertificateAuthorities() ([]*x509.Certificate, error)
	GetManufacturerCertificate() (tls.Certificate, error)
}

type subscription = interface {
	Cancel()
	Wait()
}

type Config struct {
	DeviceCacheExpirationSeconds   int64
	ObserverPollingIntervalSeconds uint64 // 0 means 3 seconds

	KeepAliveConnectionTimeoutSeconds uint64 // 0 means keepalive is disabled
	MaxMessageSize                    int
	DisablePeerTCPSignalMessageCSMs   bool
	HeartBeatSeconds                  uint64

	// specify one of:
	DeviceOwnershipSDK     *DeviceOwnershipSDKConfig     `yaml:",omitempty"`
	DeviceOwnershipBackend *DeviceOwnershipBackendConfig `yaml:",omitempty"`
}

// NewClientFromConfig constructs a new local client from the proto configuration.
func NewClientFromConfig(cfg *Config, app ApplicationCallback, createSigner func(caCert []*x509.Certificate, caKey crypto.PrivateKey, validNotBefore time.Time, validNotAfter time.Time) core.CertificateSigner, errors func(error)) (*Client, error) {
	var cacheExpiration time.Duration
	switch {
	case cfg.DeviceCacheExpirationSeconds < 0:
		cacheExpiration = time.Microsecond
	case cfg.DeviceCacheExpirationSeconds == 0:
		cacheExpiration = time.Second * 3600
	default:
		cacheExpiration = time.Second * time.Duration(cfg.DeviceCacheExpirationSeconds)
	}

	observerPollingInterval := time.Second * 3
	if cfg.ObserverPollingIntervalSeconds > 0 {
		observerPollingInterval = time.Second * time.Duration(cfg.ObserverPollingIntervalSeconds)
	}
	dialOpts := make([]coap.DialOptionFunc, 0, 5)
	if cfg.KeepAliveConnectionTimeoutSeconds > 0 {
		dialOpts = append(dialOpts, coap.WithKeepAlive(time.Second*time.Duration(cfg.KeepAliveConnectionTimeoutSeconds)))
	} else {
		dialOpts = append(dialOpts, coap.WithKeepAlive(time.Second*60))
	}
	if cfg.HeartBeatSeconds > 0 {
		dialOpts = append(dialOpts, coap.WithHeartBeat(time.Second*time.Duration(cfg.HeartBeatSeconds)))
	} else {
		dialOpts = append(dialOpts, coap.WithHeartBeat(time.Second*4))
	}
	if cfg.MaxMessageSize > 0 {
		dialOpts = append(dialOpts, coap.WithMaxMessageSize(cfg.MaxMessageSize))
	} else {
		dialOpts = append(dialOpts, coap.WithMaxMessageSize(512*1024))
	}
	if cfg.DisablePeerTCPSignalMessageCSMs {
		dialOpts = append(dialOpts, coap.WithDialDisablePeerTCPSignalMessageCSMs())
	}
	if errors != nil {
		dialOpts = append(dialOpts, coap.WithErrors(errors))
	} else {
		dialOpts = append(dialOpts, coap.WithErrors(func(error) {}))
	}

	dialTLS := func(ctx context.Context, addr string, tlsCfg *tls.Config, opts ...coap.DialOptionFunc) (*coap.ClientCloseHandler, error) {
		opts = append(opts, dialOpts...)
		return coap.DialTCPSecure(ctx, addr, tlsCfg, opts...)
	}
	dialDTLS := func(ctx context.Context, addr string, dtlsCfg *dtls.Config, opts ...coap.DialOptionFunc) (*coap.ClientCloseHandler, error) {
		opts = append(opts, dialOpts...)
		return coap.DialUDPSecure(ctx, addr, dtlsCfg, opts...)

	}
	dialTCP := func(ctx context.Context, addr string, opts ...coap.DialOptionFunc) (*coap.ClientCloseHandler, error) {
		opts = append(opts, dialOpts...)
		return coap.DialTCP(ctx, addr, opts...)

	}
	dialUDP := func(ctx context.Context, addr string, opts ...coap.DialOptionFunc) (*coap.ClientCloseHandler, error) {
		opts = append(opts, dialOpts...)
		return coap.DialUDP(ctx, addr, opts...)

	}

	opts := []core.OptionFunc{
		core.WithDialDTLS(dialDTLS),
		core.WithDialTLS(dialTLS),
		core.WithDialTCP(dialTCP),
		core.WithDialUDP(dialUDP),
	}

	deviceOwner, err := NewDeviceOwnerFromConfig(cfg, dialTLS, dialDTLS, app, createSigner, errors)
	if err != nil {
		return nil, err
	}
	return NewClient(app, deviceOwner, cacheExpiration, observerPollingInterval, errors, opts...)
}

// NewClient constructs a new local client.
func NewClient(
	app ApplicationCallback,
	deviceOwner DeviceOwner,
	cacheExpiration time.Duration,
	observerPollingInterval time.Duration,
	errors func(error),
	opt ...core.OptionFunc,
) (*Client, error) {
	if app == nil {
		return nil, fmt.Errorf("missing application callback")
	}
	if deviceOwner == nil {
		return nil, fmt.Errorf("missing device owner callback")
	}
	tls := core.TLSConfig{
		GetCertificate:            deviceOwner.GetIdentityCertificate,
		GetCertificateAuthorities: deviceOwner.GetIdentityCACerts,
	}
	opt = append(
		[]core.OptionFunc{
			core.WithTLS(&tls),
		},
		opt...,
	)
	if errors != nil {
		opt = append(opt, core.WithErr(errors))
	}
	oc := core.NewClient(opt...)
	client := Client{
		client:                  oc,
		app:                     app,
		deviceCache:             NewRefDeviceCache(cacheExpiration, errors),
		observeDeviceCache:      make(map[string]*RefDevice),
		deviceOwner:             deviceOwner,
		subscriptions:           make(map[string]subscription),
		observerPollingInterval: observerPollingInterval,
		errors:                  errors,
	}
	return &client, nil
}

type ownFunc = func(ctx context.Context, deviceID string, otmClient core.OTMClient, opts ...core.OwnOption) (string, error)

type DeviceOwner interface {
	Initialization(ctx context.Context) error
	OwnDevice(ctx context.Context, deviceID string, otmType OTMType, own ownFunc, opts ...core.OwnOption) (string, error)

	GetAccessTokenURL(ctx context.Context) (string, error)
	GetOnboardAuthorizationCodeURL(ctx context.Context, deviceID string) (string, error)
	GetIdentityCertificate() (tls.Certificate, error)
	GetIdentityCACerts() ([]*x509.Certificate, error)
	Close(ctx context.Context) error
}

// Client uses the underlying OCF local client.
type Client struct {
	app    ApplicationCallback
	client *core.Client

	deviceCache *refDeviceCache

	observeDeviceCache      map[string]*RefDevice
	observeDeviceCacheLock  sync.Mutex
	observerPollingInterval time.Duration

	deviceOwner         DeviceOwner
	grpcCertificate     tls.Certificate
	identityCertificate tls.Certificate
	rootCA              []*x509.Certificate

	subscriptionsLock sync.Mutex
	subscriptions     map[string]subscription

	disableUDPEndpoints bool
	errors              func(error)
}

func (c *Client) popSubscriptions() map[string]subscription {
	c.subscriptionsLock.Lock()
	defer c.subscriptionsLock.Unlock()
	s := c.subscriptions
	c.subscriptions = make(map[string]subscription)
	return s
}

func (c *Client) popSubscription(ID string) (subscription, error) {
	c.subscriptionsLock.Lock()
	defer c.subscriptionsLock.Unlock()
	v, ok := c.subscriptions[ID]
	if !ok {
		return nil, fmt.Errorf("cannot find observation %v", ID)
	}
	delete(c.subscriptions, ID)
	return v, nil
}

func (c *Client) insertSubscription(ID string, s subscription) {
	c.subscriptionsLock.Lock()
	defer c.subscriptionsLock.Unlock()
	c.subscriptions[ID] = s
}

func (c *Client) CoreClient() *core.Client {
	return c.client
}

// Close clears all connections and spawned goroutines by client.
func (c *Client) Close(ctx context.Context) error {
	var errors []error
	for _, s := range c.popSubscriptions() {
		s.Cancel()
	}
	err := c.deviceCache.Close(ctx)
	if err != nil {
		errors = append(errors, err)
	}

	// observeDeviceCache will be removed by cleaned by close deviceCache

	return nil
}

func NewDeviceOwnerFromConfig(cfg *Config, dialTLS core.DialTLS, dialDTLS core.DialDTLS, app ApplicationCallback, createSigner func(caCert []*x509.Certificate, caKey crypto.PrivateKey, validNotBefore time.Time, validNotAfter time.Time) core.CertificateSigner, errors func(error)) (DeviceOwner, error) {
	if cfg.DeviceOwnershipSDK != nil {
		c, err := NewDeviceOwnershipSDKFromConfig(app, dialTLS, dialDTLS, cfg.DeviceOwnershipSDK, createSigner)
		if err != nil {
			return nil, fmt.Errorf("cannot create sdk signers: %w", err)
		}
		return c, nil
	} else if cfg.DeviceOwnershipBackend != nil {
		c, err := NewDeviceOwnershipBackendFromConfig(app, dialTLS, dialDTLS, cfg.DeviceOwnershipBackend, errors)
		if err != nil {
			return nil, fmt.Errorf("cannot create server signers: %w", err)
		}
		return c, nil
	} else {
		return NewDeviceOwnershipNone(), nil
	}
}
