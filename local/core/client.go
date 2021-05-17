package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/pion/dtls/v2"
	"github.com/plgd-dev/sdk/pkg/net/coap"
	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"

	"github.com/plgd-dev/kit/log"
)

// ErrFunc to log errors in goroutines
type ErrFunc = func(err error)

// Client an OCF local client.
type Client struct {
	tlsConfig *TLSConfig
	errFunc   ErrFunc
	dialDTLS  DialDTLS
	dialTLS   DialTLS
	dialTCP   DialTCP
	dialUDP   DialUDP
}

func checkTLSConfig(cfg *TLSConfig) *TLSConfig {
	if cfg == nil {
		cfg = new(TLSConfig)
	}
	if cfg.GetCertificate == nil {
		cfg.GetCertificate = func() (tls.Certificate, error) {
			return tls.Certificate{}, MakeUnimplemented(fmt.Errorf("not supported"))
		}
	}
	if cfg.GetCertificateAuthorities == nil {
		cfg.GetCertificateAuthorities = func() ([]*x509.Certificate, error) {
			return nil, MakeUnimplemented(fmt.Errorf("not supported"))
		}
	}
	return cfg
}

type config struct {
	tlsConfig *TLSConfig
	errFunc   ErrFunc
	dialDTLS  DialDTLS
	dialTLS   DialTLS
	dialTCP   DialTCP
	dialUDP   DialUDP
}

type OptionFunc func(config) config

func WithTLS(tlsConfig *TLSConfig) OptionFunc {
	return func(cfg config) config {
		if tlsConfig != nil {
			cfg.tlsConfig = tlsConfig
		}
		return cfg
	}
}

// DiscoveryConfiguration setup discovery configuration
type DiscoveryConfiguration struct {
	MulticastHopLimit    int      // default: 2, min value: 1 - don't pass through router, max value: 255, https://tools.ietf.org/html/rfc2460#section-3
	MulticastAddressUDP4 []string // default: "[224.0.1.187:5683] (local.DiscoveryAddressUDP4), empty: don't use ipv4 multicast"
	MulticastAddressUDP6 []string // default: "[ff02::158]:5683", "[ff03::158]:5683", "[ff05::158]:5683]"] (local.DiscoveryAddressUDP6), empty: don't use ipv6 multicast"
}

func WithErr(errFunc ErrFunc) OptionFunc {
	return func(cfg config) config {
		if errFunc != nil {
			cfg.errFunc = errFunc
		}
		return cfg
	}
}

type DialDTLS = func(ctx context.Context, addr string, dtlsCfg *dtls.Config, opts ...kitNetCoap.DialOptionFunc) (*coap.ClientCloseHandler, error)
type DialTLS = func(ctx context.Context, addr string, tlsCfg *tls.Config, opts ...kitNetCoap.DialOptionFunc) (*coap.ClientCloseHandler, error)
type DialUDP = func(ctx context.Context, addr string, opts ...kitNetCoap.DialOptionFunc) (*coap.ClientCloseHandler, error)
type DialTCP = func(ctx context.Context, addr string, opts ...kitNetCoap.DialOptionFunc) (*coap.ClientCloseHandler, error)

func WithDialDTLS(dial DialDTLS) OptionFunc {
	return func(cfg config) config {
		if dial != nil {
			cfg.dialDTLS = dial
		}
		return cfg
	}
}

func WithDialTLS(dial DialTLS) OptionFunc {
	return func(cfg config) config {
		if dial != nil {
			cfg.dialTLS = dial
		}
		return cfg
	}
}

func WithDialTCP(dial DialTCP) OptionFunc {
	return func(cfg config) config {
		if dial != nil {
			cfg.dialTCP = dial
		}
		return cfg
	}
}

func WithDialUDP(dial DialUDP) OptionFunc {
	return func(cfg config) config {
		if dial != nil {
			cfg.dialUDP = dial
		}
		return cfg
	}
}

func (c *Client) getDeviceConfiguration() deviceConfiguration {
	return deviceConfiguration{
		errFunc:   c.errFunc,
		dialDTLS:  c.dialDTLS,
		dialTLS:   c.dialTLS,
		dialTCP:   c.dialTCP,
		dialUDP:   c.dialUDP,
		tlsConfig: c.tlsConfig,
	}
}

func DefaultDiscoveryConfiguration() DiscoveryConfiguration {
	return DiscoveryConfiguration{
		MulticastHopLimit:    2,
		MulticastAddressUDP4: DiscoveryAddressUDP4,
		MulticastAddressUDP6: DiscoveryAddressUDP6,
	}
}

func NewClient(opts ...OptionFunc) *Client {
	cfg := config{
		errFunc: func(err error) {
			log.Debug(err)
		},
		dialDTLS: kitNetCoap.DialUDPSecure,
		dialTLS:  kitNetCoap.DialTCPSecure,
		dialTCP:  kitNetCoap.DialTCP,
		dialUDP:  kitNetCoap.DialUDP,
	}
	for _, o := range opts {
		cfg = o(cfg)
	}

	cfg.tlsConfig = checkTLSConfig(cfg.tlsConfig)
	return &Client{
		dialDTLS:  cfg.dialDTLS,
		dialTLS:   cfg.dialTLS,
		dialTCP:   cfg.dialTCP,
		dialUDP:   cfg.dialUDP,
		errFunc:   cfg.errFunc,
		tlsConfig: cfg.tlsConfig,
	}
}
