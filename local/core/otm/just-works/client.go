package justworks

import (
	"context"
	"encoding/pem"
	"fmt"

	"github.com/pion/dtls/v2"
	kitNet "github.com/plgd-dev/kit/net"
	kitSecurity "github.com/plgd-dev/kit/security"
	"github.com/plgd-dev/sdk/local/core/otm/just-works/cipher"
	"github.com/plgd-dev/sdk/pkg/net/coap"
	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"
	"github.com/plgd-dev/sdk/schema"
)

type CertificateSigner = interface {
	//csr is encoded by PEM and returns PEM
	Sign(ctx context.Context, csr []byte) ([]byte, error)
}

type Client struct {
	signer   CertificateSigner
	dialDTLS DialDTLS
}

type DialDTLS = func(ctx context.Context, addr string, dtlsCfg *dtls.Config, opts ...kitNetCoap.DialOptionFunc) (*coap.ClientCloseHandler, error)

type OptionFunc func(Client) Client

func WithDialDTLS(dial DialDTLS) OptionFunc {
	return func(cfg Client) Client {
		if dial != nil {
			cfg.dialDTLS = dial
		}
		return cfg
	}
}

func NewClient(signer CertificateSigner, opts ...OptionFunc) *Client {
	c := Client{
		signer:   signer,
		dialDTLS: kitNetCoap.DialUDPSecure,
	}
	for _, o := range opts {
		c = o(c)
	}
	return &c
}

func (*Client) Type() schema.OwnerTransferMethod {
	return schema.JustWorks
}

func (c *Client) Dial(ctx context.Context, addr kitNet.Addr, opts ...kitNetCoap.DialOptionFunc) (*kitNetCoap.ClientCloseHandler, error) {
	switch schema.Scheme(addr.GetScheme()) {
	case schema.UDPSecureScheme:
		tlsConfig := dtls.Config{
			CustomCipherSuites: func() []dtls.CipherSuite {
				return []dtls.CipherSuite{cipher.NewTLSAecdhAes128Sha256(dtls.CipherSuiteID(0xff00))}
			},
			CipherSuites: []dtls.CipherSuiteID{},
			ConnectContextMaker: func() (context.Context, func()) {
				return context.WithCancel(ctx)
			},
		}
		return c.dialDTLS(ctx, addr.String(), &tlsConfig, opts...)
	}
	return nil, fmt.Errorf("cannot dial to url %v: scheme %v not supported", addr.URL(), addr.GetScheme())
}

func encodeToPem(encoding schema.CertificateEncoding, data []byte) []byte {
	if encoding == schema.CertificateEncoding_DER {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: data})
	}
	return data
}

func (c *Client) ProvisionOwnerCredentials(ctx context.Context, tlsClient *kitNetCoap.ClientCloseHandler, ownerID, deviceID string) error {
	/*setup credentials - PostOwnerCredential*/
	var csr schema.CertificateSigningRequestResponse
	err := tlsClient.GetResource(ctx, "/oic/sec/csr", &csr)
	if err != nil {
		return fmt.Errorf("cannot get csr for setup device owner credentials: %w", err)
	}

	pemCSR := encodeToPem(csr.Encoding, csr.CSR())

	signedCsr, err := c.signer.Sign(ctx, pemCSR)
	if err != nil {
		return fmt.Errorf("cannot sign csr for setup device owner credentials: %w", err)
	}

	certsFromChain, err := kitSecurity.ParseX509FromPEM(signedCsr)
	if err != nil {
		return fmt.Errorf("Failed to parse chain of X509 certs: %w", err)
	}

	var deviceCredential schema.CredentialResponse
	err = tlsClient.GetResource(ctx, "/oic/sec/cred", &deviceCredential, kitNetCoap.WithCredentialSubject(deviceID))
	if err != nil {
		return fmt.Errorf("cannot get device credential to setup device owner credentials: %w", err)
	}

	for _, cred := range deviceCredential.Credentials {
		switch {
		case cred.Usage == schema.CredentialUsage_CERT && cred.Type == schema.CredentialType_ASYMMETRIC_SIGNING_WITH_CERTIFICATE,
			cred.Usage == schema.CredentialUsage_TRUST_CA && cred.Type == schema.CredentialType_ASYMMETRIC_SIGNING_WITH_CERTIFICATE:
			err = tlsClient.DeleteResource(ctx, "/oic/sec/cred", nil, kitNetCoap.WithCredentialId(cred.ID))
			if err != nil {
				return fmt.Errorf("cannot delete device credentials %v (%v) to setup device owner credentials: %w", cred.ID, cred.Usage, err)
			}
		}
	}

	setIdentityDeviceCredential := schema.CredentialUpdateRequest{
		ResourceOwner: ownerID,
		Credentials: []schema.Credential{
			schema.Credential{
				Subject: deviceID,
				Type:    schema.CredentialType_ASYMMETRIC_SIGNING_WITH_CERTIFICATE,
				Usage:   schema.CredentialUsage_CERT,
				PublicData: &schema.CredentialPublicData{
					DataInternal: string(signedCsr),
					Encoding:     schema.CredentialPublicDataEncoding_PEM,
				},
			},
			schema.Credential{
				Subject: ownerID,
				Type:    schema.CredentialType_ASYMMETRIC_SIGNING_WITH_CERTIFICATE,
				Usage:   schema.CredentialUsage_TRUST_CA,
				PublicData: &schema.CredentialPublicData{
					DataInternal: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certsFromChain[len(certsFromChain)-1].Raw})),
					Encoding:     schema.CredentialPublicDataEncoding_PEM,
				},
			},
		},
	}
	err = tlsClient.UpdateResource(ctx, "/oic/sec/cred", setIdentityDeviceCredential, nil)
	if err != nil {
		return fmt.Errorf("cannot set device identity credentials: %w", err)
	}

	return nil
}
