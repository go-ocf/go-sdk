package core

import (
	"crypto/x509"
	"fmt"

	kitNetCoap "github.com/plgd-dev/sdk/pkg/net/coap"
)

func getSdkOwnerID(getCertificate GetCertificateFunc) (string, error) {
	if getCertificate == nil {
		return "", MakeUnimplemented(fmt.Errorf("getCertificate is not set"))
	}
	cert, err := getCertificate()
	if err != nil {
		return "", MakeInternal(fmt.Errorf("cannot get sdk id: %w", err))
	}

	var errors []error

	for _, c := range cert.Certificate {
		x509cert, err := x509.ParseCertificate(c)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		id, err := kitNetCoap.GetDeviceIDFromIndetityCertificate(x509cert)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		return id, nil
	}
	return "", MakeInternal(fmt.Errorf("cannot get sdk id: %v", errors))
}

// GetSdkOwnerID returns sdk ownerID from sdk identity certificate.
func (c *Client) GetSdkOwnerID() (string, error) {
	id, err := getSdkOwnerID(c.tlsConfig.GetCertificate)
	if err != nil {
		return "", fmt.Errorf("cannot get sdk id: %w", err)
	}
	return id, nil
}

// GetSdkOwnerID returns sdk ownerID from sdk identity certificate.
func (d *Device) GetSdkOwnerID() (string, error) {
	id, err := getSdkOwnerID(d.cfg.tlsConfig.GetCertificate)
	if err != nil {
		return "", fmt.Errorf("cannot get sdk id: %w", err)
	}
	return id, nil
}
