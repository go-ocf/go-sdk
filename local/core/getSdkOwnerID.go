package core

import (
	"crypto/x509"
	"fmt"

	kitNetCoap "github.com/plgd-dev/kit/net/coap"
)

// GetSdkOwnerID returns sdk ownerID from sdk identity certificate.
func (d *Device) GetSdkOwnerID() (string, error) {
	cert, err := d.cfg.tlsConfig.GetCertificate()
	if err != nil {
		return "", fmt.Errorf("cannot get sdk id: %w", err)
	}

	var errors []error

	for _, c := range cert.Certificate {
		x509cert, err := x509.ParseCertificate(c)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		deviceId, err := kitNetCoap.GetDeviceIDFromIndetityCertificate(x509cert)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		return deviceId, nil
	}
	return "", fmt.Errorf("cannot get sdk id: %v", errors)
}
