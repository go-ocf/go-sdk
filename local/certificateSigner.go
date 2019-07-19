package local

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	kitNetCoap "github.com/go-ocf/kit/net/coap"
)

type CertificateSigner interface {
	//csr is encoded by PEM and returns PEM
	Sign(ctx context.Context, csr []byte) ([]byte, error)
}

type BasicCertificateSigner struct {
	caCert   []*x509.Certificate
	caKey    *ecdsa.PrivateKey
	validFor time.Duration
}

func NewBasicCertificateSigner(caCert []*x509.Certificate, caKey *ecdsa.PrivateKey, validFor time.Duration) *BasicCertificateSigner {
	return &BasicCertificateSigner{caCert: caCert, caKey: caKey, validFor: validFor}
}

func createPemChain(intermedateCAs []*x509.Certificate, cert []byte) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 2048))

	// encode cert
	err := pem.Encode(buf, &pem.Block{
		Type: "CERTIFICATE", Bytes: cert,
	})
	if err != nil {
		return nil, err
	}
	// encode intermediate
	for _, ca := range intermedateCAs {
		if bytes.Equal(ca.RawIssuer, ca.RawSubject) {
			continue
		}
		err := pem.Encode(buf, &pem.Block{
			Type: "CERTIFICATE", Bytes: ca.Raw,
		})
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (s *BasicCertificateSigner) Sign(ctx context.Context, csr []byte) (signedCsr []byte, err error) {
	csrBlock, _ := pem.Decode(csr)
	if csrBlock == nil {
		err = fmt.Errorf("pem not found")
		return
	}

	certificateRequest, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return
	}

	err = certificateRequest.CheckSignature()
	if err != nil {
		return
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(s.validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber:       serialNumber,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		Subject:            certificateRequest.Subject,
		PublicKeyAlgorithm: certificateRequest.PublicKeyAlgorithm,
		PublicKey:          certificateRequest.PublicKey,
		SignatureAlgorithm: certificateRequest.SignatureAlgorithm,
		DNSNames:           certificateRequest.DNSNames,
		IPAddresses:        certificateRequest.IPAddresses,
		Extensions:         certificateRequest.Extensions,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{kitNetCoap.ExtendedKeyUsage_IDENTITY_CERTIFICATE},
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	if len(s.caCert) == 0 {
		return nil, fmt.Errorf("cannot sign with empty signer CA certificates")
	}
	signedCsr, err = x509.CreateCertificate(rand.Reader, &template, s.caCert[len(s.caCert)-1], certificateRequest.PublicKey, s.caKey)
	if err != nil {
		return
	}
	return createPemChain(s.caCert, signedCsr)
}
