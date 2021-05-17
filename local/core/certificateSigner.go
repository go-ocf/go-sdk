package core

import (
	"context"
)

type CertificateSigner = interface {
	//csr is encoded by PEM and returns PEM
	Sign(ctx context.Context, csr []byte) ([]byte, error)
}
