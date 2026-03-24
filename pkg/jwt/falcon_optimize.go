package jwt

import (
	"crypto"
	"crypto/rand"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
)

type SigningMethodFalconPrecomputed struct {
	Name   string
	signer *fndsa.PrecomputedSigner
}

var (
	SigningMethodFNP512  *SigningMethodFalconPrecomputed
	SigningMethodFNP1024 *SigningMethodFalconPrecomputed
)

func init() {
	// Falcon-512
	SigningMethodFNP512 = &SigningMethodFalconPrecomputed{"Falcon-Precomputed-512", nil}
	RegisterSigningMethod(SigningMethodFNP512.Alg(), func() SigningMethod {
		return SigningMethodFNP512
	})

	// Falcon-1024
	SigningMethodFNP1024 = &SigningMethodFalconPrecomputed{"Falcon-Precomputed-1024", nil}
	RegisterSigningMethod(SigningMethodFNP1024.Alg(), func() SigningMethod {
		return SigningMethodFNP1024
	})
}

func (m *SigningMethodFalconPrecomputed) Alg() string {
	return m.Name
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an []byte
func (m *SigningMethodFalconPrecomputed) Verify(signingString string, sig []byte, key any) error {
	falconKey, ok := key.([]byte)
	if !ok {
		return newError("Falcon verify expects []byte", ErrInvalidKeyType)
	}

	isValid := fndsa.Verify(falconKey, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString), sig)
	if !isValid {
		return newError("oqs/Falcon: verification error", ErrSignatureInvalid)
	}

	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an []byte
func (m *SigningMethodFalconPrecomputed) Sign(signingString string, _ any) ([]byte, error) {
	if m.signer == nil {
		return nil, newError("precomputed signer not set for Falcon", ErrInvalidKeyType)
	}

	signature, err := m.signer.Sign(rand.Reader, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString))
	if err != nil {
		return nil, newError("oqs/Falcon: signing error", err)
	}

	return signature, nil
}

func (m *SigningMethodFalconPrecomputed) SignPrecompute() bool {
	return true
}

func (m *SigningMethodFalconPrecomputed) SetPrecomputedSigner(s *fndsa.PrecomputedSigner) {
	m.signer = s
}
