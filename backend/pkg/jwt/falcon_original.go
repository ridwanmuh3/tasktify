package jwt

import (
	"crypto"
	"crypto/rand"
	"errors"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
)

type SigningMethodFalcon struct {
	Name string
}

var (
	ErrFalconSignatureInvalid = errors.New("falcon signature is invalid")
	SigningMethodFN512        *SigningMethodFalcon
	SigningMethodFN1024       *SigningMethodFalcon
)

func init() {
	SigningMethodFN512 = &SigningMethodFalcon{AlgFNDSA512}
	RegisterSigningMethod(SigningMethodFN512.Alg(), func() SigningMethod {
		return SigningMethodFN512
	})

	SigningMethodFN1024 = &SigningMethodFalcon{AlgFNDSA1024}
	RegisterSigningMethod(SigningMethodFN1024.Alg(), func() SigningMethod {
		return SigningMethodFN1024
	})
}

func (m *SigningMethodFalcon) Alg() string {
	return m.Name
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an []byte
func (m *SigningMethodFalcon) Verify(signingString string, sig []byte, key any) error {
	falconKey, ok := key.([]byte)
	if !ok {
		return newError("Falcon verify expects []byte", ErrInvalidKeyType)
	}

	isValid := fndsa.Verify(falconKey, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString), sig)
	if !isValid {
		return newError("oqs/Falcon: verification error", ErrFalconSignatureInvalid)
	}

	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an []byte
func (m *SigningMethodFalcon) Sign(signingString string, key any) ([]byte, error) {
	falconKey, ok := key.([]byte)
	if !ok {
		return nil, newError("Falcon sign expects []byte", ErrInvalidKeyType)
	}

	signature, err := fndsa.Sign(rand.Reader, falconKey, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString))
	if err != nil {
		return nil, newError("oqs/Falcon: signing error", err)
	}

	return signature, nil
}

func (m *SigningMethodFalcon) SignPrecompute() bool {
	return false
}
