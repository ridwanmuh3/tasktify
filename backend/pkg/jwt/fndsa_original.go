package jwt

import (
	"crypto"
	"crypto/rand"
	"errors"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
)

type SigningMethodFNDSA struct {
	Name string
}

var (
	ErrFNDSASignatureInvalid = errors.New("falcon signature is invalid")
	SigningMethodFN512        *SigningMethodFNDSA
	SigningMethodFN1024       *SigningMethodFNDSA
)

func init() {
	SigningMethodFN512 = &SigningMethodFNDSA{AlgFNDSA512}
	RegisterSigningMethod(SigningMethodFN512.Alg(), func() SigningMethod {
		return SigningMethodFN512
	})

	SigningMethodFN1024 = &SigningMethodFNDSA{AlgFNDSA1024}
	RegisterSigningMethod(SigningMethodFN1024.Alg(), func() SigningMethod {
		return SigningMethodFN1024
	})
}

func (m *SigningMethodFNDSA) Alg() string {
	return m.Name
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an []byte
func (m *SigningMethodFNDSA) Verify(signingString string, sig []byte, key any) error {
	fndsaKey, ok := key.([]byte)
	if !ok {
		return newError("FN-DSA verify expects []byte", ErrInvalidKeyType)
	}

	isValid := fndsa.Verify(fndsaKey, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString), sig)
	if !isValid {
		return newError("oqs/FN-DSA: verification error", ErrFNDSASignatureInvalid)
	}

	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an []byte
func (m *SigningMethodFNDSA) Sign(signingString string, key any) ([]byte, error) {
	fndsaKey, ok := key.([]byte)
	if !ok {
		return nil, newError("FN-DSA sign expects []byte", ErrInvalidKeyType)
	}

	signature, err := fndsa.Sign(rand.Reader, fndsaKey, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString))
	if err != nil {
		return nil, newError("oqs/FN-DSA: signing error", err)
	}

	return signature, nil
}

func (m *SigningMethodFNDSA) SignPrecompute() bool {
	return false
}
