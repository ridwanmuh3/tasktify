package jwt

import (
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
)

type SigningMethodFNDSAPrecomputed struct {
	Name   string
	signer *fndsa.PrecomputedSigner
}

var (
	SigningMethodFNP512  *SigningMethodFNDSAPrecomputed
	SigningMethodFNP1024 *SigningMethodFNDSAPrecomputed
)

func init() {
	SigningMethodFNP512 = &SigningMethodFNDSAPrecomputed{AlgFNDSA512, nil}
	SigningMethodFNP1024 = &SigningMethodFNDSAPrecomputed{AlgFNDSA1024, nil}
}

func (m *SigningMethodFNDSAPrecomputed) Alg() string {
	return m.Name
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an []byte
func (m *SigningMethodFNDSAPrecomputed) Verify(signingString string, sig []byte, key any) error {
	fndsaKey, ok := key.([]byte)
	if !ok {
		return newError("FN-DSA verify expects []byte", ErrInvalidKeyType)
	}
	if err := m.validatePublicKey(fndsaKey); err != nil {
		return err
	}

	isValid := fndsa.Verify(fndsaKey, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString), sig)
	if !isValid {
		return newError("oqs/FN-DSA: verification error", ErrSignatureInvalid)
	}

	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be []byte or *fndsa.PrecomputedSigner.
func (m *SigningMethodFNDSAPrecomputed) Sign(signingString string, key any) ([]byte, error) {
	signer, err := m.signerForKey(key)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(rand.Reader, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString))
	if err != nil {
		return nil, newError("oqs/FN-DSA: signing error", err)
	}

	return signature, nil
}

func (m *SigningMethodFNDSAPrecomputed) SignPrecompute() bool {
	return true
}

func (m *SigningMethodFNDSAPrecomputed) SetPrecomputedSigner(s *fndsa.PrecomputedSigner) {
	m.signer = s
}

func (m *SigningMethodFNDSAPrecomputed) signerForKey(key any) (*fndsa.PrecomputedSigner, error) {
	var signer *fndsa.PrecomputedSigner
	switch k := key.(type) {
	case nil:
		signer = m.signer
	case []byte:
		var err error
		signer, err = fndsa.NewPrecomputedSigner(k)
		if err != nil {
			return nil, newError("invalid FN-DSA private key", ErrInvalidKey, err)
		}
	case *fndsa.PrecomputedSigner:
		signer = k
	default:
		return nil, newError("FN-DSA precomputed sign expects []byte or *fndsa.PrecomputedSigner", ErrInvalidKeyType)
	}
	if signer == nil {
		return nil, newError("precomputed signer not set for FN-DSA", ErrInvalidKeyType)
	}
	if err := m.validateSigner(signer); err != nil {
		return nil, err
	}
	return signer, nil
}

func (m *SigningMethodFNDSAPrecomputed) validateSigner(signer *fndsa.PrecomputedSigner) error {
	logn, err := m.expectedLogN()
	if err != nil {
		return err
	}
	if signer.LogN() != logn {
		return newError(fmt.Sprintf("FN-DSA precomputed signer degree %d does not match %s", 1<<signer.LogN(), m.Alg()), ErrInvalidKey)
	}
	return nil
}

func (m *SigningMethodFNDSAPrecomputed) validatePublicKey(key []byte) error {
	logn, err := m.expectedLogN()
	if err != nil {
		return err
	}
	if len(key) == 0 || (key[0]&0xF0) != 0x00 || uint(key[0]&0x0F) != logn {
		return newError(fmt.Sprintf("FN-DSA public key does not match %s", m.Alg()), ErrInvalidKey)
	}
	return nil
}

func (m *SigningMethodFNDSAPrecomputed) expectedLogN() (uint, error) {
	switch m.Alg() {
	case AlgFNDSA512, LegacyAlgFNDSAPrecomputed512:
		return 9, nil
	case AlgFNDSA1024, LegacyAlgFNDSAPrecomputed1024:
		return 10, nil
	default:
		return 0, newError("unsupported FN-DSA precomputed algorithm", ErrInvalidKey)
	}
}
