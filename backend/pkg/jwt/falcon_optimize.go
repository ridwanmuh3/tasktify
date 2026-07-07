package jwt

import (
	"crypto"
	"crypto/rand"
	"fmt"

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
	SigningMethodFNP512 = &SigningMethodFalconPrecomputed{AlgFNDSA512, nil}
	SigningMethodFNP1024 = &SigningMethodFalconPrecomputed{AlgFNDSA1024, nil}
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
	if err := m.validatePublicKey(falconKey); err != nil {
		return err
	}

	isValid := fndsa.Verify(falconKey, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString), sig)
	if !isValid {
		return newError("oqs/Falcon: verification error", ErrSignatureInvalid)
	}

	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be []byte or *fndsa.PrecomputedSigner.
func (m *SigningMethodFalconPrecomputed) Sign(signingString string, key any) ([]byte, error) {
	signer, err := m.signerForKey(key)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(rand.Reader, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString))
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

func (m *SigningMethodFalconPrecomputed) signerForKey(key any) (*fndsa.PrecomputedSigner, error) {
	var signer *fndsa.PrecomputedSigner
	switch k := key.(type) {
	case nil:
		signer = m.signer
	case []byte:
		var err error
		signer, err = fndsa.NewPrecomputedSigner(k)
		if err != nil {
			return nil, newError("invalid Falcon private key", ErrInvalidKey, err)
		}
	case *fndsa.PrecomputedSigner:
		signer = k
	default:
		return nil, newError("Falcon precomputed sign expects []byte or *fndsa.PrecomputedSigner", ErrInvalidKeyType)
	}
	if signer == nil {
		return nil, newError("precomputed signer not set for Falcon", ErrInvalidKeyType)
	}
	if err := m.validateSigner(signer); err != nil {
		return nil, err
	}
	return signer, nil
}

func (m *SigningMethodFalconPrecomputed) validateSigner(signer *fndsa.PrecomputedSigner) error {
	logn, err := m.expectedLogN()
	if err != nil {
		return err
	}
	if signer.LogN() != logn {
		return newError(fmt.Sprintf("Falcon precomputed signer degree %d does not match %s", 1<<signer.LogN(), m.Alg()), ErrInvalidKey)
	}
	return nil
}

func (m *SigningMethodFalconPrecomputed) validatePublicKey(key []byte) error {
	logn, err := m.expectedLogN()
	if err != nil {
		return err
	}
	if len(key) == 0 || (key[0]&0xF0) != 0x00 || uint(key[0]&0x0F) != logn {
		return newError(fmt.Sprintf("Falcon public key does not match %s", m.Alg()), ErrInvalidKey)
	}
	return nil
}

func (m *SigningMethodFalconPrecomputed) expectedLogN() (uint, error) {
	switch m.Alg() {
	case AlgFNDSA512, LegacyAlgFalconPrecomputed512:
		return 9, nil
	case AlgFNDSA1024, LegacyAlgFalconPrecomputed1024:
		return 10, nil
	default:
		return 0, newError("unsupported Falcon precomputed algorithm", ErrInvalidKey)
	}
}
