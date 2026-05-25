package jwt

import (
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

type SigningMethodMLDSA struct {
	Name string
}

var (
	SigningMethodMLDSA44 *SigningMethodMLDSA
	SigningMethodMLDSA65 *SigningMethodMLDSA
	SigningMethodMLDSA87 *SigningMethodMLDSA
)

func init() {
	SigningMethodMLDSA44 = &SigningMethodMLDSA{"ML-DSA-44"}
	RegisterSigningMethod(SigningMethodMLDSA44.Alg(), func() SigningMethod {
		return SigningMethodMLDSA44
	})

	SigningMethodMLDSA65 = &SigningMethodMLDSA{"ML-DSA-65"}
	RegisterSigningMethod(SigningMethodMLDSA65.Alg(), func() SigningMethod {
		return SigningMethodMLDSA65
	})

	SigningMethodMLDSA87 = &SigningMethodMLDSA{"ML-DSA-87"}
	RegisterSigningMethod(SigningMethodMLDSA87.Alg(), func() SigningMethod {
		return SigningMethodMLDSA87
	})
}

func (m *SigningMethodMLDSA) Alg() string {
	return m.Name
}

func (m *SigningMethodMLDSA) Verify(signingString string, sig []byte, key any) error {
	msg := []byte(signingString)

	switch m.Name {
	case "ML-DSA-44":
		pk, ok := key.(*mldsa44.PublicKey)
		if !ok {
			return newError("ML-DSA-44 verify expects *mldsa44.PublicKey", ErrInvalidKeyType)
		}
		if !mldsa44.Verify(pk, msg, nil, sig) {
			return newError("ML-DSA-44 verify failed", ErrSignatureInvalid)
		}

	case "ML-DSA-65":
		pk, ok := key.(*mldsa65.PublicKey)
		if !ok {
			return newError("ML-DSA-65 verify expects *mldsa65.PublicKey", ErrInvalidKeyType)
		}
		if !mldsa65.Verify(pk, msg, nil, sig) {
			return newError("ML-DSA-65 verify failed", ErrSignatureInvalid)
		}

	case "ML-DSA-87":
		pk, ok := key.(*mldsa87.PublicKey)
		if !ok {
			return newError("ML-DSA-87 verify expects *mldsa87.PublicKey", ErrInvalidKeyType)
		}
		if !mldsa87.Verify(pk, msg, nil, sig) {
			return newError("ML-DSA-87 verify failed", ErrSignatureInvalid)
		}

	default:
		return fmt.Errorf("unsupported signing method: %v", m.Name)
	}
	return nil
}

func (m *SigningMethodMLDSA) Sign(signingString string, key any) ([]byte, error) {
	msg := []byte(signingString)

	switch m.Name {
	case "ML-DSA-44":
		sk, ok := key.(*mldsa44.PrivateKey)
		if !ok {
			return nil, newError("ML-DSA-44 sign expects *mldsa44.PrivateKey", ErrInvalidKeyType)
		}
		// ✅ Pre-alokasi slice sesuai ukuran signature
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(sk, msg, nil, false, sig); err != nil {
			return nil, newError("ML-DSA-44 sign failed: "+err.Error(), ErrSignatureInvalid)
		}
		return sig, nil

	case "ML-DSA-65":
		sk, ok := key.(*mldsa65.PrivateKey)
		if !ok {
			return nil, newError("ML-DSA-65 sign expects *mldsa65.PrivateKey", ErrInvalidKeyType)
		}
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(sk, msg, nil, false, sig); err != nil {
			return nil, newError("ML-DSA-65 sign failed: "+err.Error(), ErrSignatureInvalid)
		}
		return sig, nil

	case "ML-DSA-87":
		sk, ok := key.(*mldsa87.PrivateKey)
		if !ok {
			return nil, newError("ML-DSA-87 sign expects *mldsa87.PrivateKey", ErrInvalidKeyType)
		}
		sig := make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(sk, msg, nil, false, sig); err != nil {
			return nil, newError("ML-DSA-87 sign failed: "+err.Error(), ErrSignatureInvalid)
		}
		return sig, nil

	default:
		return nil, fmt.Errorf("unsupported signing method: %s", m.Name)
	}
}

func (m *SigningMethodMLDSA) SignPrecompute() bool {
	return false
}
