package jwt

import (
	"github.com/cloudflare/circl/sign/slhdsa"
)

type SigningMethodSLHDSA struct {
	Name string
}

var (
	SigningMethodSLHDSA_SHA2_128f  *SigningMethodSLHDSA
	SigningMethodSLHDSA_SHA2_128s  *SigningMethodSLHDSA
	SigningMethodSLHDSA_SHA2_192f  *SigningMethodSLHDSA
	SigningMethodSLHDSA_SHA2_192s  *SigningMethodSLHDSA
	SigningMethodSLHDSA_SHA2_256f  *SigningMethodSLHDSA
	SigningMethodSLHDSA_SHA2_256s  *SigningMethodSLHDSA
	SigningMethodSLHDSA_SHAKE_128f *SigningMethodSLHDSA
	SigningMethodSLHDSA_SHAKE_128s *SigningMethodSLHDSA
	SigningMethodSLHDSA_SHAKE_192f *SigningMethodSLHDSA
	SigningMethodSLHDSA_SHAKE_192s *SigningMethodSLHDSA
	SigningMethodSLHDSA_SHAKE_256f *SigningMethodSLHDSA
	SigningMethodSLHDSA_SHAKE_256s *SigningMethodSLHDSA
)

func init() {
	SigningMethodSLHDSA_SHA2_128f = &SigningMethodSLHDSA{"SLH-DSA-SHA2-128f"}
	SigningMethodSLHDSA_SHA2_128s = &SigningMethodSLHDSA{"SLH-DSA-SHA2-128s"}
	SigningMethodSLHDSA_SHA2_192f = &SigningMethodSLHDSA{"SLH-DSA-SHA2-192f"}
	SigningMethodSLHDSA_SHA2_192s = &SigningMethodSLHDSA{"SLH-DSA-SHA2-192s"}
	SigningMethodSLHDSA_SHA2_256f = &SigningMethodSLHDSA{"SLH-DSA-SHA2-256f"}
	SigningMethodSLHDSA_SHA2_256s = &SigningMethodSLHDSA{"SLH-DSA-SHA2-256s"}
	SigningMethodSLHDSA_SHAKE_128f = &SigningMethodSLHDSA{"SLH-DSA-SHAKE-128f"}
	SigningMethodSLHDSA_SHAKE_128s = &SigningMethodSLHDSA{"SLH-DSA-SHAKE-128s"}
	SigningMethodSLHDSA_SHAKE_192f = &SigningMethodSLHDSA{"SLH-DSA-SHAKE-192f"}
	SigningMethodSLHDSA_SHAKE_192s = &SigningMethodSLHDSA{"SLH-DSA-SHAKE-192s"}
	SigningMethodSLHDSA_SHAKE_256f = &SigningMethodSLHDSA{"SLH-DSA-SHAKE-256f"}
	SigningMethodSLHDSA_SHAKE_256s = &SigningMethodSLHDSA{"SLH-DSA-SHAKE-256s"}
	RegisterSigningMethod(SigningMethodSLHDSA_SHA2_128f.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHA2_128f
	})
	RegisterSigningMethod(SigningMethodSLHDSA_SHA2_128s.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHA2_128s
	})
	RegisterSigningMethod(SigningMethodSLHDSA_SHA2_192f.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHA2_192f
	})
	RegisterSigningMethod(SigningMethodSLHDSA_SHA2_192s.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHA2_192s
	})
	RegisterSigningMethod(SigningMethodSLHDSA_SHA2_256f.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHA2_256f
	})
	RegisterSigningMethod(SigningMethodSLHDSA_SHA2_256s.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHA2_256s
	})
	RegisterSigningMethod(SigningMethodSLHDSA_SHAKE_128f.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHAKE_128f
	})
	RegisterSigningMethod(SigningMethodSLHDSA_SHAKE_128s.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHAKE_128s
	})
	RegisterSigningMethod(SigningMethodSLHDSA_SHAKE_192f.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHAKE_192f
	})
	RegisterSigningMethod(SigningMethodSLHDSA_SHAKE_192s.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHAKE_192s
	})
	RegisterSigningMethod(SigningMethodSLHDSA_SHAKE_256f.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHAKE_256f
	})
	RegisterSigningMethod(SigningMethodSLHDSA_SHAKE_256s.Alg(), func() SigningMethod {
		return SigningMethodSLHDSA_SHAKE_256s
	})
}

func (m *SigningMethodSLHDSA) Alg() string {
	return m.Name
}

func (m *SigningMethodSLHDSA) Verify(signingString string, sig []byte, key any) error {
	pk, ok := key.(slhdsa.PublicKey)
	if !ok {
		return newError("SLH-DSA verify expects slhdsa.PublicKey key", ErrInvalidKeyType)
	}

	slhdsaMsg := slhdsa.NewMessage([]byte(signingString))
	isValid := slhdsa.Verify(&pk, slhdsaMsg, sig, nil)
	if !isValid {
		return newError("SLH-DSA verify failed", ErrSignatureInvalid)
	}

	return nil
}

func (m *SigningMethodSLHDSA) Sign(signingString string, key any) ([]byte, error) {
	sk, ok := key.(slhdsa.PrivateKey)
	if !ok {
		return nil, newError("SLH-DSA sign expects slhdsa.PrivateKey key", ErrInvalidKeyType)
	}

	slhdsaMsg := slhdsa.NewMessage([]byte(signingString))
	sig, err := slhdsa.SignDeterministic(&sk, slhdsaMsg, nil)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (m *SigningMethodSLHDSA) SignPrecompute() bool {
	return false
}
