package jwt_test

import (
	"bytes"
	"testing"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
	"github.com/ridwanmuh3/tasktify/pkg/jwt"
)

func TestFalconPrecomputedSignUsesPrivateKeyMaterial(t *testing.T) {
	skey, vkey := mustFalconKeyPair(t, 9)
	method := &jwt.SigningMethodFalconPrecomputed{Name: "Falcon-Precomputed-512"}
	signingString := "header.payload"

	sig, err := method.Sign(signingString, skey)
	if err != nil {
		t.Fatalf("sign with private key failed: %v", err)
	}
	if err := method.Verify(signingString, sig, vkey); err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	signer, err := fndsa.NewPrecomputedSigner(skey)
	if err != nil {
		t.Fatalf("precompute failed: %v", err)
	}
	sig, err = method.Sign(signingString, signer)
	if err != nil {
		t.Fatalf("sign with precomputed signer failed: %v", err)
	}
	if err := method.Verify(signingString, sig, vkey); err != nil {
		t.Fatalf("verify with precomputed signer failed: %v", err)
	}
}

func TestFalconPrecomputedRejectsAlgorithmDegreeMismatch(t *testing.T) {
	skey1024, vkey1024 := mustFalconKeyPair(t, 10)
	signer1024, err := fndsa.NewPrecomputedSigner(skey1024)
	if err != nil {
		t.Fatalf("precompute failed: %v", err)
	}

	method := &jwt.SigningMethodFalconPrecomputed{Name: "Falcon-Precomputed-512"}
	if _, err := method.Sign("header.payload", signer1024); err == nil {
		t.Fatal("expected sign error for mismatched precomputed signer")
	}
	if err := method.Verify("header.payload", make([]byte, fndsa.SignatureSize(10)), vkey1024); err == nil {
		t.Fatal("expected verify error for mismatched public key")
	}
}

func mustFalconKeyPair(t *testing.T, logn uint) ([]byte, []byte) {
	t.Helper()
	var seed [32]byte
	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i + int(logn))
	}
	skey, vkey, err := fndsa.KeyGen(logn, bytes.NewReader(seed[:]))
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	return skey, vkey
}
