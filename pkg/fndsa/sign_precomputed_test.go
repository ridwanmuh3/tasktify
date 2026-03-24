package fndsa

import (
	"bytes"
	"testing"
)

func TestPrecomputedSign(t *testing.T) {
	var seed [40]byte
	for i := 0; i < len(seed); i++ {
		seed[i] = 0x3A
	}
	data := []byte("test precomputed signer")

	rng1 := bytes.NewReader(seed[:])
	sig1, err := Sign(rng1, kat_512_skey, DOMAIN_NONE, 0, data)
	if err != nil {
		t.Fatalf("baseline sign failed: %v", err)
	}

	ps, err := NewPrecomputedSigner(kat_512_skey)
	if err != nil {
		t.Fatalf("precompute failed: %v", err)
	}
	rng2 := bytes.NewReader(seed[:])
	sig2, err := ps.Sign(rng2, DOMAIN_NONE, 0, data)
	if err != nil {
		t.Fatalf("precomputed sign failed: %v", err)
	}

	if !bytes.Equal(sig1, sig2) {
		t.Fatalf("signatures differ between baseline and precomputed")
	}
	if !Verify(kat_512_vkey, DOMAIN_NONE, 0, data, sig2) {
		t.Fatalf("precomputed signature verification failed")
	}
}
