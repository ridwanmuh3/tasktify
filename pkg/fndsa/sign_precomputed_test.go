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

func TestPrecomputedSignReusableTree(t *testing.T) {
	for _, logn := range []uint{9, 10} {
		var keySeed [32]byte
		for i := 0; i < len(keySeed); i++ {
			keySeed[i] = byte(int(logn) + i)
		}
		skey, vkey, err := KeyGen(logn, bytes.NewReader(keySeed[:]))
		if err != nil {
			t.Fatalf("keygen failed (logn=%d): %v", logn, err)
		}
		ps, err := NewPrecomputedSigner(skey)
		if err != nil {
			t.Fatalf("precompute failed (logn=%d): %v", logn, err)
		}
		if ps.LogN() != logn {
			t.Fatalf("wrong precomputed degree: got %d, want %d", ps.LogN(), logn)
		}

		for j, data := range [][]byte{
			[]byte("first reusable-tree message"),
			[]byte("second reusable-tree message"),
			[]byte("third reusable-tree message"),
		} {
			var seed [40]byte
			for i := 0; i < len(seed); i++ {
				seed[i] = byte(i + j + int(logn))
			}

			sig1, err := sign_inner_seeded(logn, logn, seed[:], skey, DOMAIN_NONE, 0, data)
			if err != nil {
				t.Fatalf("baseline sign failed (logn=%d, msg=%d): %v", logn, j, err)
			}
			sig2, err := ps.signSeeded(seed[:], DOMAIN_NONE, 0, data)
			if err != nil {
				t.Fatalf("precomputed sign failed (logn=%d, msg=%d): %v", logn, j, err)
			}
			if !bytes.Equal(sig1, sig2) {
				t.Fatalf("signatures differ (logn=%d, msg=%d)", logn, j)
			}
			if !Verify(vkey, DOMAIN_NONE, 0, data, sig2) {
				t.Fatalf("precomputed signature verification failed (logn=%d, msg=%d)", logn, j)
			}
		}
	}
}
