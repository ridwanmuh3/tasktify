package fndsa

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func newDeterministicPrecomputedSigner(t *testing.T, logn uint, keyTag byte) ([]byte, []byte, *PrecomputedSigner) {
	t.Helper()

	var keySeed [32]byte
	for i := 0; i < len(keySeed); i++ {
		keySeed[i] = byte(int(logn)*17 + i + int(keyTag))
	}
	skey, vkey, err := KeyGen(logn, bytes.NewReader(keySeed[:]))
	if err != nil {
		t.Fatalf("keygen failed (logn=%d, tag=%d): %v", logn, keyTag, err)
	}

	var ps *PrecomputedSigner
	if logn >= 9 {
		ps, err = NewPrecomputedSigner(skey)
	} else {
		ps, err = NewPrecomputedSignerWeak(skey)
	}
	if err != nil {
		t.Fatalf("precompute failed (logn=%d, tag=%d): %v", logn, keyTag, err)
	}
	if ps.LogN() != logn {
		t.Fatalf("wrong precomputed degree: got %d, want %d", ps.LogN(), logn)
	}
	return skey, vkey, ps
}

func requireSameF64Slice(t *testing.T, name string, want []f64, got []f64) {
	t.Helper()

	if len(want) != len(got) {
		t.Fatalf("%s length mismatch: got %d, want %d", name, len(got), len(want))
	}
	for i := range want {
		if f64_to_bits(want[i]) != f64_to_bits(got[i]) {
			t.Fatalf("%s mismatch at %d: got %016x, want %016x",
				name, i, f64_to_bits(got[i]), f64_to_bits(want[i]))
		}
	}
}

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

func TestPrecomputedSignerPersistentBytes(t *testing.T) {
	_, _, ps := newDeterministicPrecomputedSigner(t, 9, 0)
	if got := ps.PersistentBytes(); got < 57344 {
		t.Fatalf("persistent bytes too small: got %d, want at least 57344", got)
	}
}

// TestPrecomputedSignRejectsTampering: bit-flip signature / bit-flip
// message rejection for the precomputed signer path specifically.
// Reference: Fouque et al., "Falcon: Fast-Fourier Lattice-based Compact
// Signatures over NTRU" (NIST PQC Round 3 submission) — Verify algorithm,
// https://falcon-sign.info/falcon.pdf; EUF-CMA (Goldwasser/Micali/Rivest,
// 1988). See also TestAttack_BitFlipTampering in fndsa_adversarial_test.go,
// which runs the same two checks against both the original (dynamic)
// signer and this precomputed signer side by side for direct comparison.
func TestPrecomputedSignRejectsTampering(t *testing.T) {
	_, vkey, ps := newDeterministicPrecomputedSigner(t, 9, 1)
	data := []byte("tamper-check message")
	sig, err := ps.Sign(nil, DOMAIN_NONE, 0, data)
	if err != nil {
		t.Fatalf("precomputed sign failed: %v", err)
	}

	tamperedSig := append([]byte(nil), sig...)
	tamperedSig[len(tamperedSig)/2] ^= 0x80
	if Verify(vkey, DOMAIN_NONE, 0, data, tamperedSig) {
		t.Fatal("tampered signature verified")
	}

	tamperedData := append([]byte(nil), data...)
	tamperedData[0] ^= 0x01
	if Verify(vkey, DOMAIN_NONE, 0, tamperedData, sig) {
		t.Fatal("tampered message verified")
	}
}

func TestPrecomputedSignConcurrent(t *testing.T) {
	_, vkey, ps := newDeterministicPrecomputedSigner(t, 9, 2)
	data := []byte("same concurrent message")
	total := 512
	if testing.Short() {
		total = 64
	}

	sigs := make([][]byte, total)
	errs := make(chan error, total)
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := ps.Sign(nil, DOMAIN_NONE, 0, data)
			if err != nil {
				errs <- fmt.Errorf("sign %d: %w", i, err)
				return
			}
			if !Verify(vkey, DOMAIN_NONE, 0, data, sig) {
				errs <- fmt.Errorf("verify %d failed", i)
				return
			}
			sigs[i] = sig
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	seen := make(map[string]struct{}, total)
	for i, sig := range sigs {
		if len(sig) == 0 {
			t.Fatalf("signature %d is empty", i)
		}
		key := string(sig)
		if _, ok := seen[key]; ok {
			t.Fatalf("duplicate signature for same message at index %d", i)
		}
		seen[key] = struct{}{}
	}
}

func TestPrecomputedSignReusableTree(t *testing.T) {
	for logn := uint(2); logn <= 10; logn++ {
		skey, vkey, ps := newDeterministicPrecomputedSigner(t, logn, 0)
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
			ok := Verify(vkey, DOMAIN_NONE, 0, data, sig2)
			if logn < 9 {
				ok = VerifyWeak(vkey, DOMAIN_NONE, 0, data, sig2)
			}
			if !ok {
				t.Fatalf("precomputed signature verification failed (logn=%d, msg=%d)", logn, j)
			}
		}
	}
}

func TestPrecomputedLDLTreeMatchesSamplerRecursion(t *testing.T) {
	for logn := uint(2); logn <= 10; logn++ {
		for keyTag := byte(0); keyTag < 2; keyTag++ {
			_, _, ps := newDeterministicPrecomputedSigner(t, logn, keyTag)
			n := 1 << logn

			g00 := append([]f64(nil), ps.b00...)
			g01 := append([]f64(nil), ps.b01...)
			g11 := append([]f64(nil), ps.b10...)
			gx := append([]f64(nil), ps.b11...)
			fpoly_gram_fft(logn, g00, g01, g11, gx)

			for sampleTag := byte(0); sampleTag < 3; sampleTag++ {
				hm := make([]uint16, n)
				for i := range hm {
					hm[i] = uint16((i*37 + int(logn)*53 + int(keyTag)*97 + int(sampleTag)*193) % int(q))
				}

				t0Base := make([]f64, n)
				t1Base := make([]f64, n)
				fpoly_apply_basis(logn, t0Base, t1Base, ps.b01, ps.b11, hm)

				t0Tree := append([]f64(nil), t0Base...)
				t1Tree := append([]f64(nil), t1Base...)
				t0Ref := append([]f64(nil), t0Base...)
				t1Ref := append([]f64(nil), t1Base...)

				gram00 := append([]f64(nil), g00...)
				gram01 := append([]f64(nil), g01...)
				gram11 := append([]f64(nil), g11...)

				var subseed [56]byte
				for i := 0; i < len(subseed); i++ {
					subseed[i] = byte(i + int(logn)*11 + int(keyTag)*23 + int(sampleTag)*41)
				}
				ssRef := newSampler(logn, subseed[:])
				ssTree := newSampler(logn, subseed[:])
				ssRef.ffsamp_fft(t0Ref, t1Ref, gram00, gram01, gram11, make([]f64, n*4))
				ssTree.ffsamp_fft_precomputed(t0Tree, t1Tree, ps.tree, make([]f64, n*4))

				requireSameF64Slice(t, "sampled t0", t0Ref, t0Tree)
				requireSameF64Slice(t, "sampled t1", t1Ref, t1Tree)
			}
		}
	}
}
