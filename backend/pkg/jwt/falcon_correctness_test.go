package jwt_test

import (
	"fmt"
	"sync"
	"testing"
	"testing/quick"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
	"github.com/ridwanmuh3/tasktify/pkg/jwt"
)

func newPrecomputedFalconMethod(t *testing.T, skey []byte) *jwt.SigningMethodFalconPrecomputed {
	t.Helper()
	signer, err := fndsa.NewPrecomputedSigner(skey)
	if err != nil {
		t.Fatalf("precompute failed: %v", err)
	}
	method := &jwt.SigningMethodFalconPrecomputed{Name: jwt.AlgFNDSA512}
	method.SetPrecomputedSigner(signer)
	return method
}

func TestFalconJWTSignaturesVerifyAndRejectBitFlips(t *testing.T) {
	skey, vkey := mustFalconKeyPair(t, 9)
	precomputed := newPrecomputedFalconMethod(t, skey)

	methods := []struct {
		name   string
		method jwt.SigningMethod
		key    any
	}{
		{name: "dynamic", method: jwt.SigningMethodFN512, key: skey},
		{name: "precomputed", method: precomputed, key: nil},
	}
	messages := []string{
		"header.payload",
		"header.payload.with.more.context",
		`{"alg":"FN-DSA-512"}.{"sub":"user-1","scope":"test"}`,
	}

	for _, method := range methods {
		for _, message := range messages {
			t.Run(method.name+"/"+message, func(t *testing.T) {
				sig, err := method.method.Sign(message, method.key)
				if err != nil {
					t.Fatalf("sign failed: %v", err)
				}
				if err := method.method.Verify(message, sig, vkey); err != nil {
					t.Fatalf("verify failed: %v", err)
				}

				tamperedSig := append([]byte(nil), sig...)
				tamperedSig[len(tamperedSig)/2] ^= 0x01
				if err := method.method.Verify(message, tamperedSig, vkey); err == nil {
					t.Fatal("tampered signature verified")
				}

				if err := method.method.Verify(message+"x", sig, vkey); err == nil {
					t.Fatal("tampered message verified")
				}
			})
		}
	}
}

func TestFalconSameMessageSignaturesRemainValid(t *testing.T) {
	skey, vkey := mustFalconKeyPair(t, 9)
	precomputed := newPrecomputedFalconMethod(t, skey)
	message := "same-message-validity"

	for _, method := range []struct {
		name   string
		method jwt.SigningMethod
		key    any
	}{
		{name: "dynamic", method: jwt.SigningMethodFN512, key: skey},
		{name: "precomputed", method: precomputed, key: nil},
	} {
		t.Run(method.name, func(t *testing.T) {
			for i := 0; i < 5; i++ {
				sig, err := method.method.Sign(message, method.key)
				if err != nil {
					t.Fatalf("sign %d failed: %v", i, err)
				}
				if err := method.method.Verify(message, sig, vkey); err != nil {
					t.Fatalf("verify %d failed: %v", i, err)
				}
			}
		})
	}
}

func TestFalconJWTSignVerifyProperty(t *testing.T) {
	skey, vkey := mustFalconKeyPair(t, 9)
	precomputed := newPrecomputedFalconMethod(t, skey)

	property := func(raw []byte) bool {
		if len(raw) > 256 {
			raw = raw[:256]
		}
		message := string(raw)
		for _, method := range []struct {
			method jwt.SigningMethod
			key    any
		}{
			{method: jwt.SigningMethodFN512, key: skey},
			{method: precomputed, key: nil},
		} {
			sig, err := method.method.Sign(message, method.key)
			if err != nil {
				return false
			}
			if err := method.method.Verify(message, sig, vkey); err != nil {
				return false
			}
		}
		return true
	}

	if err := quick.Check(property, &quick.Config{MaxCount: 8}); err != nil {
		t.Fatal(err)
	}
}

func TestFalconConcurrentVerification(t *testing.T) {
	skey, vkey := mustFalconKeyPair(t, 9)
	precomputed := newPrecomputedFalconMethod(t, skey)
	message := "concurrent-verification-message"

	sigs := make([][]byte, 8)
	for i := range sigs {
		sig, err := precomputed.Sign(message, nil)
		if err != nil {
			t.Fatalf("sign %d failed: %v", i, err)
		}
		sigs[i] = sig
	}

	errs := make(chan error, len(sigs)*4)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i, sig := range sigs {
				if err := jwt.SigningMethodFN512.Verify(message, sig, vkey); err != nil {
					errs <- fmt.Errorf("dynamic verifier worker %d sig %d: %w", worker, i, err)
				}
				if err := precomputed.Verify(message, sig, vkey); err != nil {
					errs <- fmt.Errorf("precomputed verifier worker %d sig %d: %w", worker, i, err)
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}
