package fndsa

import (
	"testing"
)

var benchPrecomputedSignerSink *PrecomputedSigner

func BenchmarkBuildPrecomputedSigner512(b *testing.B) {
	sk, _, err := KeyGen(9, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ps, err := NewPrecomputedSigner(sk)
		if err != nil {
			b.Fatal(err)
		}
		benchPrecomputedSignerSink = ps
	}
}

func BenchmarkSignPrecomputed512(b *testing.B) {
	sk, _, err := KeyGen(9, nil)
	if err != nil {
		b.Fatal(err)
	}
	ps, err := NewPrecomputedSigner(sk)
	if err != nil {
		b.Fatal(err)
	}
	data := []byte("test")
	// warmup
	for i := 0; i < 10; i++ {
		sig, _ := ps.Sign(nil, DOMAIN_NONE, 0, data)
		data = sig[len(sig)-32:]
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, _ := ps.Sign(nil, DOMAIN_NONE, 0, data)
		data = sig[len(sig)-32:]
	}
}
