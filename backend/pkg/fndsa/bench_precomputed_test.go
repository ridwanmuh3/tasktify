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
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ps, err := NewPrecomputedSigner(sk)
		if err != nil {
			b.Fatal(err)
		}
		benchPrecomputedSignerSink = ps
	}
	if benchPrecomputedSignerSink != nil {
		b.ReportMetric(float64(benchPrecomputedSignerSink.PersistentBytes()), "persistent_B")
	}
}

func BenchmarkSignDynamic512(b *testing.B) {
	sk, _, err := KeyGen(9, nil)
	if err != nil {
		b.Fatal(err)
	}
	data := []byte("test")
	for i := 0; i < 10; i++ {
		sig, _ := Sign(nil, sk, DOMAIN_NONE, 0, data)
		data = sig[len(sig)-32:]
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := Sign(nil, sk, DOMAIN_NONE, 0, data)
		if err != nil {
			b.Fatal(err)
		}
		data = sig[len(sig)-32:]
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
	b.ReportAllocs()
	b.ReportMetric(float64(ps.PersistentBytes()), "persistent_B")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := ps.Sign(nil, DOMAIN_NONE, 0, data)
		if err != nil {
			b.Fatal(err)
		}
		data = sig[len(sig)-32:]
	}
}
