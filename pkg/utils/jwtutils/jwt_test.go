package jwtutils

import (
	"testing"

	"github.com/google/uuid"
)

const keysDir = "../../../keys"

var testAlgs = []string{
	"Falcon-Precomputed-512",
	"Falcon-512",
	"ML-DSA-44",
	"SLH-DSA-SHA2-128f",
	"ES256",
	"RS256",
	"HS256",
	"EdDSA",
}

// BenchmarkJWTSign menguji waktu murni untuk generasi token (Sign)
func BenchmarkJWTSign(b *testing.B) {
	configs, err := LoadAllAlgConfigs(keysDir, testAlgs, true)
	if err != nil {
		b.Fatalf("Gagal memuat konfigurasi kunci: %v. Pastikan path keysDir benar.", err)
	}

	jwtUtil := NewMultiAlgJwtUtil("benchmark-issuer", 60, "ES256", configs)
	payload := &JWTPayload{
		UserID: uuid.New(),
		Email:  "bench-gxiulagx@bench.test",
	}

	for _, alg := range testAlgs {
		b.Run(alg, func(b *testing.B) {
			payload.Algorithm = alg
			b.ResetTimer() // Reset timer agar setup loading key tidak ikut dihitung

			for i := 0; i < b.N; i++ {
				_, err := jwtUtil.Sign(payload)
				if err != nil {
					b.Fatalf("Error saat Sign algoritma %s: %v", alg, err)
				}
			}
		})
	}
}

// BenchmarkJWTVerify menguji waktu murni untuk verifikasi token (Parse)
func BenchmarkJWTVerify(b *testing.B) {
	configs, err := LoadAllAlgConfigs(keysDir, testAlgs, true)
	if err != nil {
		b.Fatalf("Gagal memuat konfigurasi kunci: %v. Pastikan path keysDir benar.", err)
	}

	jwtUtil := NewMultiAlgJwtUtil("benchmark-issuer", 60, "ES256", configs)
	payload := &JWTPayload{
		UserID: uuid.New(),
		Email:  "bench-gxiulagx@bench.test",
	}

	// Pre-generate token untuk setiap algoritma agar tidak membebani waktu benchmark
	precomputedTokens := make(map[string]string)
	for _, alg := range testAlgs {
		payload.Algorithm = alg
		token, err := jwtUtil.Sign(payload)
		if err != nil {
			b.Fatalf("Gagal pre-sign token untuk %s: %v", alg, err)
		}
		precomputedTokens[alg] = token
	}

	for _, alg := range testAlgs {
		token := precomputedTokens[alg]
		b.Run(alg, func(b *testing.B) {
			b.ResetTimer() // Reset timer setelah pre-computation selesai

			for i := 0; i < b.N; i++ {
				_, err := jwtUtil.Parse(token)
				if err != nil {
					b.Fatalf("Error saat Parse algoritma %s: %v", alg, err)
				}
			}
		})
	}
}
