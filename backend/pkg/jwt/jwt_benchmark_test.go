package jwt_test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
	"github.com/ridwanmuh3/tasktify/pkg/jwt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/slhdsa"
)

const benchmarkIterations = 100

// algSetup holds the configuration for benchmarking each algorithm
type algSetup struct {
	Name      string
	Method    jwt.SigningMethod
	SignKey   any
	VerifyKey any
}

// benchResult holds the average benchmark metrics for each algorithm
type benchResult struct {
	AlgName       string
	AvgGenTime    float64 // milliseconds
	AvgVerifyTime float64 // milliseconds
	AvgHeaderKB   float64 // kilobytes
	AvgBodyKB     float64 // kilobytes
	AvgRespTime   float64 // milliseconds (gen + verify)
	Throughput    float64 // operations per second
	ConfusionPass bool
}

// setupBenchmarkAlgorithms generates fresh key pairs for each PQC algorithm
func setupBenchmarkAlgorithms(t *testing.T) []algSetup {
	t.Helper()
	var algs []algSetup

	// 1. FN-DSA-512 (Original)
	fnSk, fnVk, err := fndsa.KeyGen(9, nil)
	if err != nil {
		t.Fatalf("FN-DSA-512 keygen failed: %v", err)
	}
	algs = append(algs, algSetup{
		Name:      "FN-DSA-512",
		Method:    jwt.SigningMethodFN512,
		SignKey:   fnSk,
		VerifyKey: fnVk,
	})

	// 2. FN-DSA-Precomputed-512
	fnpSk, fnpVk, err := fndsa.KeyGen(9, nil)
	if err != nil {
		t.Fatalf("FN-DSA-Precomputed-512 keygen failed: %v", err)
	}
	precomputedSigner, err := fndsa.NewPrecomputedSigner(fnpSk)
	if err != nil {
		t.Fatalf("Precomputed signer creation failed: %v", err)
	}
	fnpMethod := &jwt.SigningMethodFNDSAPrecomputed{Name: jwt.AlgFNDSA512}
	fnpMethod.SetPrecomputedSigner(precomputedSigner)
	algs = append(algs, algSetup{
		Name:      "FN-DSA-Precomputed-512",
		Method:    fnpMethod,
		SignKey:   nil, // signer embedded in method
		VerifyKey: fnpVk,
	})

	// 3. ML-DSA-44
	mlPk, mlSk, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ML-DSA-44 keygen failed: %v", err)
	}
	algs = append(algs, algSetup{
		Name:      "ML-DSA-44",
		Method:    jwt.SigningMethodMLDSA44,
		SignKey:   mlSk,
		VerifyKey: mlPk,
	})

	// 4. SLH-DSA-SHA2-128f
	slhPk, slhSk, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	if err != nil {
		t.Fatalf("SLH-DSA-SHA2-128f keygen failed: %v", err)
	}
	algs = append(algs, algSetup{
		Name:      "SLH-DSA-SHA2-128f",
		Method:    jwt.SigningMethodSLHDSA_SHA2_128f,
		SignKey:   slhSk,
		VerifyKey: slhPk,
	})

	return algs
}

// signBenchToken creates and signs a JWT token with the given method and key
func signBenchToken(method jwt.SigningMethod, signKey any) (string, error) {
	token := jwt.NewWithClaims(method, TestClaims{
		UserID: uuid.New(),
		Email:  "benchmark@test.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(60 * time.Minute)),
			Issuer:    "tasktify",
		},
	})
	return token.SignedString(signKey)
}

// verifyBenchToken parses and verifies a JWT token
func verifyBenchToken(tokenString string, verifyKey any, validMethod string) error {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{validMethod}),
		jwt.WithIssuer("tasktify"),
		jwt.WithIssuedAt(),
	)
	_, err := parser.ParseWithClaims(tokenString, &TestClaims{}, func(t *jwt.Token) (any, error) {
		return verifyKey, nil
	})
	return err
}

// buildResponseBody simulates the JSON response body from a sign-in endpoint
func buildResponseBody(accessToken, refreshToken string) []byte {
	body, _ := json.Marshal(map[string]any{
		"status":  200,
		"message": "sign in successful",
		"data": map[string]any{
			"token_type":    "Bearer",
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		},
	})
	return body
}

// ══════════════════════════════════════════════════════════════════
// BENCHMARK: Post-Quantum Cryptography JWT Performance
// Metrics (average over 100 iterations):
//   - Token Generation Time
//   - Token Verification Time
//   - Request Header Size (Authorization: Bearer <token>) in KB
//   - Response Body Size (JSON sign-in response) in KB
//   - Response Time (generation + verification)
//   - Throughput (ops/sec)
//   - JWT Confusion Test (cross-algorithm verification must fail)
//
// ══════════════════════════════════════════════════════════════════
func TestBenchmarkPQCAlgorithms(t *testing.T) {
	algs := setupBenchmarkAlgorithms(t)
	results := make([]benchResult, len(algs))

	// ── Run benchmark for each algorithm ──
	for idx, alg := range algs {
		idx, alg := idx, alg
		t.Run("Benchmark_"+alg.Name, func(t *testing.T) {
			var (
				totalGenTime    time.Duration
				totalVerifyTime time.Duration
				totalHeaderSize int
				totalBodySize   int
			)

			for i := 0; i < benchmarkIterations; i++ {
				// 1. Token Generation Time
				genStart := time.Now()
				accessToken, err := signBenchToken(alg.Method, alg.SignKey)
				genDuration := time.Since(genStart)
				if err != nil {
					t.Fatalf("iteration %d: sign failed: %v", i, err)
				}
				totalGenTime += genDuration

				// Generate refresh token for response body measurement
				refreshToken, err := signBenchToken(alg.Method, alg.SignKey)
				if err != nil {
					t.Fatalf("iteration %d: refresh sign failed: %v", i, err)
				}

				// 2. Token Verification Time
				verifyStart := time.Now()
				err = verifyBenchToken(accessToken, alg.VerifyKey, alg.Method.Alg())
				verifyDuration := time.Since(verifyStart)
				if err != nil {
					t.Fatalf("iteration %d: verify failed: %v", i, err)
				}
				totalVerifyTime += verifyDuration

				// 3. Request Header Size: "Authorization: Bearer <token>"
				headerSize := len("Authorization: Bearer ") + len(accessToken)
				totalHeaderSize += headerSize

				// 4. Response Body Size: full JSON sign-in response
				respBody := buildResponseBody(accessToken, refreshToken)
				totalBodySize += len(respBody)
			}

			avgGenMs := durationToMs(totalGenTime) / float64(benchmarkIterations)
			avgVerifyMs := durationToMs(totalVerifyTime) / float64(benchmarkIterations)
			avgRespMs := avgGenMs + avgVerifyMs
			throughput := 0.0
			if avgRespMs > 0 {
				throughput = 1000.0 / avgRespMs
			}

			results[idx] = benchResult{
				AlgName:       alg.Name,
				AvgGenTime:    avgGenMs,
				AvgVerifyTime: avgVerifyMs,
				AvgHeaderKB:   bytesToKB(totalHeaderSize) / float64(benchmarkIterations),
				AvgBodyKB:     bytesToKB(totalBodySize) / float64(benchmarkIterations),
				AvgRespTime:   avgRespMs,
				Throughput:    throughput,
			}

			t.Logf("%s: gen=%.4fms verify=%.4fms header=%.3fKB body=%.3fKB resp=%.4fms throughput=%.2f ops/s",
				alg.Name, avgGenMs, avgVerifyMs,
				results[idx].AvgHeaderKB, results[idx].AvgBodyKB,
				avgRespMs, throughput)
		})
	}

	// ── JWT Confusion Test ──
	t.Run("JWT_Confusion_Test", func(t *testing.T) {
		for i, alg := range algs {
			tokenString, err := signBenchToken(alg.Method, alg.SignKey)
			if err != nil {
				t.Fatalf("failed to create token for %s: %v", alg.Name, err)
			}

			confusionPass := true
			for j, other := range algs {
				if i == j || alg.Method.Alg() == other.Method.Alg() {
					continue
				}
				err := verifyBenchToken(tokenString, other.VerifyKey, other.Method.Alg())
				if err == nil {
					confusionPass = false
					t.Errorf("VULNERABLE: %s token accepted by %s verifier!", alg.Name, other.Name)
				}
			}
			results[i].ConfusionPass = confusionPass
			if confusionPass {
				t.Logf("PROTECTED: %s token correctly rejected by all other algorithms", alg.Name)
			}
		}
	})

	// ── Print Summary Table ──
	printBenchmarkSummary(results)
}

func printBenchmarkSummary(results []benchResult) {
	divider := strings.Repeat("═", 140)
	rowDiv := strings.Repeat("─", 140)

	fmt.Println()
	fmt.Println(divider)
	fmt.Printf("  POST-QUANTUM CRYPTOGRAPHY JWT BENCHMARK RESULTS (Average of %d iterations)\n", benchmarkIterations)
	fmt.Println(divider)
	fmt.Printf("  %-26s │ %12s │ %12s │ %14s │ %14s │ %12s │ %12s │ %9s\n",
		"Algorithm", "Gen Time", "Verify Time", "Header Size", "Body Size", "Resp Time", "Throughput", "Confusion")
	fmt.Printf("  %-26s │ %12s │ %12s │ %14s │ %14s │ %12s │ %12s │ %9s\n",
		"", "(ms)", "(ms)", "(KB)", "(KB)", "(ms)", "(ops/s)", "Test")
	fmt.Println(rowDiv)

	for _, r := range results {
		confusionStr := "PASS"
		if !r.ConfusionPass {
			confusionStr = "FAIL"
		}
		fmt.Printf("  %-26s │ %12.4f │ %12.4f │ %14.3f │ %14.3f │ %12.4f │ %12.2f │ %9s\n",
			r.AlgName, r.AvgGenTime, r.AvgVerifyTime,
			r.AvgHeaderKB, r.AvgBodyKB,
			r.AvgRespTime, r.Throughput, confusionStr)
	}
	fmt.Println(divider)
}

func durationToMs(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / float64(time.Millisecond)
}

func bytesToKB(v int) float64 {
	return float64(v) / 1024.0
}
