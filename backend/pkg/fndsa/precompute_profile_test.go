package fndsa

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"
)

// TestReportPrecomputeProfile measures the operational costs the precomputed
// signer moves off the runtime path: signer build (init) time, resident
// expanded-key material, and the break-even signature count after which the
// per-signature saving repays the build cost. It also samples process RSS
// while holding 1/10/100 signers so per-key resident growth is observable.
//
// It only writes an artifact when EMIT_PROFILE=1 (so plain `go test` stays
// side-effect free). Numbers are host-specific; run it on the target VPS to
// get thesis-grade figures. Output path defaults to
// benchmark-results/fndsa_precompute_profile.json, override with PROFILE_OUT.
func TestReportPrecomputeProfile(t *testing.T) {
	if os.Getenv("EMIT_PROFILE") != "1" {
		t.Skip("set EMIT_PROFILE=1 to emit fndsa_precompute_profile.json")
	}

	const (
		logn      = uint(9)
		buildReps = 50
		signReps  = 200
	)

	sk, vk, err := KeyGen(logn, nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Build (init) time: median of buildReps signer constructions.
	buildNs := make([]float64, buildReps)
	var lastSigner *PrecomputedSigner
	for i := range buildNs {
		start := time.Now()
		ps, err := NewPrecomputedSigner(sk)
		buildNs[i] = float64(time.Since(start).Nanoseconds())
		if err != nil {
			t.Fatalf("build signer: %v", err)
		}
		lastSigner = ps
	}
	buildMedianMs := medianF(buildNs) / 1e6

	// Dynamic vs precomputed per-signature time: median of signReps each.
	data := []byte("break-even profiling message")
	dynNs := make([]float64, signReps)
	for i := range dynNs {
		start := time.Now()
		if _, err := Sign(nil, sk, DOMAIN_NONE, 0, data); err != nil {
			t.Fatalf("dynamic sign: %v", err)
		}
		dynNs[i] = float64(time.Since(start).Nanoseconds())
	}
	preNs := make([]float64, signReps)
	for i := range preNs {
		start := time.Now()
		sig, err := lastSigner.Sign(nil, DOMAIN_NONE, 0, data)
		if err != nil {
			t.Fatalf("precomputed sign: %v", err)
		}
		preNs[i] = float64(time.Since(start).Nanoseconds())
		if !Verify(vk, DOMAIN_NONE, 0, data, sig) {
			t.Fatalf("precomputed signature failed verification")
		}
	}
	dynMedianMs := medianF(dynNs) / 1e6
	preMedianMs := medianF(preNs) / 1e6

	// Break-even: how many signatures until the per-signature saving repays
	// the extra build cost. Undefined if precomputed is not faster.
	saveMs := dynMedianMs - preMedianMs
	breakEven := 0.0
	if saveMs > 0 {
		breakEven = buildMedianMs / saveMs
	}

	// Resident cost: RSS growth from holding 1/10/100 live signers.
	rssBaselineKB := readRSSkb()
	rssByCount := map[string]float64{}
	for _, count := range []int{1, 10, 100} {
		signers := make([]*PrecomputedSigner, 0, count)
		for len(signers) < count {
			ps, err := NewPrecomputedSigner(sk)
			if err != nil {
				t.Fatalf("build signer for RSS: %v", err)
			}
			signers = append(signers, ps)
		}
		runtime.GC()
		rssByCount[strconv.Itoa(count)] = readRSSkb() - rssBaselineKB
		runtime.KeepAlive(signers)
	}

	out := map[string]any{
		"host": map[string]any{
			"num_cpu": runtime.NumCPU(),
			"goarch":  runtime.GOARCH,
			"goos":    runtime.GOOS,
		},
		"degree":                     1 << logn,
		"build_reps":                 buildReps,
		"sign_reps":                  signReps,
		"build_median_ms":            buildMedianMs,
		"persistent_bytes_per_key":   lastSigner.PersistentBytes(),
		"sign_dynamic_median_ms":     dynMedianMs,
		"sign_precomputed_median_ms": preMedianMs,
		"saving_per_signature_ms":    saveMs,
		"break_even_signatures":      breakEven,
		"rss_delta_kb_by_signers":    rssByCount,
	}

	path := os.Getenv("PROFILE_OUT")
	if path == "" {
		path = "../../benchmark-results/fndsa_precompute_profile.json"
	}
	blob, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, append(blob, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("wrote %s: build=%.4fms sign %.4f->%.4fms break-even=%.1f sigs persistent=%dB",
		path, buildMedianMs, dynMedianMs, preMedianMs, breakEven, lastSigner.PersistentBytes())
}

func medianF(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// readRSSkb reads resident set size from /proc/self/statm (Linux). Returns 0
// on unsupported platforms so the profile still emits the timing figures.
func readRSSkb() float64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	var size, resident int64
	if _, err := fmt.Sscan(string(data), &size, &resident); err != nil {
		return 0
	}
	return float64(resident) * float64(os.Getpagesize()) / 1024.0
}
