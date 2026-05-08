package handler

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/ridwanmuh3/tasktify/pkg/utils/jwtutils"
	"go.uber.org/zap"

	"github.com/ridwanmuh3/tasktify/gateway/internal/model"
)

type BenchmarkHandler struct {
	log          *zap.SugaredLogger
	benchmarkJWT jwtutils.JwtUtil
}

type BenchmarkRuntimeStats struct {
	MemoryAllocMB      float64
	MemoryAllocDeltaMB float64 // bytes allocated during sign operation (cumulative delta)
	MemorySysMB        float64
	CPUPct             float64 // process CPU utilization % from background sampler
}

// cpuMonitor samples process-wide CPU utilization every 100 ms via /proc/self/stat.
// /proc/self/stat utime+stime always sums all threads — reliable in containers.
// USER_HZ=100 so 1 tick = 10ms; formula: ticks*1e6/wallµs/GOMAXPROCS = %.
var cpuMonitor struct {
	mu  sync.RWMutex
	pct float64
}

func init() {
	go func() {
		prev := readCPUTicks()
		prevWall := time.Now()
		for {
			time.Sleep(100 * time.Millisecond)
			now := time.Now()
			curr := readCPUTicks()
			wallUs := now.Sub(prevWall).Microseconds()
			if wallUs > 0 {
				// 1 tick=10ms=10000µs; *1e6 = 10000*100 (tick→µs then fraction→pct)
				pct := float64(curr-prev) * 1_000_000.0 / float64(wallUs) / float64(runtime.GOMAXPROCS(0))
				cpuMonitor.mu.Lock()
				cpuMonitor.pct = pct
				cpuMonitor.mu.Unlock()
			}
			prev = curr
			prevWall = now
		}
	}()
}

// readCPUTicks reads process-wide CPU clock ticks (utime+stime) from /proc/self/stat.
// Unlike Getrusage(RUSAGE_SELF), this always aggregates all threads on Linux.
func readCPUTicks() int64 {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	s := string(data)
	end := strings.LastIndex(s, ")")
	if end < 0 || end+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[end+2:])
	if len(fields) < 13 {
		return 0
	}
	utime, _ := strconv.ParseInt(fields[11], 10, 64)
	stime, _ := strconv.ParseInt(fields[12], 10, 64)
	return utime + stime
}

func NewBenchmarkHandler(log *zap.SugaredLogger, benchmarkJWT jwtutils.JwtUtil) *BenchmarkHandler {
	return &BenchmarkHandler{log: log, benchmarkJWT: benchmarkJWT}
}

// BenchmarkSignRequest defines a pure-sign isolated benchmark.
// Email is used to derive stable JWT claims. Password is ignored and kept
// only for backward-compatible k6 payloads.
// PayloadNote is metadata-only — it has no effect on the signing itself
// but is echoed in the response for experiment traceability.
type BenchmarkSignRequest struct {
	Algorithm        string `json:"algorithm"         validate:"required"`
	Iterations       int    `json:"iterations"        validate:"required,min=1,max=10000"`
	WarmupIterations int    `json:"warmup_iterations"`
	Email            string `json:"email"             validate:"required,email"`
	Password         string `json:"password"`
	PayloadNote      string `json:"payload_note"` // optional experiment label
}

type BenchmarkTokenRequest struct {
	Algorithm string `json:"algorithm" validate:"required"`
	Email     string `json:"email"     validate:"required,email"`
	Password  string `json:"password"`
}

// TimingStats holds descriptive statistics for a latency series.
type TimingStats struct {
	MinMs   float64 `json:"min_ms"`
	MaxMs   float64 `json:"max_ms"`
	AvgMs   float64 `json:"avg_ms"`
	P50Ms   float64 `json:"p50_ms"`
	P95Ms   float64 `json:"p95_ms"`
	P99Ms   float64 `json:"p99_ms"`
	StdevMs float64 `json:"stdev_ms"`
	SumMs   float64 `json:"sum_ms"`
}

// NumericStats holds descriptive statistics for non-latency series.
type NumericStats struct {
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
	Avg   float64 `json:"avg"`
	P50   float64 `json:"p50"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
	Stdev float64 `json:"stdev"`
	Sum   float64 `json:"sum"`
}

// BenchmarkSignResult is the academic experiment output.
// TokenGenerationTimingsMs = pure JWT generation durations from the local benchmark signer.
// TotalTimingsMs = per-iteration local handler durations around payload build + sign.
type BenchmarkSignResult struct {
	Algorithm                string    `json:"algorithm"`
	Iterations               int       `json:"iterations"`
	WarmupIterations         int       `json:"warmup_iterations"`
	SuccessCount             int       `json:"success_count"`
	PayloadNote              string    `json:"payload_note,omitempty"`
	SignTimingsMs            []float64 `json:"sign_timings_ms"`             // backward-compatible alias
	TokenGenerationTimingsMs []float64 `json:"token_generation_timings_ms"` // clean: JWT generation only
	TotalTimingsMs           []float64 `json:"total_timings_ms"`            // local iteration around pure sign
	TokenSizeBytes           []float64 `json:"token_size_bytes"`
	TokenHeaderSizeBytes     []float64 `json:"token_header_size_bytes"`
	TokenBodySizeBytes       []float64 `json:"token_body_size_bytes"`
	TokenSignatureSizeBytes  []float64 `json:"token_signature_size_bytes"`
	AuthCPUPct               []float64 `json:"auth_cpu_pct"`
	AuthMemoryAllocMB        []float64 `json:"auth_memory_alloc_mb"`
	AuthMemoryAllocDeltaMB   []float64 `json:"auth_memory_alloc_delta_mb"`
	AuthMemorySysMB          []float64 `json:"auth_memory_sys_mb"`
	Stats                    struct {
		Sign            TimingStats `json:"sign"`             // backward-compatible alias
		TokenGeneration TimingStats `json:"token_generation"` // clean token generation
		Total           TimingStats `json:"total"`            // local iteration stats
		TokenSize       struct {
			Token     NumericStats `json:"token"`
			Header    NumericStats `json:"header"`
			Body      NumericStats `json:"body"`
			Signature NumericStats `json:"signature"`
		} `json:"token_size"`
		Resource struct {
			CPUUtilization      NumericStats `json:"cpu_utilization_pct"`
			MemoryAllocMB       NumericStats `json:"memory_alloc_mb"`
			MemoryAllocDeltaMB  NumericStats `json:"memory_alloc_delta_mb"`
			MemorySysMB         NumericStats `json:"memory_sys_mb"`
		} `json:"resource"`
	} `json:"stats"`
}

// SignLatency runs N sequential pure-sign iterations and returns per-iteration timing data.
// Designed for isolated academic experiments — use 1 VU in k6 for controlled measurements.
//
// POST /api/benchmark/sign
func (h *BenchmarkHandler) SignLatency(c fiber.Ctx) error {
	var req BenchmarkSignRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	signTimings := make([]float64, 0, req.Iterations)
	totalTimings := make([]float64, 0, req.Iterations)
	tokenSizes := make([]float64, 0, req.Iterations)
	tokenHeaderSizes := make([]float64, 0, req.Iterations)
	tokenBodySizes := make([]float64, 0, req.Iterations)
	tokenSignatureSizes := make([]float64, 0, req.Iterations)
	cpuSamples := make([]float64, 0, req.Iterations)
	memAllocSamples := make([]float64, 0, req.Iterations)
	memAllocDeltaSamples := make([]float64, 0, req.Iterations)
	memSysSamples := make([]float64, 0, req.Iterations)
	warmupIterations := req.WarmupIterations
	if warmupIterations < 0 {
		warmupIterations = 0
	}

	for i := 0; i < warmupIterations; i++ {
		if _, _, _, _, err := h.signBenchmarkToken(req.Algorithm, req.Email); err != nil {
			h.log.Warnf("benchmark warmup iter %d failed: %v", i, err)
		}
	}

	for i := 0; i < req.Iterations; i++ {
		token, signMs, totalMs, stats, err := h.signBenchmarkToken(req.Algorithm, req.Email)
		if err != nil {
			h.log.Warnf("benchmark iter %d failed: %v", i, err)
			continue
		}

		signTimings = append(signTimings, signMs)
		totalTimings = append(totalTimings, totalMs)
		addTokenSizeSamples(token, &tokenSizes, &tokenHeaderSizes, &tokenBodySizes, &tokenSignatureSizes)
		cpuSamples = append(cpuSamples, stats.CPUPct)
		memAllocSamples = append(memAllocSamples, stats.MemoryAllocMB)
		memAllocDeltaSamples = append(memAllocDeltaSamples, stats.MemoryAllocDeltaMB)
		memSysSamples = append(memSysSamples, stats.MemorySysMB)
	}

	result := BenchmarkSignResult{
		Algorithm:                req.Algorithm,
		Iterations:               req.Iterations,
		WarmupIterations:         warmupIterations,
		SuccessCount:             len(totalTimings),
		PayloadNote:              req.PayloadNote,
		SignTimingsMs:            signTimings,
		TokenGenerationTimingsMs: signTimings,
		TotalTimingsMs:           totalTimings,
		TokenSizeBytes:           tokenSizes,
		TokenHeaderSizeBytes:     tokenHeaderSizes,
		TokenBodySizeBytes:       tokenBodySizes,
		TokenSignatureSizeBytes:  tokenSignatureSizes,
		AuthCPUPct:               cpuSamples,
		AuthMemoryAllocMB:        memAllocSamples,
		AuthMemoryAllocDeltaMB:   memAllocDeltaSamples,
		AuthMemorySysMB:          memSysSamples,
	}
	result.Stats.Sign = computeTimingStats(signTimings)
	result.Stats.TokenGeneration = result.Stats.Sign
	result.Stats.Total = computeTimingStats(totalTimings)
	result.Stats.TokenSize.Token = computeNumericStats(tokenSizes)
	result.Stats.TokenSize.Header = computeNumericStats(tokenHeaderSizes)
	result.Stats.TokenSize.Body = computeNumericStats(tokenBodySizes)
	result.Stats.TokenSize.Signature = computeNumericStats(tokenSignatureSizes)
	result.Stats.Resource.CPUUtilization = computeNumericStats(cpuSamples)
	result.Stats.Resource.MemoryAllocMB = computeNumericStats(memAllocSamples)
	result.Stats.Resource.MemoryAllocDeltaMB = computeNumericStats(memAllocDeltaSamples)
	result.Stats.Resource.MemorySysMB = computeNumericStats(memSysSamples)

	c.Set("X-Bench-Sign-P95-Ms", fmt.Sprintf("%.3f", result.Stats.Sign.P95Ms))
	c.Set("X-Bench-Token-Generation-P95-Ms", fmt.Sprintf("%.3f", result.Stats.TokenGeneration.P95Ms))
	c.Set("X-Bench-Total-P95-Ms", fmt.Sprintf("%.3f", result.Stats.Total.P95Ms))

	return c.JSON(model.Response[any]{
		Status:  fiber.StatusOK,
		Message: "benchmark complete",
		Data:    result,
	})
}

// SignToken signs one benchmark token and returns the same response shape as /api/auth/signin
// with clean signing latency in headers for k6 stress runs.
//
// POST /api/benchmark/token
func (h *BenchmarkHandler) SignToken(c fiber.Ctx) error {
	var req BenchmarkTokenRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	token, signMs, _, stats, err := h.signBenchmarkToken(req.Algorithm, req.Email)
	if err != nil {
		h.log.Errorf("benchmark token sign failed: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "failed to generate benchmark token")
	}

	c.Set("X-Sign-Time-Ms", fmt.Sprintf("%.3f", signMs))
	c.Set("X-Token-Generation-Time-Ms", fmt.Sprintf("%.3f", signMs))
	c.Set("X-Auth-CPU-Pct", fmt.Sprintf("%.3f", stats.CPUPct))
	c.Set("X-Auth-Mem-Alloc-MB", fmt.Sprintf("%.3f", stats.MemoryAllocMB))
	c.Set("X-Auth-Mem-Alloc-Delta-MB", fmt.Sprintf("%.6f", stats.MemoryAllocDeltaMB))
	c.Set("X-Auth-Mem-Sys-MB", fmt.Sprintf("%.3f", stats.MemorySysMB))

	return c.JSON(model.Response[any]{
		Status:  fiber.StatusOK,
		Message: "benchmark token generated",
		Data: fiber.Map{
			"token_type":   "Bearer",
			"access_token": token,
		},
	})
}

func (h *BenchmarkHandler) signBenchmarkToken(algorithm string, email string) (string, float64, float64, BenchmarkRuntimeStats, error) {
	if h.benchmarkJWT == nil {
		return "", 0, 0, BenchmarkRuntimeStats{}, fmt.Errorf("benchmark signer not configured")
	}

	userID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(strings.ToLower(email)))
	payload := &jwtutils.JWTPayload{
		UserID:    userID,
		Email:     email,
		Algorithm: algorithm,
	}

	// Memory: ReadMemStats is the most reliable cross-version API.
	// TotalAlloc is cumulative (monotonically increasing), so delta = bytes
	// actually allocated during Sign regardless of GC activity.
	// ReadMemStats is called outside the sign timer so STW pause doesn't skew latency.
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	cpuOpBefore := readCPUTicks()
	totalStart := time.Now()
	token, err := h.benchmarkJWT.Sign(payload)
	signMs := float64(time.Since(totalStart).Microseconds()) / 1000.0
	cpuOpAfter := readCPUTicks()
	totalMs := signMs

	if err != nil {
		return "", 0, 0, BenchmarkRuntimeStats{}, err
	}

	runtime.ReadMemStats(&memAfter)

	// CPU: prefer background monitor (stable 200 ms window).
	// Fall back to per-op Getrusage delta when monitor hasn't warmed up yet
	// (cpuMonitor.pct == 0 within the first 200 ms of process start).
	cpuMonitor.mu.RLock()
	cpuPct := cpuMonitor.pct
	cpuMonitor.mu.RUnlock()

	if cpuPct == 0 && signMs > 0 {
		wallUs := int64(signMs * 1000)
		cpuDelta := cpuOpAfter - cpuOpBefore
		if wallUs > 0 && cpuDelta > 0 {
			cpuPct = float64(cpuDelta) * 1_000_000.0 / float64(wallUs) / float64(runtime.GOMAXPROCS(0))
		}
	}

	stats := BenchmarkRuntimeStats{
		MemoryAllocMB:      float64(memAfter.HeapAlloc) / 1024 / 1024,
		MemoryAllocDeltaMB: float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / 1024 / 1024,
		MemorySysMB:        float64(memAfter.Sys) / 1024 / 1024,
		CPUPct:             cpuPct,
	}

	return token, signMs, totalMs, stats, nil
}

func bytesToMB(v uint64) float64 {
	return float64(v) / 1024.0 / 1024.0
}

func computeTimingStats(timings []float64) TimingStats {
	if len(timings) == 0 {
		return TimingStats{}
	}

	sorted := make([]float64, len(timings))
	copy(sorted, timings)
	sort.Float64s(sorted)

	n := len(sorted)
	var sum float64
	for _, v := range sorted {
		sum += v
	}
	avg := sum / float64(n)

	var variance float64
	for _, v := range sorted {
		d := v - avg
		variance += d * d
	}
	variance /= float64(n)

	percentile := func(p float64) float64 {
		if n == 1 {
			return sorted[0]
		}
		idx := p / 100.0 * float64(n-1)
		lo := int(idx)
		hi := lo + 1
		if hi >= n {
			return sorted[n-1]
		}
		frac := idx - float64(lo)
		return sorted[lo]*(1-frac) + sorted[hi]*frac
	}

	return TimingStats{
		MinMs:   sorted[0],
		MaxMs:   sorted[n-1],
		AvgMs:   avg,
		P50Ms:   percentile(50),
		P95Ms:   percentile(95),
		P99Ms:   percentile(99),
		StdevMs: math.Sqrt(variance),
		SumMs:   sum,
	}
}

func computeNumericStats(values []float64) NumericStats {
	t := computeTimingStats(values)
	return NumericStats{
		Min:   t.MinMs,
		Max:   t.MaxMs,
		Avg:   t.AvgMs,
		P50:   t.P50Ms,
		P95:   t.P95Ms,
		P99:   t.P99Ms,
		Stdev: t.StdevMs,
		Sum:   t.SumMs,
	}
}

func addTokenSizeSamples(token string, tokenSizes, headerSizes, bodySizes, signatureSizes *[]float64) {
	if token == "" {
		return
	}
	*tokenSizes = append(*tokenSizes, float64(len(token)))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return
	}
	*headerSizes = append(*headerSizes, float64(len(parts[0])))
	*bodySizes = append(*bodySizes, float64(len(parts[1])))
	*signatureSizes = append(*signatureSizes, float64(len(parts[2])))
}
