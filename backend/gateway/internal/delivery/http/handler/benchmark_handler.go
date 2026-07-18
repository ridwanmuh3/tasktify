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
	"go.uber.org/zap"

	"github.com/ridwanmuh3/tasktify/pkg/utils/jwtutils"

	"github.com/ridwanmuh3/tasktify/gateway/internal/model"
)

type BenchmarkHandler struct {
	log              *zap.SugaredLogger
	benchmarkJWT     jwtutils.JwtUtil
	benchmarkConfigs map[string]*jwtutils.AlgConfig
}

const (
	bytesPerKB       = 1024.0
	pureSigningInput = "tasktify-fndsa-pure-signing-benchmark-message-v1"
)

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

func readMemoryRSSKB() float64 {
	if kb := readMemoryRSSFromStatusKB(); kb > 0 {
		return kb
	}
	return readMemoryRSSFromStatmKB()
}

func readMemoryRSSFromStatusKB() float64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return readMemoryRSSFallbackKB()
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return readMemoryRSSFallbackKB()
		}
		kb, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return readMemoryRSSFallbackKB()
		}
		return kb
	}
	return readMemoryRSSFallbackKB()
}

func readMemoryRSSFromStatmKB() float64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return readMemoryRSSFallbackKB()
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return readMemoryRSSFallbackKB()
	}
	pages, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return readMemoryRSSFallbackKB()
	}
	return pages * float64(os.Getpagesize()) / bytesPerKB
}

func readMemoryRSSFallbackKB() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Sys) / bytesPerKB
}

func NewBenchmarkHandler(
	log *zap.SugaredLogger,
	benchmarkJWT jwtutils.JwtUtil,
	benchmarkConfigs map[string]*jwtutils.AlgConfig,
) *BenchmarkHandler {
	return &BenchmarkHandler{
		log:              log,
		benchmarkJWT:     benchmarkJWT,
		benchmarkConfigs: benchmarkConfigs,
	}
}

// JWTIssuance runs N sequential JWT issuance iterations and returns per-iteration timing data.
// Designed for isolated academic experiments — use 1 VU in k6 for controlled measurements.
//
// POST /api/benchmark/jwt-issuance
func (h *BenchmarkHandler) JWTIssuance(c fiber.Ctx) error {
	return h.jwtIssuance(c, "/api/benchmark/jwt-issuance")
}

// SignLatency is kept as a backward-compatible alias for older k6 scripts.
//
// POST /api/benchmark/sign
func (h *BenchmarkHandler) SignLatency(c fiber.Ctx) error {
	return h.jwtIssuance(c, "/api/benchmark/sign")
}

// PureSigning runs N sequential signing primitive iterations.
// It excludes JWT claim serialization, Base64URL, and compact-token assembly.
//
// POST /api/benchmark/pure-signing
func (h *BenchmarkHandler) PureSigning(c fiber.Ctx) error {
	var req BenchmarkSignRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if req.Iterations <= 0 {
		return fiber.NewError(fiber.StatusBadRequest, "iterations must be positive")
	}

	pureSigningTimings := make([]float64, 0, req.Iterations)
	gcFreePureSigningTimings := make([]float64, 0, req.Iterations)
	cpuSamples := make([]float64, 0, req.Iterations)
	cpuTimeSamples := make([]float64, 0, req.Iterations)
	memAllocSamples := make([]float64, 0, req.Iterations)
	memAllocDeltaSamples := make([]float64, 0, req.Iterations)
	memSysSamples := make([]float64, 0, req.Iterations)
	memRSSSamples := make([]float64, 0, req.Iterations)
	warmupIterations := req.WarmupIterations
	if warmupIterations < 0 {
		warmupIterations = 0
	}

	for i := 0; i < warmupIterations; i++ {
		if _, _, err := h.signPure(req.Algorithm, false); err != nil {
			h.log.Warnf("pure signing warmup iter %d failed: %v", i, err)
		}
	}

	runtime.GC()
	runtime.GC()

	gcContaminatedCount := 0
	var firstErr error
	for i := 0; i < req.Iterations; i++ {
		signMs, stats, err := h.signPure(req.Algorithm, true)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			h.log.Warnf("pure signing iter %d failed: %v", i, err)
			continue
		}

		pureSigningTimings = append(pureSigningTimings, signMs)
		cpuSamples = append(cpuSamples, stats.CPUPct)
		cpuTimeSamples = append(cpuTimeSamples, stats.CPUTimeMs)
		memAllocSamples = append(memAllocSamples, stats.MemoryAllocKB)
		memAllocDeltaSamples = append(memAllocDeltaSamples, stats.MemoryAllocDeltaKB)
		memSysSamples = append(memSysSamples, stats.MemorySysKB)
		memRSSSamples = append(memRSSSamples, stats.MemoryRSSKB)

		if stats.GCOccurred {
			gcContaminatedCount++
		} else {
			gcFreePureSigningTimings = append(gcFreePureSigningTimings, signMs)
		}
	}

	if len(pureSigningTimings) == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("no successful iterations")
		}
		return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("pure signing benchmark failed: %v", firstErr))
	}

	result := BenchmarkPureSigningResult{
		Endpoint:               "/api/benchmark/pure-signing",
		MetricScope:            "pure_signing",
		Algorithm:              req.Algorithm,
		JWSAlgorithm:           jwtutils.HeaderAlgForConfigAlg(req.Algorithm),
		Iterations:             req.Iterations,
		WarmupIterations:       warmupIterations,
		SuccessCount:           len(pureSigningTimings),
		GCContaminatedCount:    gcContaminatedCount,
		PayloadNote:            req.PayloadNote,
		SigningInputBytes:      len(pureSigningInput),
		PureSigningTimingsMs:   pureSigningTimings,
		PureSigningGCFreeMs:    gcFreePureSigningTimings,
		AuthCPUPct:             cpuSamples,
		AuthCPUTimeMs:          cpuTimeSamples,
		AuthMemoryAllocKB:      memAllocSamples,
		AuthMemoryAllocDeltaKB: memAllocDeltaSamples,
		AuthMemorySysKB:        memSysSamples,
		AuthMemoryRSSKB:        memRSSSamples,
	}
	result.Stats.PureSigning = computeTimingStats(pureSigningTimings)
	result.Stats.PureSigningGCFree = computeTimingStats(gcFreePureSigningTimings)
	result.Stats.Resource.CPUUtilization = computeNumericStats(cpuSamples)
	result.Stats.Resource.CPUTimeMs = computeNumericStats(cpuTimeSamples)
	// Pure signing does one signature per iteration (unlike jwt_issuance's
	// access+refresh pair), so cost-per-token equals the raw per-iteration CPU cost.
	result.Stats.Resource.CPUTimePerTokenMs = computeNumericStats(cpuTimeSamples)
	result.Stats.Resource.MemoryAllocKB = computeNumericStats(memAllocSamples)
	result.Stats.Resource.MemoryAllocDeltaKB = computeNumericStats(memAllocDeltaSamples)
	result.Stats.Resource.MemorySysKB = computeNumericStats(memSysSamples)
	result.Stats.Resource.MemoryRSSKB = computeNumericStats(memRSSSamples)

	c.Set("X-Bench-Pure-Signing-P95-Ms", fmt.Sprintf("%.3f", result.Stats.PureSigning.P95Ms))

	return c.JSON(model.Response[any]{
		Status:  fiber.StatusOK,
		Message: "pure signing benchmark complete",
		Data:    result,
	})
}

func (h *BenchmarkHandler) jwtIssuance(c fiber.Ctx, endpoint string) error {
	var req BenchmarkSignRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if req.Iterations <= 0 {
		return fiber.NewError(fiber.StatusBadRequest, "iterations must be positive")
	}

	signTimings := make([]float64, 0, req.Iterations)
	gcFreeSignTimings := make([]float64, 0, req.Iterations)
	refreshTokenTimings := make([]float64, 0, req.Iterations)
	gcFreeRefreshTokenTimings := make([]float64, 0, req.Iterations)
	totalTimings := make([]float64, 0, req.Iterations)
	cpuSamples := make([]float64, 0, req.Iterations)
	cpuTimeSamples := make([]float64, 0, req.Iterations)
	memAllocSamples := make([]float64, 0, req.Iterations)
	memAllocDeltaSamples := make([]float64, 0, req.Iterations)
	memSysSamples := make([]float64, 0, req.Iterations)
	memRSSSamples := make([]float64, 0, req.Iterations)
	warmupIterations := req.WarmupIterations
	if warmupIterations < 0 {
		warmupIterations = 0
	}

	for i := 0; i < warmupIterations; i++ {
		if _, _, _, err := h.signBenchmarkToken(req.Algorithm, req.Email, jwtutils.TokenUseAccess, false); err != nil {
			h.log.Warnf("benchmark warmup access iter %d failed: %v", i, err)
		}
		if _, _, _, err := h.signBenchmarkToken(req.Algorithm, req.Email, jwtutils.TokenUseRefresh, false); err != nil {
			h.log.Warnf("benchmark warmup iter %d failed: %v", i, err)
		}
	}

	// Force GC twice after warmup so measurement starts with a clean heap.
	// First call triggers collection; second ensures finalizers have run.
	runtime.GC()
	runtime.GC()

	gcContaminatedCount := 0
	var firstErr error
	for i := 0; i < req.Iterations; i++ {
		_, signMs, accessStats, err := h.signBenchmarkToken(req.Algorithm, req.Email, jwtutils.TokenUseAccess, true)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			h.log.Warnf("benchmark access iter %d failed: %v", i, err)
			continue
		}
		_, refreshMs, refreshStats, err := h.signBenchmarkToken(req.Algorithm, req.Email, jwtutils.TokenUseRefresh, true)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			h.log.Warnf("benchmark refresh iter %d failed: %v", i, err)
			continue
		}

		stats := combineBenchmarkStats(accessStats, refreshStats)
		totalMs := signMs + refreshMs

		signTimings = append(signTimings, signMs)
		refreshTokenTimings = append(refreshTokenTimings, refreshMs)
		totalTimings = append(totalTimings, totalMs)
		cpuSamples = append(cpuSamples, stats.CPUPct)
		cpuTimeSamples = append(cpuTimeSamples, stats.CPUTimeMs)
		memAllocSamples = append(memAllocSamples, stats.MemoryAllocKB)
		memAllocDeltaSamples = append(memAllocDeltaSamples, stats.MemoryAllocDeltaKB)
		memSysSamples = append(memSysSamples, stats.MemorySysKB)
		memRSSSamples = append(memRSSSamples, stats.MemoryRSSKB)

		if stats.GCOccurred {
			gcContaminatedCount++
		} else {
			gcFreeSignTimings = append(gcFreeSignTimings, signMs)
			gcFreeRefreshTokenTimings = append(gcFreeRefreshTokenTimings, refreshMs)
		}
	}

	if len(signTimings) == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("no successful iterations")
		}
		return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("jwt issuance benchmark failed: %v", firstErr))
	}

	result := BenchmarkSignResult{
		Endpoint:                 endpoint,
		MetricScope:              "jwt_issuance",
		Algorithm:                req.Algorithm,
		JWSAlgorithm:             jwtutils.HeaderAlgForConfigAlg(req.Algorithm),
		Iterations:               req.Iterations,
		WarmupIterations:         warmupIterations,
		SuccessCount:             len(signTimings),
		GCContaminatedCount:      gcContaminatedCount,
		PayloadNote:              req.PayloadNote,
		SignTimingsMs:            signTimings,
		TokenGenerationTimingsMs: signTimings,
		TokenGenerationGCFreeMs:  gcFreeSignTimings,
		RefreshTokenTimingsMs:    refreshTokenTimings,
		RefreshTokenGCFreeMs:     gcFreeRefreshTokenTimings,
		TotalTimingsMs:           totalTimings,
		AuthCPUPct:               cpuSamples,
		AuthCPUTimeMs:            cpuTimeSamples,
		AuthMemoryAllocKB:        memAllocSamples,
		AuthMemoryAllocDeltaKB:   memAllocDeltaSamples,
		AuthMemorySysKB:          memSysSamples,
		AuthMemoryRSSKB:          memRSSSamples,
	}
	result.Stats.Sign = computeTimingStats(signTimings)
	result.Stats.TokenGeneration = result.Stats.Sign
	result.Stats.TokenGenerationGCFree = computeTimingStats(gcFreeSignTimings)
	result.Stats.RefreshToken = computeTimingStats(refreshTokenTimings)
	result.Stats.RefreshTokenGCFree = computeTimingStats(gcFreeRefreshTokenTimings)
	result.Stats.Total = computeTimingStats(totalTimings)
	result.Stats.Resource.CPUUtilization = computeNumericStats(cpuSamples)
	result.Stats.Resource.CPUTimeMs = computeNumericStats(cpuTimeSamples)
	result.Stats.Resource.CPUTimePerTokenMs = computeNumericStats(scaleValues(cpuTimeSamples, 0.5))
	result.Stats.Resource.MemoryAllocKB = computeNumericStats(memAllocSamples)
	result.Stats.Resource.MemoryAllocDeltaKB = computeNumericStats(memAllocDeltaSamples)
	result.Stats.Resource.MemorySysKB = computeNumericStats(memSysSamples)
	result.Stats.Resource.MemoryRSSKB = computeNumericStats(memRSSSamples)

	c.Set("X-Bench-Sign-P95-Ms", fmt.Sprintf("%.3f", result.Stats.Sign.P95Ms))
	c.Set("X-Bench-Token-Generation-P95-Ms", fmt.Sprintf("%.3f", result.Stats.TokenGeneration.P95Ms))
	c.Set("X-Bench-Refresh-Token-Generation-P95-Ms", fmt.Sprintf("%.3f", result.Stats.RefreshToken.P95Ms))
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

	token, signMs, _, err := h.signBenchmarkToken(req.Algorithm, req.Email, jwtutils.TokenUseAccess, false)
	if err != nil {
		h.log.Errorf("benchmark token sign failed: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "failed to generate benchmark token")
	}

	c.Set("X-Sign-Time-Ms", fmt.Sprintf("%.3f", signMs))
	c.Set("X-Token-Generation-Time-Ms", fmt.Sprintf("%.3f", signMs))

	return c.JSON(model.Response[any]{
		Status:  fiber.StatusOK,
		Message: "benchmark token generated",
		Data: fiber.Map{
			"token_type":   "Bearer",
			"access_token": token,
		},
	})
}

// signBenchmarkToken signs one JWT and returns timing + runtime stats.
// usePerOpCPU=true: per-op tick delta, accurate for isolated <1ms ops.
// usePerOpCPU=false: 100ms background monitor, better for steady stress load.
func (h *BenchmarkHandler) signBenchmarkToken(algorithm string, email string, tokenUse string, usePerOpCPU bool) (string, float64, BenchmarkRuntimeStats, error) {
	if h.benchmarkJWT == nil {
		return "", 0, BenchmarkRuntimeStats{}, fmt.Errorf("benchmark signer not configured")
	}

	userID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(strings.ToLower(email)))
	payload := &jwtutils.JWTPayload{
		UserID:    userID,
		Email:     email,
		Algorithm: algorithm,
		TokenUse:  tokenUse,
	}

	// Memory: ReadMemStats is the most reliable cross-version API.
	// TotalAlloc is cumulative (monotonically increasing), so delta = bytes
	// actually allocated during Sign regardless of GC activity.
	// ReadMemStats is called outside the sign timer so STW pause doesn't skew latency.
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	cpuOpBefore := readCPUTicks()
	t0 := time.Now()
	token, err := h.benchmarkJWT.Sign(payload)
	elapsed := time.Since(t0)
	signMs := durationToMs(elapsed)
	cpuOpAfter := readCPUTicks()

	if err != nil {
		return "", 0, BenchmarkRuntimeStats{}, err
	}

	runtime.ReadMemStats(&memAfter)

	cpuDelta := cpuOpAfter - cpuOpBefore

	stats := benchmarkRuntimeStats(memBefore, memAfter, elapsed, cpuDelta, usePerOpCPU)

	return token, signMs, stats, nil
}

func (h *BenchmarkHandler) signPure(algorithm string, usePerOpCPU bool) (float64, BenchmarkRuntimeStats, error) {
	if len(h.benchmarkConfigs) == 0 {
		return 0, BenchmarkRuntimeStats{}, fmt.Errorf("benchmark signer configs not configured")
	}
	cfg, ok := h.benchmarkConfigs[algorithm]
	if !ok || cfg == nil || cfg.Method == nil {
		return 0, BenchmarkRuntimeStats{}, fmt.Errorf("benchmark algorithm not configured: %s", algorithm)
	}

	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	cpuOpBefore := readCPUTicks()
	t0 := time.Now()
	_, err := cfg.Method.Sign(pureSigningInput, cfg.SignKey)
	elapsed := time.Since(t0)
	signMs := durationToMs(elapsed)
	cpuOpAfter := readCPUTicks()

	if err != nil {
		return 0, BenchmarkRuntimeStats{}, err
	}

	runtime.ReadMemStats(&memAfter)
	stats := benchmarkRuntimeStats(memBefore, memAfter, elapsed, cpuOpAfter-cpuOpBefore, usePerOpCPU)

	return signMs, stats, nil
}

func benchmarkRuntimeStats(
	memBefore runtime.MemStats,
	memAfter runtime.MemStats,
	elapsed time.Duration,
	cpuDelta int64,
	usePerOpCPU bool,
) BenchmarkRuntimeStats {
	var cpuPct float64
	wallNs := elapsed.Nanoseconds()
	if usePerOpCPU {
		// Per-op tick delta: accurate for sub-millisecond isolated iterations where
		// the 100ms background window would average in unrelated workload.
		if wallNs > 0 && cpuDelta >= 0 {
			cpuPct = float64(cpuDelta) * 1_000_000_000.0 / float64(wallNs) / float64(runtime.GOMAXPROCS(0))
		}
	} else {
		// Background monitor: stable 100ms window — better under steady stress load.
		// Falls back to per-op delta if the monitor hasn't warmed up yet.
		cpuMonitor.mu.RLock()
		cpuPct = cpuMonitor.pct
		cpuMonitor.mu.RUnlock()
		if cpuPct == 0 && wallNs > 0 && cpuDelta > 0 {
			cpuPct = float64(cpuDelta) * 1_000_000_000.0 / float64(wallNs) / float64(runtime.GOMAXPROCS(0))
		}
	}

	return BenchmarkRuntimeStats{
		MemoryAllocKB:      bytesToKB(memAfter.HeapAlloc),
		MemoryAllocDeltaKB: bytesToKB(memAfter.TotalAlloc - memBefore.TotalAlloc),
		MemorySysKB:        bytesToKB(memAfter.Sys),
		MemoryRSSKB:        readMemoryRSSKB(),
		CPUTimeMs:          float64(cpuDelta) * 10.0,
		CPUPct:             cpuPct,
		GCOccurred:         memAfter.NumGC > memBefore.NumGC,
	}
}

func combineBenchmarkStats(accessStats, refreshStats BenchmarkRuntimeStats) BenchmarkRuntimeStats {
	cpuPct := accessStats.CPUPct
	if refreshStats.CPUPct > cpuPct {
		cpuPct = refreshStats.CPUPct
	}

	return BenchmarkRuntimeStats{
		MemoryAllocKB:      refreshStats.MemoryAllocKB,
		MemoryAllocDeltaKB: accessStats.MemoryAllocDeltaKB + refreshStats.MemoryAllocDeltaKB,
		MemorySysKB:        refreshStats.MemorySysKB,
		MemoryRSSKB:        math.Max(accessStats.MemoryRSSKB, refreshStats.MemoryRSSKB),
		CPUTimeMs:          accessStats.CPUTimeMs + refreshStats.CPUTimeMs,
		CPUPct:             cpuPct,
		GCOccurred:         accessStats.GCOccurred || refreshStats.GCOccurred,
	}
}

func durationToMs(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / float64(time.Millisecond)
}

func bytesToKB(v uint64) float64 {
	return float64(v) / bytesPerKB
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

func scaleValues(values []float64, factor float64) []float64 {
	if len(values) == 0 {
		return nil
	}
	scaled := make([]float64, len(values))
	for i, value := range values {
		scaled[i] = value * factor
	}
	return scaled
}
