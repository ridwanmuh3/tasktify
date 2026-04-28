package handler

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/ridwanmuh3/tasktify/gateway/internal/model"
)

type BenchmarkHandler struct {
	log        *zap.SugaredLogger
	authClient model.AuthServiceClient
}

func NewBenchmarkHandler(log *zap.SugaredLogger, authClient model.AuthServiceClient) *BenchmarkHandler {
	return &BenchmarkHandler{log: log, authClient: authClient}
}

// BenchmarkSignRequest defines an isolated signing-latency experiment.
// Use a pre-registered benchmark user (email/password).
// PayloadNote is metadata-only — it has no effect on the signing itself
// but is echoed in the response for experiment traceability.
type BenchmarkSignRequest struct {
	Algorithm   string `json:"algorithm"    validate:"required"`
	Iterations  int    `json:"iterations"   validate:"required,min=1,max=10000"`
	Email       string `json:"email"        validate:"required,email"`
	Password    string `json:"password"     validate:"required"`
	PayloadNote string `json:"payload_note"` // optional experiment label
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
// TokenGenerationTimingsMs = JWT generation durations reported by auth-service (clean time).
// TotalTimingsMs = full gRPC round-trip durations measured here in gateway (dirty time).
// The difference (total - sign) isolates network + serialization overhead.
type BenchmarkSignResult struct {
	Algorithm                string    `json:"algorithm"`
	Iterations               int       `json:"iterations"`
	SuccessCount             int       `json:"success_count"`
	PayloadNote              string    `json:"payload_note,omitempty"`
	SignTimingsMs            []float64 `json:"sign_timings_ms"`             // backward-compatible alias
	TokenGenerationTimingsMs []float64 `json:"token_generation_timings_ms"` // clean: JWT generation only
	TotalTimingsMs           []float64 `json:"total_timings_ms"`            // dirty: full gRPC call
	TokenSizeBytes           []float64 `json:"token_size_bytes"`
	TokenHeaderSizeBytes     []float64 `json:"token_header_size_bytes"`
	TokenBodySizeBytes       []float64 `json:"token_body_size_bytes"`
	TokenSignatureSizeBytes  []float64 `json:"token_signature_size_bytes"`
	AuthCPUPct               []float64 `json:"auth_cpu_pct"`
	AuthMemoryAllocMB        []float64 `json:"auth_memory_alloc_mb"`
	AuthMemorySysMB          []float64 `json:"auth_memory_sys_mb"`
	Stats                    struct {
		Sign            TimingStats `json:"sign"`             // backward-compatible alias
		TokenGeneration TimingStats `json:"token_generation"` // clean token generation
		Total           TimingStats `json:"total"`            // dirty (sign + gRPC overhead) stats
		TokenSize       struct {
			Token     NumericStats `json:"token"`
			Header    NumericStats `json:"header"`
			Body      NumericStats `json:"body"`
			Signature NumericStats `json:"signature"`
		} `json:"token_size"`
		Resource struct {
			CPUUtilization NumericStats `json:"cpu_utilization_pct"`
			MemoryAllocMB  NumericStats `json:"memory_alloc_mb"`
			MemorySysMB    NumericStats `json:"memory_sys_mb"`
		} `json:"resource"`
	} `json:"stats"`
}

// SignLatency runs N sequential sign-in calls and returns per-iteration timing data.
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
	memSysSamples := make([]float64, 0, req.Iterations)

	for i := 0; i < req.Iterations; i++ {
		var trailer metadata.MD

		start := time.Now()
		resp, err := h.authClient.SignIn(c.Context(), &model.SignInRequest{
			Email:     req.Email,
			Password:  req.Password,
			Algorithm: req.Algorithm,
		}, grpc.Trailer(&trailer))
		elapsedMs := float64(time.Since(start).Microseconds()) / 1000.0

		if err != nil {
			h.log.Warnf("benchmark iter %d failed: %v", i, err)
			continue
		}

		totalTimings = append(totalTimings, elapsedMs)
		if resp != nil && resp.Auth != nil {
			addTokenSizeSamples(resp.Auth.AccessToken, &tokenSizes, &tokenHeaderSizes, &tokenBodySizes, &tokenSignatureSizes)
		}

		if vals := trailer.Get("x-sign-time-ms"); len(vals) > 0 {
			if t, ok := parseFloat(vals[0]); ok {
				signTimings = append(signTimings, t)
			}
		}
		if vals := trailer.Get("x-auth-cpu-pct"); len(vals) > 0 {
			if t, ok := parseFloat(vals[0]); ok {
				cpuSamples = append(cpuSamples, t)
			}
		}
		if vals := trailer.Get("x-auth-mem-alloc-mb"); len(vals) > 0 {
			if t, ok := parseFloat(vals[0]); ok {
				memAllocSamples = append(memAllocSamples, t)
			}
		}
		if vals := trailer.Get("x-auth-mem-sys-mb"); len(vals) > 0 {
			if t, ok := parseFloat(vals[0]); ok {
				memSysSamples = append(memSysSamples, t)
			}
		}
	}

	result := BenchmarkSignResult{
		Algorithm:                req.Algorithm,
		Iterations:               req.Iterations,
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

func parseFloat(s string) (float64, bool) {
	var v float64
	if _, err := fmt.Sscanf(s, "%f", &v); err != nil {
		return 0, false
	}
	return v, true
}
