package handler

// Auth

type SignInRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required"`
	Algorithm string `json:"algorithm"`
}

type RefreshTokenRequest struct {
	UserID       string `json:"user_id"`
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// User

type RegisterRequest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
}

// Task

type CreateTaskRequest struct {
	Title       string `json:"title" validate:"required"`
	Description string `json:"description"`
	Status      string `json:"status" validate:"required"`
	DueDate     *int64 `json:"due_date"`
}

type UpdateTaskRequest struct {
	Title       string `json:"title" validate:"required"`
	Description string `json:"description"`
	Status      string `json:"status" validate:"required"`
	DueDate     *int64 `json:"due_date"`
}

type TaskResponse struct {
	Id          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
	DueDate     int64  `json:"due_date,omitempty"`
	UserId      string `json:"user_id"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

// Benchmark

type BenchmarkRuntimeStats struct {
	MemoryAllocKB      float64
	MemoryAllocDeltaKB float64
	MemorySysKB        float64
	MemoryRSSKB        float64
	CPUTimeMs          float64
	CPUPct             float64
	GCOccurred         bool
}

type BenchmarkSignRequest struct {
	Algorithm        string `json:"algorithm"         validate:"required"`
	Iterations       int    `json:"iterations"        validate:"required,min=1,max=10000"`
	WarmupIterations int    `json:"warmup_iterations"`
	Email            string `json:"email"             validate:"required,email"`
	Password         string `json:"password"`
	PayloadNote      string `json:"payload_note"`
}

type BenchmarkTokenRequest struct {
	Algorithm string `json:"algorithm" validate:"required"`
	Email     string `json:"email"     validate:"required,email"`
	Password  string `json:"password"`
}

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

type BenchmarkSignResult struct {
	Endpoint                 string    `json:"endpoint"`
	MetricScope              string    `json:"metric_scope"`
	Algorithm                string    `json:"algorithm"`
	JWSAlgorithm             string    `json:"jws_alg"`
	Iterations               int       `json:"iterations"`
	WarmupIterations         int       `json:"warmup_iterations"`
	SuccessCount             int       `json:"success_count"`
	GCContaminatedCount      int       `json:"gc_contaminated_count"`
	PayloadNote              string    `json:"payload_note,omitempty"`
	SignTimingsMs            []float64 `json:"sign_timings_ms"`
	TokenGenerationTimingsMs []float64 `json:"token_generation_timings_ms"`
	TokenGenerationGCFreeMs  []float64 `json:"token_generation_gc_free_timings_ms"`
	RefreshTokenTimingsMs    []float64 `json:"refresh_token_generation_timings_ms"`
	RefreshTokenGCFreeMs     []float64 `json:"refresh_token_generation_gc_free_timings_ms"`
	TotalTimingsMs           []float64 `json:"total_timings_ms"`
	AuthCPUPct               []float64 `json:"auth_cpu_pct"`
	AuthCPUTimeMs            []float64 `json:"auth_cpu_time_ms"`
	AuthMemoryAllocKB        []float64 `json:"auth_memory_alloc_kb"`
	AuthMemoryAllocDeltaKB   []float64 `json:"auth_memory_alloc_delta_kb"`
	AuthMemorySysKB          []float64 `json:"auth_memory_sys_kb"`
	AuthMemoryRSSKB          []float64 `json:"auth_memory_rss_kb"`
	Stats                    struct {
		Sign                  TimingStats `json:"sign"`
		TokenGeneration       TimingStats `json:"token_generation"`
		TokenGenerationGCFree TimingStats `json:"token_generation_gc_free"`
		RefreshToken          TimingStats `json:"refresh_token_generation"`
		RefreshTokenGCFree    TimingStats `json:"refresh_token_generation_gc_free"`
		Total                 TimingStats `json:"total"`
		Resource              struct {
			CPUUtilization     NumericStats `json:"cpu_utilization_pct"`
			CPUTimeMs          NumericStats `json:"cpu_time_ms"`
			CPUTimePerTokenMs  NumericStats `json:"cpu_time_per_token_ms"`
			MemoryAllocKB      NumericStats `json:"memory_alloc_kb"`
			MemoryAllocDeltaKB NumericStats `json:"memory_alloc_delta_kb"`
			MemorySysKB        NumericStats `json:"memory_sys_kb"`
			MemoryRSSKB        NumericStats `json:"memory_rss_kb"`
		} `json:"resource"`
	} `json:"stats"`
}

type BenchmarkPureSigningResult struct {
	Endpoint               string    `json:"endpoint"`
	MetricScope            string    `json:"metric_scope"`
	Algorithm              string    `json:"algorithm"`
	JWSAlgorithm           string    `json:"jws_alg"`
	Iterations             int       `json:"iterations"`
	WarmupIterations       int       `json:"warmup_iterations"`
	SuccessCount           int       `json:"success_count"`
	GCContaminatedCount    int       `json:"gc_contaminated_count"`
	PayloadNote            string    `json:"payload_note,omitempty"`
	SigningInputBytes      int       `json:"signing_input_bytes"`
	PureSigningTimingsMs   []float64 `json:"pure_signing_timings_ms"`
	PureSigningGCFreeMs    []float64 `json:"pure_signing_gc_free_timings_ms"`
	AuthCPUPct             []float64 `json:"auth_cpu_pct"`
	AuthCPUTimeMs          []float64 `json:"auth_cpu_time_ms"`
	AuthMemoryAllocKB      []float64 `json:"auth_memory_alloc_kb"`
	AuthMemoryAllocDeltaKB []float64 `json:"auth_memory_alloc_delta_kb"`
	AuthMemorySysKB        []float64 `json:"auth_memory_sys_kb"`
	AuthMemoryRSSKB        []float64 `json:"auth_memory_rss_kb"`
	Stats                  struct {
		PureSigning       TimingStats `json:"pure_signing"`
		PureSigningGCFree TimingStats `json:"pure_signing_gc_free"`
		Resource          struct {
			CPUUtilization     NumericStats `json:"cpu_utilization_pct"`
			CPUTimeMs          NumericStats `json:"cpu_time_ms"`
			CPUTimePerTokenMs  NumericStats `json:"cpu_time_per_token_ms"`
			MemoryAllocKB      NumericStats `json:"memory_alloc_kb"`
			MemoryAllocDeltaKB NumericStats `json:"memory_alloc_delta_kb"`
			MemorySysKB        NumericStats `json:"memory_sys_kb"`
			MemoryRSSKB        NumericStats `json:"memory_rss_kb"`
		} `json:"resource"`
	} `json:"stats"`
}
