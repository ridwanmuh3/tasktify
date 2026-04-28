package service

import (
	"context"
	"runtime"
	"runtime/metrics"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/ridwanmuh3/tasktify/pkg/utils/jwtutils"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"auth-service/internal/entity"
	"auth-service/internal/repository"
)

type RuntimeStats struct {
	MemoryAllocMB float64
	MemorySysMB   float64
	CPUPct        float64
}

var runtimeStatsState struct {
	sync.Mutex
	lastWall time.Time
	lastCPU  float64
}

type AuthService struct {
	db             *gorm.DB
	validate       *validator.Validate
	log            *zap.SugaredLogger
	userRepository *repository.UserRepository
	jwtUtil        jwtutils.JwtUtil
}

func NewAuthService(
	db *gorm.DB,
	validate *validator.Validate,
	log *zap.SugaredLogger,
	userRepository *repository.UserRepository,
	jwtUtil jwtutils.JwtUtil,
) *AuthService {
	return &AuthService{
		db:             db,
		validate:       validate,
		log:            log,
		userRepository: userRepository,
		jwtUtil:        jwtUtil,
	}
}

// SignIn returns (accessToken, refreshToken, tokenGenerationMs, runtimeStats, error).
// tokenGenerationMs is measured around JWT generation only, isolated from DB lookup and bcrypt.
func (s *AuthService) SignIn(ctx context.Context, email, password, algorithm string) (string, string, float64, RuntimeStats, error) {
	db := s.db.WithContext(ctx)

	user := new(entity.User)
	if err := s.userRepository.GetByEmail(db, email, user); err != nil {
		s.log.Warnf("user not found with email %s: %v", email, err)
		return "", "", 0, RuntimeStats{}, status.Error(codes.Unauthenticated, "invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		s.log.Warnf("invalid password for email %s", email)
		return "", "", 0, RuntimeStats{}, status.Error(codes.Unauthenticated, "invalid email or password")
	}

	signStart := time.Now()
	accessToken, err := s.jwtUtil.Sign(&jwtutils.JWTPayload{
		UserID:    user.Id,
		Email:     user.Email,
		Algorithm: algorithm,
	})
	signTimeMs := float64(time.Since(signStart).Microseconds()) / 1000.0

	if err != nil {
		s.log.Errorf("failed to sign access token: %v", err)
		return "", "", 0, RuntimeStats{}, status.Error(codes.Internal, "failed to generate token")
	}

	return accessToken, "", signTimeMs, collectRuntimeStats(), nil
}

func (s *AuthService) Verify(ctx context.Context, token string) error {
	_, err := s.jwtUtil.Parse(token)
	if err != nil {
		return status.Error(codes.Unauthenticated, "invalid token")
	}
	return nil
}

func collectRuntimeStats() RuntimeStats {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	stats := RuntimeStats{
		MemoryAllocMB: bytesToMB(mem.Alloc),
		MemorySysMB:   bytesToMB(mem.Sys),
	}

	now := time.Now()
	cpuSeconds := readGoCPUSeconds()

	runtimeStatsState.Lock()
	defer runtimeStatsState.Unlock()

	if !runtimeStatsState.lastWall.IsZero() {
		wallSeconds := now.Sub(runtimeStatsState.lastWall).Seconds()
		cpuDelta := cpuSeconds - runtimeStatsState.lastCPU
		if wallSeconds > 0 && cpuDelta >= 0 {
			stats.CPUPct = (cpuDelta / wallSeconds / float64(runtime.GOMAXPROCS(0))) * 100
		}
	}
	runtimeStatsState.lastWall = now
	runtimeStatsState.lastCPU = cpuSeconds

	return stats
}

func readGoCPUSeconds() float64 {
	samples := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindFloat64 {
		return 0
	}
	return samples[0].Value.Float64()
}

func bytesToMB(v uint64) float64 {
	return float64(v) / 1024.0 / 1024.0
}
