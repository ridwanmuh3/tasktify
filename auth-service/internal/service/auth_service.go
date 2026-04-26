package service

import (
	"context"
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

// SignIn returns (accessToken, refreshToken, signTimeMs, error).
// signTimeMs is the pure cryptographic signing duration in milliseconds,
// isolated from DB lookup and bcrypt — usable as clean signing latency.
func (s *AuthService) SignIn(ctx context.Context, email, password, algorithm string) (string, string, float64, error) {
	db := s.db.WithContext(ctx)

	user := new(entity.User)
	if err := s.userRepository.GetByEmail(db, email, user); err != nil {
		s.log.Warnf("user not found with email %s: %v", email, err)
		return "", "", 0, status.Error(codes.Unauthenticated, "invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		s.log.Warnf("invalid password for email %s", email)
		return "", "", 0, status.Error(codes.Unauthenticated, "invalid email or password")
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
		return "", "", 0, status.Error(codes.Internal, "failed to generate token")
	}

	return accessToken, "", signTimeMs, nil
}

func (s *AuthService) Verify(ctx context.Context, token string) error {
	_, err := s.jwtUtil.Parse(token)
	if err != nil {
		return status.Error(codes.Unauthenticated, "invalid token")
	}
	return nil
}
