package service

import (
	"context"

	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"auth-service/internal/entity"
	"auth-service/internal/repository"

	"github.com/ridwanmuh3/tasktify/pkg/utils/jwtutils"
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

func (s *AuthService) SignIn(ctx context.Context, email, password, algorithm string) (string, string, error) {
	db := s.db.WithContext(ctx)

	user := new(entity.User)
	if err := s.userRepository.GetByEmail(db, email, user); err != nil {
		s.log.Warnf("user not found with email %s: %v", email, err)
		return "", "", status.Error(codes.Unauthenticated, "invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		s.log.Warnf("invalid password for email %s", email)
		return "", "", status.Error(codes.Unauthenticated, "invalid email or password")
	}

	accessToken, err := s.jwtUtil.Sign(&jwtutils.JWTPayload{
		UserID:    user.Id,
		Email:     user.Email,
		Algorithm: algorithm,
	})
	if err != nil {
		s.log.Errorf("failed to sign access token: %v", err)
		return "", "", status.Error(codes.Internal, "failed to generate token")
	}

	refreshToken, err := s.jwtUtil.Sign(&jwtutils.JWTPayload{
		UserID:    user.Id,
		Email:     user.Email,
		Algorithm: algorithm,
	})
	if err != nil {
		s.log.Errorf("failed to sign refresh token: %v", err)
		return "", "", status.Error(codes.Internal, "failed to generate token")
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) Verify(ctx context.Context, token string) error {
	_, err := s.jwtUtil.Parse(token)
	if err != nil {
		return status.Error(codes.Unauthenticated, "invalid token")
	}
	return nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (string, string, error) {
	claims, err := s.jwtUtil.Parse(refreshToken)
	if err != nil {
		return "", "", status.Error(codes.Unauthenticated, "invalid refresh token")
	}

	accessToken, err := s.jwtUtil.Sign(&jwtutils.JWTPayload{
		UserID: claims.UserID,
		Email:  claims.Email,
	})
	if err != nil {
		s.log.Errorf("failed to sign access token: %v", err)
		return "", "", status.Error(codes.Internal, "failed to generate token")
	}

	newRefreshToken, err := s.jwtUtil.Sign(&jwtutils.JWTPayload{
		UserID: claims.UserID,
		Email:  claims.Email,
	})
	if err != nil {
		s.log.Errorf("failed to sign refresh token: %v", err)
		return "", "", status.Error(codes.Internal, "failed to generate token")
	}

	return accessToken, newRefreshToken, nil
}
