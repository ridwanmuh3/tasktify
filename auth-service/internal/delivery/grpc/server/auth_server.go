package server

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"

	"auth-service/internal/model"
	"auth-service/internal/service"
)

type AuthServer struct {
	model.UnimplementedAuthServiceServer
	log         *zap.SugaredLogger
	authService *service.AuthService
}

func NewAuthServer(log *zap.SugaredLogger, authService *service.AuthService) *AuthServer {
	return &AuthServer{
		log:         log,
		authService: authService,
	}
}

func (s *AuthServer) SignIn(ctx context.Context, request *model.SignInRequest) (*model.AuthResponse, error) {
	accessToken, refreshToken, err := s.authService.SignIn(ctx, request.Email, request.Password)
	if err != nil {
		return nil, err
	}

	return &model.AuthResponse{
		Auth: &model.Auth{
			TokenType:    "Bearer",
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}, nil
}

func (s *AuthServer) RefreshToken(ctx context.Context, request *model.RefreshTokenRequest) (*model.AuthResponse, error) {
	accessToken, refreshToken, err := s.authService.RefreshToken(ctx, request.RefreshToken)
	if err != nil {
		return nil, err
	}

	return &model.AuthResponse{
		Auth: &model.Auth{
			TokenType:    "Bearer",
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}, nil
}

func (s *AuthServer) Verify(ctx context.Context, request *model.VerifyRequest) (*emptypb.Empty, error) {
	if err := s.authService.Verify(ctx, request.Token); err != nil {
		return nil, err
	}
	return new(emptypb.Empty), nil
}
