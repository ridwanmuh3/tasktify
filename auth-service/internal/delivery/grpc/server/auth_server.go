package server

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
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
	accessToken, refreshToken, tokenGenerationMs, runtimeStats, err := s.authService.SignIn(ctx, request.Email, request.Password, request.Algorithm)
	if err != nil {
		return nil, err
	}

	// Expose clean token-generation latency and auth-service resource usage
	// as gRPC trailers so gateway can forward them as k6-visible headers.
	grpc.SetTrailer(ctx, metadata.Pairs(
		"x-sign-time-ms", fmt.Sprintf("%.3f", tokenGenerationMs),
		"x-token-generation-time-ms", fmt.Sprintf("%.3f", tokenGenerationMs),
		"x-auth-cpu-pct", fmt.Sprintf("%.3f", runtimeStats.CPUPct),
		"x-auth-mem-alloc-mb", fmt.Sprintf("%.3f", runtimeStats.MemoryAllocMB),
		"x-auth-mem-sys-mb", fmt.Sprintf("%.3f", runtimeStats.MemorySysMB),
	))

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
