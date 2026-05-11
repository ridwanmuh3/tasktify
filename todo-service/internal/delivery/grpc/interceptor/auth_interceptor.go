package interceptor

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"todo-service/internal/delivery/grpc/server"
)

func AuthInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "metadata not provided")
	}

	userIDs := md.Get("x-user-id")
	if len(userIDs) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "x-user-id not provided")
	}

	// Reject malformed values — valid user IDs are always UUIDs set by the gateway
	// after JWT verification. Any non-UUID value indicates a misconfiguration or
	// an attacker probing the gRPC port directly.
	if _, err := uuid.Parse(userIDs[0]); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid x-user-id")
	}

	authCtx := context.WithValue(ctx, server.AuthContextKey, userIDs[0])

	return handler(authCtx, req)
}
