package interceptor

import (
	"context"

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

	authCtx := context.WithValue(ctx, server.AuthContextKey, userIDs[0])

	return handler(authCtx, req)
}
