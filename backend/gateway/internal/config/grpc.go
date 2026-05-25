package config

import (
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// grpcClientOpts shared keep-alive params — keeps the single HTTP/2 connection alive
// under sustained 50-VU concurrent load and long-running benchmark calls.
var grpcClientOpts = []grpc.DialOption{
	grpc.WithTransportCredentials(insecure.NewCredentials()),
	grpc.WithKeepaliveParams(keepalive.ClientParameters{
		// Send pings every 20s if no activity — detects stale connections fast.
		Time: 20 * time.Second,
		// Wait 10s for ping ack before declaring connection dead.
		Timeout: 10 * time.Second,
		// Send pings even without active RPC streams (e.g. between VU bursts).
		PermitWithoutStream: true,
	}),
}

func NewAuthServiceConn(config *viper.Viper, log *zap.SugaredLogger) *grpc.ClientConn {
	addr := config.GetString("AUTH_SERVICE_ADDR")
	if addr == "" {
		addr = "localhost:3001"
	}

	conn, err := grpc.NewClient(addr, grpcClientOpts...)
	if err != nil {
		log.Fatalf("failed to connect to auth-service: %v", err)
	}

	log.Infof("connected to auth-service at %s", addr)
	return conn
}

func NewTodoServiceConn(config *viper.Viper, log *zap.SugaredLogger) *grpc.ClientConn {
	addr := config.GetString("TODO_SERVICE_ADDR")
	if addr == "" {
		addr = "localhost:3002"
	}

	conn, err := grpc.NewClient(addr, grpcClientOpts...)
	if err != nil {
		log.Fatalf("failed to connect to todo-service: %v", err)
	}

	log.Infof("connected to todo-service at %s", addr)
	return conn
}
