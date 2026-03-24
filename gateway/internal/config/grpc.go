package config

import (
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func NewAuthServiceConn(config *viper.Viper, log *zap.SugaredLogger) *grpc.ClientConn {
	addr := config.GetString("AUTH_SERVICE_ADDR")
	if addr == "" {
		addr = "localhost:3001"
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to connect to todo-service: %v", err)
	}

	log.Infof("connected to todo-service at %s", addr)
	return conn
}
