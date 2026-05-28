package main

import (
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"todo-service/internal/config"
	"todo-service/internal/delivery/grpc/interceptor"
	"todo-service/internal/entity"
)

func main() {
	viperConfig := config.NewViper()
	log := config.NewLogger(viperConfig)
	db := config.NewDB(viperConfig, log)
	validate := config.NewValidator(viperConfig)
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(interceptor.AuthInterceptor),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	db.AutoMigrate(&entity.Task{})

	config.Bootstrap(&config.BootstrapConfig{
		DB:         db,
		GrpcServer: srv,
		Log:        log,
		Validate:   validate,
		Config:     viperConfig,
	})

	grpcPort := viperConfig.GetString("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "3002"
	}

	lst, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("failed to listen server: %v", err)
	}

	log.Infof("todo-service gRPC server listening on :%s", grpcPort)
	if err := srv.Serve(lst); err != nil {
		log.Fatalf("failed to serve grpc server: %v", err)
	}

	defer log.Sync()
}
