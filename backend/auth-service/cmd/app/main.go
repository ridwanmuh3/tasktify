package main

import (
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"auth-service/internal/config"
	"auth-service/internal/entity"
)

func main() {
	viperConfig := config.NewViper()
	log := config.NewLogger(viperConfig)
	db := config.NewDB(viperConfig, log)
	validate := config.NewValidator(viperConfig)
	srv := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			// Send pings every 30s of inactivity to keep connection alive under sustained load.
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			// Allow client pings even without active streams (benchmark idle periods).
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	db.AutoMigrate(&entity.User{})

	config.Bootstrap(&config.BootstrapConfig{
		DB:         db,
		GrpcServer: srv,
		Log:        log,
		Validate:   validate,
		Config:     viperConfig,
	})

	grpcPort := viperConfig.GetString("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "3001"
	}

	lst, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("failed to listen server: %v", err)
	}

	log.Infof("auth-service gRPC server listening on :%s", grpcPort)
	if err := srv.Serve(lst); err != nil {
		log.Fatalf("failed to serve grpc server: %v", err)
	}

	defer log.Sync()
}
