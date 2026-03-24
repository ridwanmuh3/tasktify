package main

import (
	"net"

	"google.golang.org/grpc"

	"auth-service/internal/config"
	"auth-service/internal/entity"
)

func main() {
	viperConfig := config.NewViper()
	log := config.NewLogger(viperConfig)
	db := config.NewDB(viperConfig, log)
	validate := config.NewValidator(viperConfig)
	srv := grpc.NewServer()

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
