package main

import (
	"net"

	"google.golang.org/grpc"

	"todo-service/internal/config"
	"todo-service/internal/delivery/grpc/interceptor"
)

func main() {
	viperConfig := config.NewViper()
	log := config.NewLogger(viperConfig)
	db := config.NewDB(viperConfig, log)
	validate := config.NewValidator(viperConfig)
	srv := grpc.NewServer(grpc.UnaryInterceptor(interceptor.AuthInterceptor))

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
