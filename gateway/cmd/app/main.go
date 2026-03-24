package main

import (
	"fmt"

	"github.com/ridwanmuh3/tasktify/gateway/internal/config"
)

func main() {
	viperConfig := config.NewViper()
	log := config.NewLogger(viperConfig)
	validate := config.NewValidator(viperConfig)
	app := config.NewFiber(viperConfig)

	// gRPC client connections ke backend services
	authServiceConn := config.NewAuthServiceConn(viperConfig, log)
	defer authServiceConn.Close()

	todoServiceConn := config.NewTodoServiceConn(viperConfig, log)
	defer todoServiceConn.Close()

	config.Bootstrap(&config.BootstrapConfig{
		App:             app,
		Log:             log,
		Validate:        validate,
		Config:          viperConfig,
		AuthServiceConn: authServiceConn,
		TodoServiceConn: todoServiceConn,
	})

	appPort := viperConfig.GetInt("APP_PORT")
	log.Infof("gateway listening on :%d", appPort)
	if err := app.Listen(fmt.Sprintf(":%d", appPort)); err != nil {
		log.Fatalf("failed to start gateway: %v", err)
	}

	defer log.Sync()
}
