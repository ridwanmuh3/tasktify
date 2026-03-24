package config

import (
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gorm.io/gorm"

	"todo-service/internal/delivery/grpc/server"
	"todo-service/internal/model"
	"todo-service/internal/repository"
	"todo-service/internal/service"
)

type BootstrapConfig struct {
	DB         *gorm.DB
	GrpcServer *grpc.Server
	Log        *zap.SugaredLogger
	Validate   *validator.Validate
	Config     *viper.Viper
}

func Bootstrap(config *BootstrapConfig) {
	// repositories
	taskRepository := repository.NewTaskRepository()

	// services
	taskService := service.NewTaskService(config.DB, config.Validate, config.Log, taskRepository)

	// gRPC Server
	taskServer := server.NewTaskServer(config.Log, taskService)

	model.RegisterTaskServiceServer(config.GrpcServer, taskServer)
	reflection.Register(config.GrpcServer)
}
