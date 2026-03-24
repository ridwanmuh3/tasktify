package config

import (
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/ridwanmuh3/tasktify/gateway/internal/delivery/http/handler"
	"github.com/ridwanmuh3/tasktify/gateway/internal/delivery/http/middleware"
	"github.com/ridwanmuh3/tasktify/gateway/internal/delivery/http/route"
	"github.com/ridwanmuh3/tasktify/gateway/internal/model"

	"github.com/ridwanmuh3/tasktify/pkg/jwt"
	"github.com/ridwanmuh3/tasktify/pkg/utils/jwtutils"
)

type BootstrapConfig struct {
	App             *fiber.App
	Log             *zap.SugaredLogger
	Validate        *validator.Validate
	Config          *viper.Viper
	AuthServiceConn *grpc.ClientConn
	TodoServiceConn *grpc.ClientConn
}

func Bootstrap(config *BootstrapConfig) {
	// Load Falcon public key once for JWT verification
	vkPath := config.Config.GetString("JWT_PUBLIC_KEY_PATH")
	vkBytes, err := os.ReadFile(vkPath)
	if err != nil {
		config.Log.Fatalf("failed to read public key file: %v", err)
	}
	verifyKey, err := jwt.ParseFalconPublicKeyFromPEM(vkBytes)
	if err != nil {
		config.Log.Fatalf("failed to parse public key: %v", err)
	}

	// JWT util for token verification (PQC Falcon - public key loaded once)
	jwtUtil := jwtutils.NewJwtUtil(config.Config, verifyKey)

	// gRPC clients
	authClient := model.NewAuthServiceClient(config.AuthServiceConn)
	userClient := model.NewUserServiceClient(config.AuthServiceConn)
	taskClient := model.NewTaskServiceClient(config.TodoServiceConn)

	// middleware
	authMiddleware := middleware.NewAuthMiddleware(config.Log, jwtUtil)

	// handlers
	authHandler := handler.NewAuthHandler(config.Log, authClient)
	userHandler := handler.NewUserHandler(config.Log, userClient)
	taskHandler := handler.NewTaskHandler(config.Log, taskClient)

	routeConfig := &route.RouteConfig{
		App:            config.App,
		Log:            config.Log,
		AuthHandler:    authHandler,
		UserHandler:    userHandler,
		TaskHandler:    taskHandler,
		AuthMiddleware: authMiddleware,
	}

	routeConfig.Setup()
}
