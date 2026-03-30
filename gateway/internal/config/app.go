package config

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/ridwanmuh3/tasktify/gateway/internal/delivery/http/handler"
	"github.com/ridwanmuh3/tasktify/gateway/internal/delivery/http/middleware"
	"github.com/ridwanmuh3/tasktify/gateway/internal/delivery/http/route"
	"github.com/ridwanmuh3/tasktify/gateway/internal/model"

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

// Supported algorithms for multi-algorithm JWT verification
var supportedAlgorithms = []string{
	"Falcon-512",
	"Falcon-Precomputed-512",
	"ML-DSA-44",
	"SLH-DSA-SHA2-128f",
	"ES256",
	"RS256",
	"HS256",
	"EdDSA",
}

func Bootstrap(config *BootstrapConfig) {
	keysDir := config.Config.GetString("KEYS_DIR")
	if keysDir == "" {
		keysDir = "./keys"
	}

	defaultAlg := config.Config.GetString("JWT_DEFAULT_ALG")
	if defaultAlg == "" {
		defaultAlg = "Falcon-Precomputed-512"
	}

	// Load all algorithm configurations (sign mode = false for gateway, verification only)
	algConfigs, err := jwtutils.LoadAllAlgConfigs(keysDir, supportedAlgorithms, false)
	if err != nil {
		config.Log.Fatalf("failed to load algorithm configs: %v", err)
	}

	issuer := config.Config.GetString("JWT_ISSUER")
	duration := config.Config.GetInt("JWT_TOKEN_DURATION")

	// Multi-algorithm JWT util for token verification
	jwtUtil := jwtutils.NewMultiAlgJwtUtil(issuer, duration, defaultAlg, algConfigs)

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
