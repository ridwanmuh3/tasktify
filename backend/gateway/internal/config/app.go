package config

import (
	"strings"

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

// Supported algorithms for multi-algorithm JWT verification. Fallback when
// JWT_ALLOWED_ALGS is unset; deployments narrow it further (production pins
// FN-DSA-Precomputed-512). FN-DSA only — mixing a symmetric algorithm into a
// verify allow-list alongside asymmetric ones invites algorithm confusion
// (RFC 8725 §3.1).
var supportedAlgorithms = []string{
	"FN-DSA-512",
	"FN-DSA-Precomputed-512",
	"Falcon-512",
	"Falcon-Precomputed-512",
}

func Bootstrap(config *BootstrapConfig) {
	keysDir := config.Config.GetString("KEYS_DIR")
	if keysDir == "" {
		keysDir = "./keys"
	}

	defaultAlg := config.Config.GetString("JWT_DEFAULT_ALG")
	if defaultAlg == "" {
		defaultAlg = "FN-DSA-Precomputed-512"
	}

	// Determine which algorithms to load.
	// JWT_ALLOWED_ALGS narrows the set (useful for benchmark gateways that only
	// need to verify tokens from one algorithm). Falls back to full list.
	// GetStringSlice uses strings.Fields (whitespace split), not comma split —
	// read as string and split manually for comma-separated env var values.
	var algsToLoad []string
	if raw := config.Config.GetString("JWT_ALLOWED_ALGS"); raw != "" {
		for _, a := range strings.Split(raw, ",") {
			if t := strings.TrimSpace(a); t != "" {
				algsToLoad = append(algsToLoad, t)
			}
		}
	}
	if len(algsToLoad) == 0 {
		algsToLoad = supportedAlgorithms
	}

	// Load all algorithm configurations (sign mode = false for gateway, verification only)
	algConfigs, err := jwtutils.LoadAllAlgConfigs(keysDir, algsToLoad, false)
	if err != nil {
		config.Log.Fatalf("failed to load algorithm configs: %v", err)
	}

	issuer := config.Config.GetString("JWT_ISSUER")
	audience := config.Config.GetString("JWT_AUDIENCE")
	duration := config.Config.GetInt("JWT_TOKEN_DURATION")

	// Multi-algorithm JWT util for token verification
	jwtUtil := jwtutils.NewMultiAlgJwtUtil(issuer, audience, duration, defaultAlg, algConfigs)

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
