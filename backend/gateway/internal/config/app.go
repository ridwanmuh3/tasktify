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

// Supported algorithms for multi-algorithm JWT verification.
// HS256/RS256/ES256 are classical baselines kept alongside the PQC profiles
// for the adversarial + performance comparison (thesis defense requirement).
var supportedAlgorithms = []string{
	"FN-DSA-512",
	"FN-DSA-Precomputed-512",
	"Falcon-512",
	"Falcon-Precomputed-512",
	"HS256",
	"RS256",
	"ES256",
	"EdDSA",
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
	// Benchmark signing configs must cover every algorithm the benchmark client
	// exercises, so they are loaded from the full supportedAlgorithms list rather
	// than the JWT_ALLOWED_ALGS-narrowed set. Narrowing is meant for production
	// verification; narrowing the benchmark signer makes /api/benchmark reject any
	// algorithm not in the production allow-list (e.g. FN-DSA-Precomputed-512).
	benchmarkAlgConfigs, err := jwtutils.LoadAllAlgConfigs(keysDir, supportedAlgorithms, true)
	if err != nil {
		config.Log.Fatalf("failed to load benchmark signing configs: %v", err)
	}

	issuer := config.Config.GetString("JWT_ISSUER")
	duration := config.Config.GetInt("JWT_TOKEN_DURATION")

	// Multi-algorithm JWT util for token verification
	jwtUtil := jwtutils.NewMultiAlgJwtUtil(issuer, duration, defaultAlg, algConfigs)
	benchmarkJWT := jwtutils.NewMultiAlgJwtUtil(issuer, duration, defaultAlg, benchmarkAlgConfigs)

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
	benchmarkHandler := handler.NewBenchmarkHandler(config.Log, benchmarkJWT, benchmarkAlgConfigs)

	routeConfig := &route.RouteConfig{
		App:              config.App,
		Log:              config.Log,
		AuthHandler:      authHandler,
		UserHandler:      userHandler,
		TaskHandler:      taskHandler,
		BenchmarkHandler: benchmarkHandler,
		AuthMiddleware:   authMiddleware,
	}

	routeConfig.Setup()
}
