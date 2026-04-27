package config

import (
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/ridwanmuh3/tasktify/pkg/utils/jwtutils"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gorm.io/gorm"

	"auth-service/internal/delivery/grpc/server"
	"auth-service/internal/model"
	"auth-service/internal/repository"
	"auth-service/internal/service"
)

type BootstrapConfig struct {
	DB         *gorm.DB
	GrpcServer *grpc.Server
	Log        *zap.SugaredLogger
	Validate   *validator.Validate
	Config     *viper.Viper
}

// Supported algorithms for multi-algorithm JWT signing
var supportedAlgorithms = []string{
	"Falcon-512",
	"Falcon-Precomputed-512",
	"ML-DSA-44",
	"SLH-DSA-SHA2-128f",
	"SLH-DSA-SHA2-128s",
	"SLH-DSA-SHAKE-128f",
	"SLH-DSA-SHAKE-128s",
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

	// Determine which algorithms to load.
	// JWT_ALLOWED_ALGS narrows the set (useful for benchmark services that only
	// need one algorithm). Falls back to the full supportedAlgorithms list.
	// Use GetString+Split because viper AutomaticEnv doesn't split comma-separated env vars.
	var algsToLoad []string
	if raw := config.Config.GetString("JWT_ALLOWED_ALGS"); raw != "" {
		algsToLoad = strings.Split(raw, ",")
	}
	if len(algsToLoad) == 0 {
		algsToLoad = supportedAlgorithms
	}

	// Load all algorithm configurations (sign mode = true for auth-service)
	algConfigs, err := jwtutils.LoadAllAlgConfigs(keysDir, algsToLoad, true)
	if err != nil {
		config.Log.Fatalf("failed to load algorithm configs: %v", err)
	}

	issuer := config.Config.GetString("JWT_ISSUER")
	duration := config.Config.GetInt("JWT_TOKEN_DURATION")

	// Multi-algorithm JWT utility
	jwtUtil := jwtutils.NewMultiAlgJwtUtil(issuer, duration, defaultAlg, algConfigs)

	// repositories
	userRepository := repository.NewUserRepository()

	// services
	authService := service.NewAuthService(config.DB, config.Validate, config.Log, userRepository, jwtUtil)
	userService := service.NewUserService(config.DB, config.Validate, config.Log, userRepository)

	// gRPC servers
	authServer := server.NewAuthServer(config.Log, authService)
	userServer := server.NewUserServer(config.Log, userService)

	model.RegisterAuthServiceServer(config.GrpcServer, authServer)
	model.RegisterUserServiceServer(config.GrpcServer, userServer)
	reflection.Register(config.GrpcServer)
}
