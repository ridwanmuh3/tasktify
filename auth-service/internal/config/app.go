package config

import (
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gorm.io/gorm"

	"auth-service/internal/delivery/grpc/server"
	"auth-service/internal/model"
	"auth-service/internal/repository"
	"auth-service/internal/service"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
	"github.com/ridwanmuh3/tasktify/pkg/jwt"
	"github.com/ridwanmuh3/tasktify/pkg/utils/jwtutils"
)

type BootstrapConfig struct {
	DB         *gorm.DB
	GrpcServer *grpc.Server
	Log        *zap.SugaredLogger
	Validate   *validator.Validate
	Config     *viper.Viper
}

func Bootstrap(config *BootstrapConfig) {
	// Load Falcon private key and create precomputed signer
	skPath := config.Config.GetString("JWT_PRIVATE_KEY_PATH")
	skBytes, err := os.ReadFile(skPath)
	if err != nil {
		config.Log.Fatalf("failed to read private key file: %v", err)
	}
	secretKey, err := jwt.ParseFalconPrivateKeyFromPEM(skBytes)
	if err != nil {
		config.Log.Fatalf("failed to parse private key: %v", err)
	}
	signer, err := fndsa.NewPrecomputedSigner(secretKey)
	if err != nil {
		config.Log.Fatalf("failed to create precomputed signer: %v", err)
	}

	// Set precomputed signer on signing method (loaded once)
	jwtMethod := jwt.SigningMethodFNP512
	jwtMethod.SetPrecomputedSigner(signer)

	// Load Falcon public key for verification
	vkPath := config.Config.GetString("JWT_PUBLIC_KEY_PATH")
	vkBytes, err := os.ReadFile(vkPath)
	if err != nil {
		config.Log.Fatalf("failed to read public key file: %v", err)
	}
	verifyKey, err := jwt.ParseFalconPublicKeyFromPEM(vkBytes)
	if err != nil {
		config.Log.Fatalf("failed to parse public key: %v", err)
	}

	// JWT util with precomputed signer
	jwtUtil := jwtutils.NewJwtUtilWithSigner(config.Config, jwtMethod, verifyKey)

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
