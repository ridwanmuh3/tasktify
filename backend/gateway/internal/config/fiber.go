package config

import (
	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/spf13/viper"

	"github.com/ridwanmuh3/tasktify/gateway/internal/exception"
)

// PQC JWT Authorization header sizes (base64url-encoded signatures):
//   Falcon-512 / Precomputed-512 :  ~1.1 KB  — fits in 4 KB default
//   ML-DSA-44                    :  ~3.4 KB  — fails combined with other headers
//   SLH-DSA-SHA2-128s            : ~10.5 KB  — always fails at 4 KB default
//   SLH-DSA-SHA2-128f            : ~22.5 KB  — always fails at 4 KB default
//
// Fasthttp ReadBufferSize is a hard cap on the total request header section.
// 64 KB gives ~3× headroom over the largest current algorithm (SLH-DSA-SHA2-128f).
const pqcReadBufferSize = 64 * 1024 // 64 KB

func NewFiber(config *viper.Viper) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:      config.GetString("APP_NAME"),
		JSONEncoder:  sonic.Marshal,
		JSONDecoder:  sonic.Unmarshal,
		ErrorHandler: exception.NewErrorHandler(),
		// Must be ≥ largest PQC Authorization header (SLH-DSA-SHA2-128f ≈ 22.5 KB).
		// Default 4096 causes Fasthttp to reject requests with large JWT tokens.
		ReadBufferSize: pqcReadBufferSize,
	})

	app.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{
			fiber.MethodGet,
			fiber.MethodPost,
			fiber.MethodPut,
			fiber.MethodDelete,
			fiber.MethodOptions,
		},
		AllowHeaders: []string{
			fiber.HeaderAccept,
			fiber.HeaderAuthorization,
			fiber.HeaderContentType,
			fiber.HeaderOrigin,
		},
	}))

	return app
}
