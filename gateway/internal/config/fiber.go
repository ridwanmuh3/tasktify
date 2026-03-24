package config

import (
	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"

	"github.com/ridwanmuh3/tasktify/gateway/internal/exception"
)

func NewFiber(config *viper.Viper) *fiber.App {
	return fiber.New(fiber.Config{
		AppName:      config.GetString("APP_NAME"),
		JSONEncoder:  sonic.Marshal,
		JSONDecoder:  sonic.Unmarshal,
		ErrorHandler: exception.NewErrorHandler(),
	})
}
