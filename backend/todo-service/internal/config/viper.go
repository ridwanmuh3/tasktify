package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

func NewViper() *viper.Viper {
	mode := os.Getenv("APP_MODE")
	if mode == "" {
		mode = "dev"
	}

	config := viper.New()

	if mode == "dev" {
		config.SetConfigFile(".env")
		config.AddConfigPath(".")
		config.AddConfigPath("..")

		if err := config.ReadInConfig(); err != nil {
			panic(fmt.Errorf("failed to read config on env file: %w", err))
		}
	} else {
		// Mode production: hanya membaca dari Environment Variables sistem
		config.AutomaticEnv()
	}

	return config
}
