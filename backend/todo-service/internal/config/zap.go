package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func NewLogger(config *viper.Viper) *zap.SugaredLogger {
	var zapConfig zap.Config
	var log *zap.Logger
	var err error

	if config.GetString("APP_MODE") == "prod" {
		zapConfig = zap.NewProductionConfig()

		cwd, _ := os.Getwd()
		logDir := filepath.Join(cwd, "logs")
		if err := os.MkdirAll(logDir, 0o755); err != nil {
			panic(fmt.Errorf("failed to create log directory: %v", err))
		}

		logFileName := filepath.Join(logDir, fmt.Sprintf("server-%d.log", time.Now().Unix()))

		file, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(fmt.Errorf("failed to create log file: %v", err))
		}
		defer file.Close()

		zapConfig.OutputPaths = []string{
			"stdout",
			logFileName,
		}

		log, err = zapConfig.Build(zap.AddStacktrace(zap.WarnLevel))
		if err != nil {
			panic(fmt.Errorf("failed to instantiate logger: %v", err))
		}
	} else {
		zapConfig = zap.NewDevelopmentConfig()
		zapConfig.OutputPaths = []string{
			"stdout",
		}

		log, err = zapConfig.Build(zap.AddStacktrace(zap.ErrorLevel))
		if err != nil {
			panic(fmt.Errorf("failed to instantiate logger: %v", err))
		}
	}

	return log.Sugar()
}
