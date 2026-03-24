package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func NewDB(viper *viper.Viper, log *zap.SugaredLogger) *gorm.DB {
	dbUsername := viper.GetString("DB_USER")
	dbPassword := viper.GetString("DB_PASSWORD")
	dbName := viper.GetString("DB_NAME")
	dbHost := viper.GetString("DB_HOST")
	dbPort := viper.GetString("DB_PORT")
	dbSslMode := viper.GetString("DB_SSL_MODE")
	dbPoolIdle := viper.GetInt("DB_POOL_IDLE")
	dbMaxPool := viper.GetInt("DB_MAX_POOL")
	dbMaxLifetime := viper.GetDuration("DB_MAX_LIFETIME")

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s  sslmode=%s TimeZone=Asia/Jakarta", dbHost, dbUsername, dbPassword, dbName, dbPort, dbSslMode)

	gormCustomLog := zap.NewStdLog(log.Desugar())

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.New(gormCustomLog, logger.Config{
			SlowThreshold:             time.Second * 5,
			Colorful:                  false,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true,
			LogLevel:                  logger.Warn,
		}),
	})
	if err != nil {
		log.Fatalf("failed to create gorm instance: %v", err)
	}

	conn, err := db.DB()
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	conn.SetMaxOpenConns(dbPoolIdle)
	conn.SetMaxIdleConns(dbMaxPool)
	conn.SetConnMaxLifetime(dbMaxLifetime)

	return db
}
