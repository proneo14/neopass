package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port          int
	DatabaseURL   string
	MigrationsDir string
	TLSCert       string
	TLSKey        string
	LogLevel      string
}

func Load() *Config {
	port := 8443
	if p := os.Getenv("PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	return &Config{
		Port:          port,
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		MigrationsDir: os.Getenv("MIGRATIONS_DIR"),
		TLSCert:       os.Getenv("TLS_CERT"),
		TLSKey:        os.Getenv("TLS_KEY"),
		LogLevel:      logLevel,
	}
}
