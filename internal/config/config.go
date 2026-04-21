package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port          int
	DatabaseURL   string
	SidecarMode   bool
	ExtensionSecret string
	MigrationsDir string
	TLSCert       string
	TLSKey        string
	LogLevel      string
	CORSOrigins   []string

	// SMS 2FA (Telnyx)
	EnableSMS2FA   bool
	TelnyxAPIKey   string
	TelnyxFromNum  string
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

	var corsOrigins []string
	if co := os.Getenv("CORS_ORIGINS"); co != "" {
		for _, o := range strings.Split(co, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				corsOrigins = append(corsOrigins, trimmed)
			}
		}
	}

	return &Config{
		Port:            port,
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		MigrationsDir:   os.Getenv("MIGRATIONS_DIR"),
		TLSCert:         os.Getenv("TLS_CERT"),
		TLSKey:          os.Getenv("TLS_KEY"),
		LogLevel:        logLevel,
		CORSOrigins:     corsOrigins,
		SidecarMode:     os.Getenv("SIDECAR_MODE") == "1",
		ExtensionSecret: os.Getenv("EXTENSION_SECRET"),
		EnableSMS2FA:    os.Getenv("ENABLE_SMS_2FA") == "true",
		TelnyxAPIKey:    os.Getenv("TELNYX_API_KEY"),
		TelnyxFromNum:   os.Getenv("TELNYX_FROM_NUMBER"),
	}
}
