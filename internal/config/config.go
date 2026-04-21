package config

import (
	"os"
	"path/filepath"
	"runtime"
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

	// Storage backend: "postgres" or "sqlite"
	StorageBackend string
	SQLiteDBPath   string

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

	storageBackend := os.Getenv("STORAGE_BACKEND")
	if storageBackend == "" {
		storageBackend = "postgres"
	}

	sqliteDBPath := os.Getenv("SQLITE_DB_PATH")
	if sqliteDBPath == "" {
		sqliteDBPath = filepath.Join(defaultAppDataDir(), "vault.db")
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
		StorageBackend:  storageBackend,
		SQLiteDBPath:    sqliteDBPath,
		EnableSMS2FA:    os.Getenv("ENABLE_SMS_2FA") == "true",
		TelnyxAPIKey:    os.Getenv("TELNYX_API_KEY"),
		TelnyxFromNum:   os.Getenv("TELNYX_FROM_NUMBER"),
	}
}

// defaultAppDataDir returns the platform-specific default app data directory.
func defaultAppDataDir() string {
	const appName = "QuantumPasswordManager"
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
		return filepath.Join(appData, appName)
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", appName)
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", appName)
	}
}
