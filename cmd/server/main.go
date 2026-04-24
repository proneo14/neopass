package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/admin"
	"github.com/password-manager/password-manager/internal/api"
	"github.com/password-manager/password-manager/internal/auth"
	"github.com/password-manager/password-manager/internal/config"
	"github.com/password-manager/password-manager/internal/db"
	syncsvc "github.com/password-manager/password-manager/internal/sync"
	"github.com/password-manager/password-manager/internal/vault"
)

func main() {
	cfg := config.Load()

	// Configure structured logging
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Caller().Logger()

	// Database connection (PostgreSQL)
	var database *db.DB
	if cfg.StorageBackend == "postgres" && cfg.DatabaseURL != "" {
		var dbErr error
		database, dbErr = db.New(context.Background(), cfg.DatabaseURL)
		if dbErr != nil {
			log.Fatal().Err(dbErr).Msg("failed to connect to database")
		}
		defer database.Close()

		// Run migrations
		migrationsDir := cfg.MigrationsDir
		if migrationsDir == "" {
			migrationsDir = "migrations"
		}
		if dbErr = database.RunMigrations(context.Background(), migrationsDir); dbErr != nil {
			log.Fatal().Err(dbErr).Msg("failed to run migrations")
		}
	} else if cfg.StorageBackend == "postgres" {
		log.Warn().Msg("DATABASE_URL not set — running without PostgreSQL database")
	}

	// Build router
	r := chi.NewRouter()

	// Middleware stack
	r.Use(api.PanicRecovery)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(api.SecurityHeaders)
	r.Use(api.RequestSizeLimit)
	r.Use(jsonContentType)

	// CORS — configurable via CORS_ORIGINS env var; no wildcard allowed
	if len(cfg.CORSOrigins) > 0 {
		r.Use(api.CORSMiddleware(cfg.CORSOrigins))
	}

	// CSRF protection for browser clients (skip in sidecar mode — local-only server)
	if !cfg.SidecarMode {
		r.Use(api.CSRFMiddleware)
	}

	// General rate limiter: 100 requests per minute per IP
	generalLimiter := api.NewRateLimiter(100, 1*time.Minute)
	r.Use(generalLimiter.RateLimit)

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Initialize auth service
	var authService *auth.Service
	var totpService *auth.TOTPService
	var smsService *auth.SMSService
	var vaultService *vault.Service
	var adminService *admin.Service
	var syncService *syncsvc.Service
	var webauthnService *auth.WebAuthnService
	var vaultRepo db.VaultRepository
	var userRepo db.UserRepository
	var rawSQLiteDB *sql.DB // raw *sql.DB for migration support

	if cfg.StorageBackend == "sqlite" {
		// SQLite standalone mode
		sqliteDB, sqlErr := db.NewSQLiteDB(cfg.SQLiteDBPath)
		if sqlErr != nil {
			log.Fatal().Err(sqlErr).Msg("failed to open sqlite database")
		}
		defer sqliteDB.Close()
		rawSQLiteDB = sqliteDB.DB

		sqliteMigrationsDir := cfg.MigrationsDir
		if sqliteMigrationsDir == "" {
			sqliteMigrationsDir = "migrations/sqlite"
		}
		if sqlErr = sqliteDB.RunMigrations(context.Background(), sqliteMigrationsDir); sqlErr != nil {
			log.Fatal().Err(sqlErr).Msg("failed to run sqlite migrations")
		}

		userRepo = db.NewSQLiteUserRepo(sqliteDB.DB)
		totpRepo := db.NewSQLiteTOTPRepo(sqliteDB.DB)
		sqlVaultRepo := db.NewSQLiteVaultRepo(sqliteDB.DB)
		vaultRepo = sqlVaultRepo
		orgRepo := db.NewSQLiteOrgRepo(sqliteDB.DB)
		auditRepo := db.NewSQLiteAuditRepo(sqliteDB.DB)
		syncRepo := db.NewSQLiteSyncRepo(sqliteDB.DB)

		var authErr error
		authService, authErr = auth.NewService(userRepo, nil, nil, auth.ServiceConfig{}, vaultRepo, orgRepo)
		if authErr != nil {
			log.Fatal().Err(authErr).Msg("failed to create auth service")
		}
		totpService = auth.NewTOTPService(totpRepo, userRepo)
		vaultService = vault.NewService(sqlVaultRepo)
		adminService = admin.NewService(orgRepo, userRepo, sqlVaultRepo, auditRepo)
		syncService = syncsvc.NewService(sqlVaultRepo, syncRepo)

		passkeyRepo := db.NewSQLitePasskeyRepo(sqliteDB.DB)
		adminService.SetPasskeyRepo(passkeyRepo)
		hwKeyRepo := db.NewSQLiteHardwareKeyRepo(sqliteDB.DB)
		webauthnService = auth.NewWebAuthnService(auth.WebAuthnConfig{
			RPDisplayName: "LGI Pass",
			RPID:          "localhost",
			RPOrigins:     []string{"http://localhost"},
		}, passkeyRepo, hwKeyRepo)

		log.Info().Str("path", cfg.SQLiteDBPath).Msg("running with SQLite backend")
	} else if database != nil {
		userRepo = db.NewPgUserRepo(database.Pool)
		totpRepo := db.NewPgTOTPRepo(database.Pool)
		vaultRepo = db.NewPgVaultRepo(database.Pool)
		orgRepo := db.NewPgOrgRepo(database.Pool)
		auditRepo := db.NewPgAuditRepo(database.Pool)
		syncRepo := db.NewPgSyncRepo(database.Pool)
		var authErr error
		authService, authErr = auth.NewService(userRepo, nil, nil, auth.ServiceConfig{}, vaultRepo, orgRepo)
		if authErr != nil {
			log.Fatal().Err(authErr).Msg("failed to create auth service")
		}
		totpService = auth.NewTOTPService(totpRepo, userRepo)
		vaultService = vault.NewService(vaultRepo)
		adminService = admin.NewService(orgRepo, userRepo, vaultRepo, auditRepo)
		syncService = syncsvc.NewService(vaultRepo, syncRepo)

		passkeyRepo := db.NewPgPasskeyRepo(database.Pool)
		adminService.SetPasskeyRepo(passkeyRepo)
		hwKeyRepo := db.NewPgHardwareKeyRepo(database.Pool)
		webauthnService = auth.NewWebAuthnService(auth.WebAuthnConfig{
			RPDisplayName: "LGI Pass",
			RPID:          "localhost",
			RPOrigins:     []string{"http://localhost"},
		}, passkeyRepo, hwKeyRepo)
	}

	// SMS 2FA (works with any backend)
	if cfg.EnableSMS2FA {
		smsService = auth.NewSMSService(auth.SMSConfig{
			Enabled:    true,
			APIKey:     cfg.TelnyxAPIKey,
			FromNumber: cfg.TelnyxFromNum,
		})
	}

	// API v1 route group
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"version":"1.0.0"}`))
		})

		if authService != nil {
			r.Mount("/", api.Router(authService, totpService, smsService, vaultService, adminService, syncService, webauthnService, userRepo, cfg.StorageBackend, rawSQLiteDB))
		}
	})

	// Extension bridge routes (for native messaging host)
	if vaultRepo != nil {
		extSecret := cfg.ExtensionSecret
		if extSecret == "" && cfg.SidecarMode {
			// Generate a random secret if not provided in sidecar mode
			b := make([]byte, 32)
			if _, err := rand.Read(b); err == nil {
				extSecret = hex.EncodeToString(b)
			}
		}
		r.Mount("/extension", api.ExtensionRouter(vaultRepo, extSecret, webauthnService))

		// Write sidecar lockfile in sidecar mode
		if cfg.SidecarMode {
			writeSidecarLockfile(cfg.Port, extSecret)
		}
	}

	// Create server — bind to loopback only in sidecar mode to avoid
	// firewall prompts; otherwise listen on all interfaces.
	addr := fmt.Sprintf(":%d", cfg.Port)
	if cfg.SidecarMode {
		addr = fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Enforce TLS 1.3 minimum when TLS is configured
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			// TLS 1.3 cipher suites are not configurable in Go — all secure suites are used.
			// Go 1.23+ enables X25519Kyber768 hybrid PQ key exchange by default.
		}
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info().Str("addr", addr).Msg("starting server")
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			log.Warn().Msg("TLS not configured — running plain HTTP (development only)")
			err = srv.ListenAndServe() // #nosec G114 -- development only, TLS enforced when certs provided
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server failed")
		}
	}()

	<-ctx.Done()
	log.Info().Msg("shutting down server")

	if cfg.SidecarMode {
		removeSidecarLockfile()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatal().Err(err).Msg("server shutdown failed")
	}

	log.Info().Msg("server stopped")
}

// jsonContentType sets the Content-Type header to application/json for all responses.
func jsonContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// getAppDataDir returns the platform-specific app data directory.
func getAppDataDir() string {
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

// writeSidecarLockfile writes the sidecar port and extension secret to a lockfile
// so the native messaging host can discover and authenticate with the sidecar.
func writeSidecarLockfile(port int, secret string) {
	dir := getAppDataDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Error().Err(err).Msg("failed to create app data directory")
		return
	}

	lockPath := filepath.Join(dir, "sidecar.lock")
	content := fmt.Sprintf("%d\n%s", port, secret)
	if err := os.WriteFile(lockPath, []byte(content), 0600); err != nil {
		log.Error().Err(err).Msg("failed to write sidecar lockfile")
		return
	}

	log.Info().Str("path", lockPath).Int("port", port).Msg("wrote sidecar lockfile")
}

// removeSidecarLockfile cleans up the lockfile on shutdown.
func removeSidecarLockfile() {
	lockPath := filepath.Join(getAppDataDir(), "sidecar.lock")
	_ = os.Remove(lockPath)
}
