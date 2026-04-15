package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/api"
	"github.com/password-manager/password-manager/internal/auth"
	"github.com/password-manager/password-manager/internal/config"
	"github.com/password-manager/password-manager/internal/db"
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

	// Database connection
	var database *db.DB
	if cfg.DatabaseURL != "" {
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
	} else {
		log.Warn().Msg("DATABASE_URL not set — running without database")
	}

	// Build router
	r := chi.NewRouter()

	// Middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(jsonContentType)

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Initialize auth service
	var authService *auth.Service
	if database != nil {
		userRepo := db.NewUserRepo(database.Pool)
		var authErr error
		authService, authErr = auth.NewService(userRepo, nil, nil, auth.ServiceConfig{})
		if authErr != nil {
			log.Fatal().Err(authErr).Msg("failed to create auth service")
		}
	}

	// API v1 route group
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"version":"1.0.0"}`))
		})

		if authService != nil {
			r.Mount("/", api.Router(authService))
		}
	})

	// Create server
	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
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
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server failed")
		}
	}()

	<-ctx.Done()
	log.Info().Msg("shutting down server")

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
