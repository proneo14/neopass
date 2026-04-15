package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/password-manager/password-manager/internal/auth"
)

// Router sets up all API v1 routes.
func Router(authService *auth.Service) chi.Router {
	r := chi.NewRouter()

	authHandler := NewAuthHandler(authService)

	// Rate limiter for auth endpoints: 5 requests per minute per IP
	authLimiter := NewRateLimiter(5, 1*time.Minute)

	// Public auth routes
	r.Route("/auth", func(r chi.Router) {
		r.Use(authLimiter.RateLimit)
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
		r.Post("/refresh", authHandler.Refresh)
		r.Post("/logout", authHandler.Logout)
	})

	// Protected routes (placeholder groups for future prompts)
	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(authService))

		// Vault routes (Prompt 6)
		r.Route("/vault", func(r chi.Router) {
			r.Get("/", placeholder("vault endpoints coming soon"))
		})

		// Admin routes (Prompt 7)
		r.Route("/admin", func(r chi.Router) {
			r.Get("/", placeholder("admin endpoints coming soon"))
		})

		// Sync routes (Prompt 8)
		r.Route("/sync", func(r chi.Router) {
			r.Get("/", placeholder("sync endpoints coming soon"))
		})
	})

	return r
}

func placeholder(msg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"message": msg})
	}
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
