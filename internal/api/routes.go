package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/password-manager/password-manager/internal/admin"
	"github.com/password-manager/password-manager/internal/auth"
	syncsvc "github.com/password-manager/password-manager/internal/sync"
	"github.com/password-manager/password-manager/internal/vault"
)

// Router sets up all API v1 routes.
func Router(authService *auth.Service, totpService *auth.TOTPService, smsService *auth.SMSService, vaultService *vault.Service, adminService *admin.Service, syncService *syncsvc.Service) chi.Router {
	r := chi.NewRouter()

	authHandler := NewAuthHandler(authService)
	tfaHandler := NewTwoFactorHandler(totpService, smsService, authService)
	vaultHandler := NewVaultHandler(vaultService)
	adminHandler := NewAdminHandler(adminService)
	syncHandler := NewSyncHandler(syncService)

	// Rate limiter for auth endpoints: 5 requests per minute per IP
	authLimiter := NewRateLimiter(5, 1*time.Minute)

	// Public auth routes
	r.Route("/auth", func(r chi.Router) {
		r.Use(authLimiter.RateLimit)
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
		r.Post("/refresh", authHandler.Refresh)
		r.Post("/logout", authHandler.Logout)

		// 2FA routes that use temp token (no auth middleware)
		r.Post("/2fa/validate", tfaHandler.Validate)
		r.Post("/2fa/sms/send", tfaHandler.SendSMS)
		r.Post("/2fa/sms/validate", tfaHandler.ValidateSMS)
	})

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(authService))

		// 2FA management (requires full auth)
		r.Route("/auth/2fa", func(r chi.Router) {
			r.Post("/setup", tfaHandler.Setup)
			r.Post("/verify-setup", tfaHandler.VerifySetup)
			r.Post("/disable", tfaHandler.Disable)
			r.Post("/share", tfaHandler.Share)
			r.Post("/claim/{id}", tfaHandler.Claim)
		})

		// Vault routes
		r.Route("/vault", func(r chi.Router) {
			r.Post("/entries", vaultHandler.CreateEntry)
			r.Get("/entries", vaultHandler.ListEntries)
			r.Get("/entries/{id}", vaultHandler.GetEntry)
			r.Put("/entries/{id}", vaultHandler.UpdateEntry)
			r.Delete("/entries/{id}", vaultHandler.DeleteEntry)

			r.Post("/folders", vaultHandler.CreateFolder)
			r.Get("/folders", vaultHandler.ListFolders)
			r.Delete("/folders/{id}", vaultHandler.DeleteFolder)
		})

		// Admin routes
		r.Route("/admin", func(r chi.Router) {
			r.Post("/orgs", adminHandler.CreateOrg)
			r.Route("/orgs/{id}", func(r chi.Router) {
				r.Post("/invite", adminHandler.InviteUser)
				r.Post("/accept", adminHandler.AcceptInvite)
				r.Get("/members", adminHandler.ListMembers)
				r.Delete("/members/{uid}", adminHandler.RemoveUser)
				r.Get("/vault/{uid}", adminHandler.AccessUserVault)
				r.Post("/vault/{uid}/reset-password", adminHandler.ResetPassword)
				r.Put("/policy", adminHandler.SetPolicy)
				r.Get("/audit", adminHandler.GetAuditLog)
			})
		})

		// Sync routes
		r.Route("/sync", func(r chi.Router) {
			r.Post("/pull", syncHandler.Pull)
			r.Post("/push", syncHandler.Push)
			r.Post("/resolve", syncHandler.Resolve)
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
