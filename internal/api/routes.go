package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/password-manager/password-manager/internal/admin"
	"github.com/password-manager/password-manager/internal/auth"
	"github.com/password-manager/password-manager/internal/db"
	syncsvc "github.com/password-manager/password-manager/internal/sync"
	"github.com/password-manager/password-manager/internal/vault"
)

// Router sets up all API v1 routes.
// storageBackend should be "sqlite" or "postgres".
// sqliteDB is the raw SQLite *sql.DB for migration support (nil when using postgres).
func Router(authService *auth.Service, totpService *auth.TOTPService, smsService *auth.SMSService, vaultService *vault.Service, adminService *admin.Service, syncService *syncsvc.Service, webauthnService *auth.WebAuthnService, userRepo db.UserRepository, storageBackend string, sqliteDB *sql.DB) chi.Router {
	r := chi.NewRouter()

	authHandler := NewAuthHandler(authService)
	tfaHandler := NewTwoFactorHandler(totpService, smsService, authService)
	vaultHandler := NewVaultHandler(vaultService)
	adminHandler := NewAdminHandler(adminService, userRepo)
	if sqliteDB != nil {
		adminHandler.SetSQLiteDB(sqliteDB)
	}
	syncHandler := NewSyncHandler(syncService)
	passkeyHandler := NewPasskeyHandler(webauthnService)

	// Rate limiter for auth endpoints: 5 requests per minute per IP
	authLimiter := NewRateLimiter(5, 1*time.Minute)

	// Public FIDO metadata endpoint (no auth required)
	r.Get("/fido/metadata", passkeyHandler.FIDOMetadata)

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

		// Password change (self-service)
		r.Post("/auth/change-password", authHandler.ChangePassword)

		// Security settings
		r.Post("/auth/require-hardware-key", authHandler.SetRequireHWKey)
		r.Get("/auth/security-settings", authHandler.GetSecuritySettings)

		// 2FA management (requires full auth)
		r.Route("/auth/2fa", func(r chi.Router) {
			r.Post("/setup", tfaHandler.Setup)
			r.Post("/verify-setup", tfaHandler.VerifySetup)
			r.Post("/disable", tfaHandler.Disable)
			r.Post("/share", tfaHandler.Share)
			r.Post("/claim/{id}", tfaHandler.Claim)
			r.Get("/pending", tfaHandler.ListPending)
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

			// Passkey routes
			r.Get("/passkeys", passkeyHandler.ListPasskeys)
			r.Delete("/passkeys/{id}", passkeyHandler.DeletePasskey)
			r.Post("/passkeys/register/begin", passkeyHandler.BeginRegistration)
			r.Post("/passkeys/register/finish", passkeyHandler.FinishRegistration)
			r.Post("/passkeys/authenticate/begin", passkeyHandler.BeginAuthentication)
			r.Post("/passkeys/authenticate/finish", passkeyHandler.FinishAuthentication)
		})

		// Hardware key routes
		r.Route("/auth/hardware-keys", func(r chi.Router) {
			r.Get("/", passkeyHandler.ListHardwareKeys)
			r.Delete("/{id}", passkeyHandler.DeleteHardwareKey)
			r.Post("/register/begin", passkeyHandler.BeginHardwareKeyRegistration)
			r.Post("/register/finish", passkeyHandler.FinishHardwareKeyRegistration)
			r.Post("/authenticate/begin", passkeyHandler.BeginHardwareKeyAuth)
			r.Post("/authenticate/finish", passkeyHandler.FinishHardwareKeyAuth)
		})

		// Admin routes
		r.Route("/admin", func(r chi.Router) {
			// Storage migration endpoints (available on any backend)
			r.Post("/test-pg-connection", adminHandler.TestPgConnection)
			r.Post("/migrate-to-postgres", adminHandler.MigrateToPostgres)

			if storageBackend == "sqlite" {
				r.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
					writeJSON(w, http.StatusNotImplemented, map[string]string{
						"error": "Organization features require PostgreSQL. Go to Settings to upgrade.",
					})
				})
				return
			}
			r.Get("/my-org", adminHandler.GetMyOrg)
			r.Get("/my-invitations", adminHandler.GetMyInvitations)
			r.Post("/orgs", adminHandler.CreateOrg)
			r.Route("/orgs/{id}", func(r chi.Router) {
				r.Post("/leave", adminHandler.LeaveOrg)
				r.Post("/invite", adminHandler.InviteUser)
				r.Post("/accept", adminHandler.AcceptInvite)
				r.Get("/members", adminHandler.ListMembers)
				r.Delete("/members/{uid}", adminHandler.RemoveUser)
				r.Get("/vault/{uid}", adminHandler.AccessUserVault)
				r.Post("/vault/{uid}/reset-password", adminHandler.ResetPassword)
				r.Get("/policy", adminHandler.GetPolicy)
				r.Put("/policy", adminHandler.SetPolicy)
				r.Get("/invitations", adminHandler.ListInvitations)
				r.Get("/audit", adminHandler.GetAuditLog)
				r.Post("/propagate-keys", adminHandler.PropagateKeys)
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

// ExtensionRouter sets up routes for the browser extension native messaging bridge.
// These endpoints are localhost-only and protected by a shared secret.
func ExtensionRouter(vaultRepo db.VaultRepository, secret string, webauthnService *auth.WebAuthnService) chi.Router {
	r := chi.NewRouter()
	h := NewExtensionHandler(vaultRepo, secret, webauthnService)

	r.Post("/session", h.PushSession)
	r.Get("/status", h.GetStatus)
	r.Get("/credentials", h.GetCredentials)
	r.Post("/credentials", h.SaveCredential)
	r.Put("/credentials/{id}", h.UpdateCredential)
	r.Post("/lock", h.Lock)

	// Passkey endpoints for native host
	r.Get("/passkeys", h.ExtListPasskeys)
	r.Post("/passkeys/get", h.ExtGetPasskeys)
	r.Post("/passkeys/create", h.ExtCreatePasskey)
	r.Post("/passkeys/sign", h.ExtSignPasskey)
	r.Delete("/passkeys/{id}", h.ExtDeletePasskey)

	return r
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
