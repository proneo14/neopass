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
func Router(authService *auth.Service, totpService *auth.TOTPService, smsService *auth.SMSService, vaultService *vault.Service, adminService *admin.Service, syncService *syncsvc.Service, webauthnService *auth.WebAuthnService, userRepo db.UserRepository, vaultRepo db.VaultRepository, sendRepo db.SendRepository, collectionRepo db.CollectionRepository, orgRepo db.OrgRepository, auditRepo db.AuditRepository, eaRepo db.EmergencyAccessRepository, syncRepo db.SyncRepository, storageBackend string, sqliteDB *sql.DB) chi.Router {
	r := chi.NewRouter()

	authHandler := NewAuthHandler(authService)
	tfaHandler := NewTwoFactorHandler(totpService, smsService, authService)
	vaultHandler := NewVaultHandler(vaultService)
	adminHandler := NewAdminHandler(adminService, userRepo)
	adminHandler.SetOrgAndAuditRepo(orgRepo, auditRepo)
	if sqliteDB != nil {
		adminHandler.SetSQLiteDB(sqliteDB)
	}
	syncHandler := NewSyncHandler(syncService, syncRepo)
	passkeyHandler := NewPasskeyHandler(webauthnService)
	sendHandler := NewSendHandler(sendRepo, userRepo)
	collectionHandler := NewCollectionHandler(collectionRepo, orgRepo, userRepo, auditRepo)
	emergencyHandler := NewEmergencyAccessHandler(eaRepo, userRepo, vaultRepo, auditRepo, orgRepo, collectionRepo)

	// SSO & SCIM handlers (PostgreSQL-only)
	var ssoHandler *SSOHandler
	var scimHandler *SCIMHandler
	if storageBackend != "sqlite" {
		ssoService := auth.NewSSOService(orgRepo, userRepo, authService, auditRepo)
		ssoHandler = NewSSOHandler(ssoService, authService, orgRepo, auditRepo)
		scimHandler = NewSCIMHandler(userRepo, orgRepo, auditRepo)
	}

	// Rate limiter for public auth endpoints: 10 requests per minute per IP
	authLimiter := NewRateLimiter(10, 1*time.Minute)

	// Public FIDO metadata endpoint (no auth required)
	r.Get("/fido/metadata", passkeyHandler.FIDOMetadata)

	// Public auth routes (rate-limited)
	r.Route("/auth", func(r chi.Router) {
		r.With(authLimiter.RateLimit).Post("/register", authHandler.Register)
		r.With(authLimiter.RateLimit).Post("/login", authHandler.Login)
		r.With(authLimiter.RateLimit).Post("/refresh", authHandler.Refresh)
		r.Post("/logout", authHandler.Logout)

		// 2FA routes that use temp token (no auth middleware)
		r.With(authLimiter.RateLimit).Post("/2fa/validate", tfaHandler.Validate)
		r.With(authLimiter.RateLimit).Post("/2fa/sms/send", tfaHandler.SendSMS)
		r.With(authLimiter.RateLimit).Post("/2fa/sms/validate", tfaHandler.ValidateSMS)
	})

	// Public SSO routes (rate-limited, no auth required — PostgreSQL only)
	if ssoHandler != nil {
		ssoLimiter := NewRateLimiter(10, 1*time.Minute)
		r.Route("/sso/{orgId}", func(r chi.Router) {
			r.With(ssoLimiter.RateLimit).Get("/login", ssoHandler.Login)
			r.With(ssoLimiter.RateLimit).Post("/callback", ssoHandler.Callback)
			r.With(ssoLimiter.RateLimit).Post("/unlock", ssoHandler.Unlock)
		})
	}

	// SCIM 2.0 routes (bearer token auth, PostgreSQL only)
	if scimHandler != nil {
		r.Route("/scim/v2/{orgId}", func(r chi.Router) {
			r.Use(scimHandler.SCIMAuthMiddleware)
			r.Get("/Users", scimHandler.ListUsers)
			r.Post("/Users", scimHandler.CreateUser)
			r.Get("/Users/{id}", scimHandler.GetUser)
			r.Put("/Users/{id}", scimHandler.UpdateUser)
			r.Patch("/Users/{id}", scimHandler.PatchUser)
			r.Delete("/Users/{id}", scimHandler.DeleteUser)
		})
	}

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(authService, userRepo))

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
			r.Put("/entries/{id}/favorite", vaultHandler.SetFavorite)
			r.Put("/entries/{id}/archive", vaultHandler.SetArchived)
			r.Post("/entries/{id}/restore", vaultHandler.RestoreEntry)
			r.Delete("/entries/{id}/permanent", vaultHandler.PermanentDeleteEntry)
			r.Post("/entries/{id}/clone", vaultHandler.CloneEntry)
			r.Post("/trash/purge", vaultHandler.PurgeTrash)

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

				// SSO configuration (admin only)
				if ssoHandler != nil {
					r.Get("/sso", ssoHandler.GetSSOConfig)
					r.Put("/sso", ssoHandler.SetSSOConfig)
				}

				// SCIM configuration (admin only)
				r.Post("/scim/generate-token", adminHandler.GenerateSCIMToken)
				r.Get("/scim", adminHandler.GetSCIMConfig)
				r.Put("/scim", adminHandler.SetSCIMConfig)
			})

			// Org-scoped collection routes
			r.Route("/orgs/{orgId}/collections", func(r chi.Router) {
				r.Post("/", collectionHandler.CreateCollection)
				r.Get("/", collectionHandler.ListOrgCollections)
			})
		})

		// Collection routes (not org-scoped)
		r.Get("/collections", collectionHandler.ListUserCollections)
		r.Route("/collections/{id}", func(r chi.Router) {
			r.Get("/", collectionHandler.GetCollection)
			r.Put("/", collectionHandler.UpdateCollection)
			r.Delete("/", collectionHandler.DeleteCollection)
			r.Post("/members", collectionHandler.AddMember)
			r.Get("/members", collectionHandler.GetCollectionMembers)
			r.Delete("/members/{uid}", collectionHandler.RemoveMember)
			r.Put("/members/{uid}/permission", collectionHandler.UpdateMemberPermission)
			r.Post("/entries", collectionHandler.AddEntry)
			r.Get("/entries", collectionHandler.ListEntries)
			r.Delete("/entries/{entryId}", collectionHandler.RemoveEntry)
		})

		// Entry's collections
		r.Get("/vault/entries/{id}/collections", collectionHandler.GetEntryCollections)

		// Sync routes
		r.Route("/sync", func(r chi.Router) {
			r.Post("/pull", syncHandler.Pull)
			r.Post("/push", syncHandler.Push)
			r.Post("/resolve", syncHandler.Resolve)
			r.Get("/devices", syncHandler.ListDevices)
			r.Delete("/devices/{deviceId}", syncHandler.DeleteDevice)
		})

		// Secure Send routes (authenticated)
		r.Route("/sends", func(r chi.Router) {
			r.Post("/", sendHandler.CreateSend)
			r.Get("/", sendHandler.ListSends)
			r.Delete("/{id}", sendHandler.DeleteSend)
			r.Put("/{id}/disable", sendHandler.DisableSend)
		})

		// Emergency Access routes
		r.Route("/emergency-access", func(r chi.Router) {
			r.Post("/invite", emergencyHandler.Invite)
			r.Get("/granted", emergencyHandler.ListGranted)
			r.Get("/trusted", emergencyHandler.ListTrusted)
			r.Post("/{id}/accept", emergencyHandler.Accept)
			r.Get("/{id}/public-key", emergencyHandler.GetGranteePublicKey)
			r.Post("/{id}/confirm", emergencyHandler.Confirm)
			r.Post("/{id}/initiate", emergencyHandler.Initiate)
			r.Post("/{id}/approve", emergencyHandler.Approve)
			r.Post("/{id}/reject", emergencyHandler.Reject)
			r.Get("/{id}/vault", emergencyHandler.GetVault)
			r.Post("/{id}/takeover", emergencyHandler.Takeover)
			r.Delete("/{id}", emergencyHandler.Delete)
		})
	})

	// Public send access routes (no authentication required)
	sendAccessLimiter := NewRateLimiter(10, 1*time.Minute)
	r.Route("/send/{slug}", func(r chi.Router) {
		r.Use(sendAccessLimiter.RateLimit)
		r.Get("/", sendHandler.AccessSend)
		r.Post("/access", sendHandler.AccessSendWithPassword)
	})

	return r
}

// ExtensionRouter sets up routes for the browser extension native messaging bridge.
// These endpoints are localhost-only and protected by a shared secret.
func ExtensionRouter(vaultRepo db.VaultRepository, userRepo db.UserRepository, secret string, webauthnService *auth.WebAuthnService) chi.Router {
	r := chi.NewRouter()
	h := NewExtensionHandler(vaultRepo, userRepo, secret, webauthnService)

	r.Post("/session", h.PushSession)
	r.Get("/status", h.GetStatus)
	r.Get("/credentials", h.GetCredentials)
	r.Post("/credentials", h.SaveCredential)
	r.Put("/credentials/{id}", h.UpdateCredential)
	r.Post("/verify-password", h.VerifyPassword)
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
