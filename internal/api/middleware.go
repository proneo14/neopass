package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/auth"
	"github.com/password-manager/password-manager/internal/db"
)

// MaxRequestBodySize is the maximum allowed request body (1 MB).
const MaxRequestBodySize = 1 << 20 // 1 MB

type contextKey string

const (
	// UserContextKey is the context key for the authenticated user's claims.
	UserContextKey contextKey = "user_claims"
)

// GetClaims retrieves the authenticated user's claims from the request context.
func GetClaims(ctx context.Context) *auth.Claims {
	claims, _ := ctx.Value(UserContextKey).(*auth.Claims)
	return claims
}

// AuthMiddleware validates JWT tokens on protected routes and injects claims into context.
func AuthMiddleware(authService *auth.Service, userRepo db.UserRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := extractBearerToken(r)
			if tokenStr == "" {
				writeError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}

			claims, err := authService.ValidateToken(tokenStr)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			// Reject partial 2FA tokens on protected routes
			if claims.Is2FA {
				writeError(w, http.StatusForbidden, "2fa verification required")
				return
			}

			// Check if the user's tokens have been revoked (e.g. after emergency takeover)
			if claims.IssuedAt != nil {
				user, err := userRepo.GetUserByID(r.Context(), claims.UserID)
				if err != nil {
					writeError(w, http.StatusUnauthorized, "invalid or expired token")
					return
				}
				if user.TokensRevokedAt != nil && claims.IssuedAt.Before(*user.TokensRevokedAt) {
					writeError(w, http.StatusUnauthorized, "session revoked")
					return
				}
			}

			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractBearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

// RequirePermission returns middleware that checks if the authenticated user has
// the specified permission within the organization identified by the "id" or "orgId"
// URL parameter. It uses the granular role-based permission system.
// If roleRepo is nil, it falls back to checking the legacy role == "admin" for
// any permission starting with "org.".
func RequirePermission(roleRepo db.RoleRepository, orgRepo db.OrgRepository, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			// Determine org ID from URL params
			orgID := chi.URLParam(r, "id")
			if orgID == "" {
				orgID = chi.URLParam(r, "orgId")
			}
			if orgID == "" {
				writeError(w, http.StatusBadRequest, "missing organization ID")
				return
			}

			if roleRepo != nil {
				role, err := roleRepo.GetMemberRole(r.Context(), orgID, claims.UserID)
				if err != nil {
					writeError(w, http.StatusForbidden, "not a member of this organization")
					return
				}

				if !HasPermission(role, permission) {
					writeError(w, http.StatusForbidden, "insufficient permissions: requires "+permission)
					return
				}
			} else {
				// Fallback: legacy role check
				member, err := orgRepo.GetMember(r.Context(), orgID, claims.UserID)
				if err != nil {
					writeError(w, http.StatusForbidden, "not a member of this organization")
					return
				}
				if member.Role != "admin" {
					writeError(w, http.StatusForbidden, "admin role required")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HasPermission checks if a role has a given permission.
// The wildcard "*" permission grants access to everything.
func HasPermission(role db.Role, permission string) bool {
	var perms []string
	if err := json.Unmarshal(role.Permissions, &perms); err != nil {
		return false
	}
	for _, p := range perms {
		if p == "*" || p == permission {
			return true
		}
	}
	return false
}

// CheckPermission is a helper used in handlers to verify permission without middleware.
// Returns the role and nil error if the user has the permission, or an error otherwise.
func CheckPermission(ctx context.Context, roleRepo db.RoleRepository, orgRepo db.OrgRepository, orgID, userID, permission string) (db.Role, error) {
	if roleRepo != nil {
		role, err := roleRepo.GetMemberRole(ctx, orgID, userID)
		if err != nil {
			return db.Role{}, fmt.Errorf("not a member of this organization")
		}
		if !HasPermission(role, permission) {
			return role, fmt.Errorf("insufficient permissions: requires %s", permission)
		}
		return role, nil
	}
	// Fallback: legacy check
	member, err := orgRepo.GetMember(ctx, orgID, userID)
	if err != nil {
		return db.Role{}, fmt.Errorf("not a member of this organization")
	}
	if member.Role != "admin" {
		return db.Role{}, fmt.Errorf("admin role required")
	}
	return db.Role{Name: "Admin"}, nil
}

// RateLimiter provides per-IP rate limiting for sensitive endpoints.
type RateLimiter struct {
	mu       sync.Mutex
	counters map[string]*rateBucket
	limit    int
	window   time.Duration
}

type rateBucket struct {
	count    int
	windowStart time.Time
}

// NewRateLimiter creates a rate limiter allowing `limit` requests per `window` per IP.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		counters: make(map[string]*rateBucket),
		limit:    limit,
		window:   window,
	}

	// Background cleanup of stale entries every minute
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()

	return rl
}

// RateLimit returns middleware that rate-limits requests by IP.
func (rl *RateLimiter) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		// Strip port
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}

		if !rl.allow(ip) {
			log.Warn().Str("ip", ip).Msg("rate limit exceeded")
			writeError(w, http.StatusTooManyRequests, "too many requests")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.counters[ip]

	if !exists || now.Sub(bucket.windowStart) > rl.window {
		rl.counters[ip] = &rateBucket{count: 1, windowStart: now}
		return true
	}

	bucket.count++
	return bucket.count <= rl.limit
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, bucket := range rl.counters {
		if now.Sub(bucket.windowStart) > rl.window {
			delete(rl.counters, ip)
		}
	}
}

// SecurityHeaders adds standard security headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware handles CORS with configurable allowed origins.
// If allowedOrigins is empty or nil, no CORS headers are sent (deny all cross-origin).
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[strings.TrimRight(o, "/")] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && originSet[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.Header().Set("Vary", "Origin")
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CSRFMiddleware implements double-submit cookie CSRF protection.
// Safe methods (GET, HEAD, OPTIONS) are exempt.
// Mutating requests must include an X-CSRF-Token header matching the csrf_token cookie.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure a CSRF cookie exists
		cookie, err := r.Cookie("csrf_token")
		if err != nil || cookie.Value == "" {
			token := generateCSRFToken()
			http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly:false is intentional for CSRF double-submit pattern
				Name:     "csrf_token",
				Value:    token,
				Path:     "/",
				HttpOnly: false, // JS must be able to read it for the double-submit pattern
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   86400,
			})
			cookie = &http.Cookie{Value: token} // #nosec G124 -- local-only reference, not sent to client
		}

		// Safe methods are exempt from CSRF validation
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Skip CSRF for extension bridge routes (localhost-only, protected by shared secret)
		if strings.HasPrefix(r.URL.Path, "/extension/") {
			next.ServeHTTP(w, r)
			return
		}

		// Skip CSRF for non-browser clients (desktop app, CLI).
		// CSRF exploits require a browser Origin; requests without one aren't vulnerable.
		origin := r.Header.Get("Origin")
		referer := r.Header.Get("Referer")
		if origin == "" && referer == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Skip CSRF for API-only clients using Bearer auth (non-browser)
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}

		// Validate double-submit: X-CSRF-Token header must match cookie
		headerToken := r.Header.Get("X-CSRF-Token")
		if subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookie.Value)) != 1 {
			writeError(w, http.StatusForbidden, "invalid CSRF token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// RequestSizeLimit limits the request body to MaxRequestBodySize bytes.
func RequestSizeLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)
		next.ServeHTTP(w, r)
	})
}

// PanicRecovery catches panics in HTTP handlers and returns a generic 500 error.
// Unlike chi's Recoverer, this never leaks stack traces to the client.
func PanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error().Interface("panic", rec).Str("method", r.Method).Str("path", r.URL.Path).Msg("panic recovered")
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
