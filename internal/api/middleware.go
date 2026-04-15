package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/auth"
)

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
func AuthMiddleware(authService *auth.Service) func(http.Handler) http.Handler {
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
