package syncserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// contextKey is used for storing values in request context.
type contextKey string

const (
	// ContextKeyVaultUUID is the context key for the authenticated vault UUID.
	ContextKeyVaultUUID contextKey = "vault_uuid"
)

// AuthMiddleware handles API key authentication and rate limiting.
type AuthMiddleware struct {
	store          *ServerStore
	mu             sync.Mutex
	requests       map[[32]byte]rateBucket // keyed by SHA-256 hash of API key
	registerLimits map[string]rateBucket   // keyed by IP address
	stopCleanup    chan struct{}
}

type rateBucket struct {
	count       int
	windowStart time.Time
}

const (
	// maxRequestsPerMinute is the maximum requests per API key per minute.
	maxRequestsPerMinute = 60
	rateWindow           = time.Minute

	// maxRegisterPerIP is the maximum vault registrations per IP per window.
	maxRegisterPerIP   = 5
	registerRateWindow = time.Hour
)

// NewAuthMiddleware creates a new AuthMiddleware.
func NewAuthMiddleware(store *ServerStore) *AuthMiddleware {
	return &AuthMiddleware{
		store:          store,
		requests:       make(map[[32]byte]rateBucket),
		registerLimits: make(map[string]rateBucket),
		stopCleanup:    make(chan struct{}),
	}
}

// StartCleanup begins a background goroutine that sweeps expired rate-limit
// buckets every 5 minutes.
func (m *AuthMiddleware) StartCleanup() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.sweepExpired()
			case <-m.stopCleanup:
				return
			}
		}
	}()
}

// StopCleanup signals the background sweeper to exit.
func (m *AuthMiddleware) StopCleanup() {
	close(m.stopCleanup)
}

// sweepExpired removes stale entries from both rate-limit maps.
func (m *AuthMiddleware) sweepExpired() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	for k, v := range m.requests {
		if now.Sub(v.windowStart) > rateWindow {
			delete(m.requests, k)
		}
	}
	for k, v := range m.registerLimits {
		if now.Sub(v.windowStart) > registerRateWindow {
			delete(m.registerLimits, k)
		}
	}
}

// rateLimitRegister checks if the given IP has exceeded the registration rate limit.
// Returns true if rate limited, false if allowed.
func (m *AuthMiddleware) rateLimitRegister(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	bucket, exists := m.registerLimits[ip]

	if !exists || now.Sub(bucket.windowStart) > registerRateWindow {
		m.registerLimits[ip] = rateBucket{count: 1, windowStart: now}
		return false
	}

	if bucket.count >= maxRegisterPerIP {
		return true
	}

	bucket.count++
	m.registerLimits[ip] = bucket
	return false
}

// rateLimit checks if the given key hash has exceeded the rate limit.
// Returns true if rate limited, false if allowed.
// Must be called with m.mu held.
func (m *AuthMiddleware) rateLimit(keyHash [32]byte) bool {
	now := time.Now()
	bucket, exists := m.requests[keyHash]

	if !exists || now.Sub(bucket.windowStart) > rateWindow {
		// New window
		m.requests[keyHash] = rateBucket{count: 1, windowStart: now}
		return false
	}

	if bucket.count >= maxRequestsPerMinute {
		return true // rate limited
	}

	bucket.count++
	m.requests[keyHash] = bucket
	return false
}

// Authenticate is HTTP middleware that validates Bearer token authentication
// and enforces per-API-key rate limiting.
// It extracts the token from the Authorization header, SHA-256 hashes it,
// looks up the hash in the api_keys table, and rejects if not found or revoked.
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, errAuthMissingHeader), http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, errAuthInvalidFormat), http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, errAuthEmptyToken), http.StatusUnauthorized)
			return
		}

		// Decode hex-encoded API key to raw bytes, then SHA-256 hash
		rawKey, err := hex.DecodeString(token)
		if err != nil || len(rawKey) == 0 {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, errAuthInvalidKeyFormat), http.StatusForbidden)
			return
		}
		keyHash := sha256.Sum256(rawKey)

		// Rate limiting check
		m.mu.Lock()
		limited := m.rateLimit(keyHash)
		m.mu.Unlock()
		if limited {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(rateWindow.Seconds())))
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, errAuthRateLimit), http.StatusTooManyRequests)
			return
		}

		apiKey, err := m.store.GetAPIKey(keyHash[:])
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, errAuthInvalidAPIKey), http.StatusForbidden)
			return
		}

		if apiKey.Revoked {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, errAuthKeyRevoked), http.StatusForbidden)
			return
		}

		// Store vault UUID in request context for downstream handlers
		ctx := context.WithValue(r.Context(), ContextKeyVaultUUID, apiKey.VaultUUID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
