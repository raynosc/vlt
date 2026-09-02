package syncserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

// testHandler is a simple handler that returns 200 for authenticated requests.
var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestAuthMiddleware_MissingHeader(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	mw := NewAuthMiddleware(s)
	handler := mw.Authenticate(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing auth, got %d", rec.Code)
	}
}

func TestAuthMiddleware_InvalidKey(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	mw := NewAuthMiddleware(s)
	handler := mw.Authenticate(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-key-that-does-not-exist")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for invalid key, got %d", rec.Code)
	}
}

func TestAuthMiddleware_ValidKey(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Create a vault and API key
	vaultUUID := "auth-test-vault"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatalf("generate raw key: %v", err)
	}
	keyHash := sha256.Sum256(rawKey)

	if err := s.AddAPIKey(vaultUUID, keyHash[:], "test-key"); err != nil {
		t.Fatalf("AddAPIKey failed: %v", err)
	}

	mw := NewAuthMiddleware(s)
	handler := mw.Authenticate(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+hex.EncodeToString(rawKey))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid key, got %d", rec.Code)
	}
}

func TestAuthMiddleware_MalformedBearer(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	mw := NewAuthMiddleware(s)
	handler := mw.Authenticate(testHandler)

	tests := []struct {
		name  string
		value string
	}{
		{"empty bearer", "Bearer "},
		{"no bearer prefix", "SomeToken"},
		{"empty header", ""},
		{"bearer lowercase", "bearer token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.value != "" {
				req.Header.Set("Authorization", tt.value)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
				t.Errorf("expected 401 or 403 for %q, got %d", tt.name, rec.Code)
			}
		})
	}
}

func TestAuthMiddleware_RevokedKey(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	vaultUUID := "revoked-key-vault"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatalf("generate raw key: %v", err)
	}
	keyHash := sha256.Sum256(rawKey)

	if err := s.AddAPIKey(vaultUUID, keyHash[:], "revocable-key"); err != nil {
		t.Fatalf("AddAPIKey failed: %v", err)
	}

	// Revoke the key
	if err := s.RevokeAPIKey(vaultUUID, keyHash[:]); err != nil {
		t.Fatalf("RevokeAPIKey failed: %v", err)
	}

	mw := NewAuthMiddleware(s)
	handler := mw.Authenticate(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+hex.EncodeToString(rawKey))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for revoked key, got %d", rec.Code)
	}
}
