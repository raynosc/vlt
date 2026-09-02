package sync_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/raynosc/vlt/internal/store"
	syncpkg "github.com/raynosc/vlt/internal/sync"
)

func TestWrapUnwrapConfigValue_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	original := []byte("super-secret-api-key-XXXX")
	wrapped, err := syncpkg.WrapConfigValue("api_key", original, key)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	if !syncpkg.IsWrappedConfigValue(wrapped) {
		t.Fatalf("wrapped value missing magic prefix")
	}

	// Sanity: the original plaintext must not appear inside the wrapped blob.
	if bytes.Contains(wrapped, original) {
		t.Fatalf("plaintext leaked into the wrapped blob")
	}

	got, wasWrapped, err := syncpkg.UnwrapConfigValue("api_key", wrapped, key, 1)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !wasWrapped {
		t.Fatalf("expected wasWrapped=true")
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("unwrap mismatch: got %q, want %q", got, original)
	}
}

func TestUnwrapConfigValue_LegacyPlaintextPassThrough(t *testing.T) {
	key := make([]byte, 32)
	plain := []byte("legacy-plaintext-config-value")

	got, wasWrapped, err := syncpkg.UnwrapConfigValue("api_key", plain, key, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wasWrapped {
		t.Fatalf("legacy value should not be reported as wrapped")
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("legacy pass-through mismatch")
	}
}

func TestUnwrapConfigValue_WrongKey(t *testing.T) {
	good := make([]byte, 32)
	bad := make([]byte, 32)
	if _, err := rand.Read(good); err != nil {
		t.Fatalf("rand: %v", err)
	}
	bad[0] = 1 // distinct from good

	wrapped, err := syncpkg.WrapConfigValue("api_key", []byte("payload"), good)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if _, _, err := syncpkg.UnwrapConfigValue("api_key", wrapped, bad, 1); err == nil {
		t.Fatal("expected unwrap failure with wrong key, got nil")
	}
}

func TestUnwrapConfigValue_WrongAAD_TriggersFallbackAndMigration(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	original := []byte("secret-payload-with-legacy-nil-aad")

	// Manually construct a legacy wrap (passing "" as keyName to mimic legacy nil AAD)
	legacyWrapped, err := syncpkg.WrapConfigValue("", original, key)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	// Unwrap with a specific key name should succeed using the fallback,
	// but should return wasWrapped = false to trigger automatic re-wrapping/migration!
	got, wasWrapped, err := syncpkg.UnwrapConfigValue("api_key", legacyWrapped, key, 1)
	if err != nil {
		t.Fatalf("unwrap fallback: %v", err)
	}
	if wasWrapped {
		t.Fatalf("expected wasWrapped=false for fallback to trigger migration")
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("got %q, want %q", got, original)
	}
}

// --- F3 config_format_version gate tests (RED phase) ---

// TestUnwrapConfigValue_Version2_RejectsNilAADFallback verifies that when
// configVersion=2, a legacy nil-AAD blob returns an error instead of
// falling back to nil-AAD decryption (ADR-9 strict mode).
func TestUnwrapConfigValue_Version2_RejectsNilAADFallback(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	original := []byte("secret-payload-with-legacy-nil-aad")

	// Produce a legacy nil-AAD blob (wrap with empty keyName mimics nil AAD).
	legacyWrapped, err := syncpkg.WrapConfigValue("", original, key)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	// configVersion=2: nil-AAD fallback must be DISABLED — expect error.
	_, _, err = syncpkg.UnwrapConfigValue("api_key", legacyWrapped, key, syncpkg.ConfigFormatVersionAAD)
	if err == nil {
		t.Fatal("expected error for nil-AAD blob with configVersion=2, got nil")
	}
}

// TestUnwrapConfigValue_Version1_AllowsNilAADFallback verifies that the existing
// legacy-fallback behaviour is preserved when configVersion=1.
func TestUnwrapConfigValue_Version1_AllowsNilAADFallback(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	original := []byte("secret-payload-with-legacy-nil-aad")

	// Legacy nil-AAD blob.
	legacyWrapped, err := syncpkg.WrapConfigValue("", original, key)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	// configVersion=1: fallback must succeed; wrapped=false to trigger migration.
	got, wasWrapped, err := syncpkg.UnwrapConfigValue("api_key", legacyWrapped, key, syncpkg.ConfigFormatVersionLegacy)
	if err != nil {
		t.Fatalf("unexpected error with configVersion=1: %v", err)
	}
	if wasWrapped {
		t.Fatal("expected wasWrapped=false for nil-AAD fallback path")
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, original)
	}
}

// TestNewClient_LegacyVaultIsMigratedLazily simulates a pre-S-01 vault that
// still has api_key and sync_encryption_key in plaintext. After the first
// successful NewClient(...) the on-disk values must be wrapped.
func TestNewClient_LegacyVaultIsMigratedLazily(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-vault.sqlite")
	s := store.NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand: %v", err)
	}

	rawAPI := make([]byte, 32)
	if _, err := rand.Read(rawAPI); err != nil {
		t.Fatalf("rand: %v", err)
	}
	rawSync := make([]byte, 32)
	if _, err := rand.Read(rawSync); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// Seed legacy (plaintext) values.
	if err := s.ConfigSet("sync_server_url", []byte("https://example.com")); err != nil {
		t.Fatalf("set url: %v", err)
	}
	if err := s.ConfigSet("vault_uuid", []byte("legacy-vault-uuid")); err != nil {
		t.Fatalf("set uuid: %v", err)
	}
	if err := s.ConfigSet("api_key", []byte(hex.EncodeToString(rawAPI))); err != nil {
		t.Fatalf("set api_key: %v", err)
	}
	if err := s.ConfigSet("sync_encryption_key", rawSync); err != nil {
		t.Fatalf("set sync_encryption_key: %v", err)
	}
	if err := s.ConfigSet("last_sync_seq", []byte("0")); err != nil {
		t.Fatalf("set seq: %v", err)
	}

	if _, err := syncpkg.NewClient(s, masterKey); err != nil {
		t.Fatalf("NewClient on legacy vault: %v", err)
	}

	// Both values should now be wrapped on disk.
	got, err := s.ConfigGet("api_key")
	if err != nil {
		t.Fatalf("re-read api_key: %v", err)
	}
	if !syncpkg.IsWrappedConfigValue(got) {
		t.Fatalf("api_key was not migrated to wrapped form")
	}

	got, err = s.ConfigGet("sync_encryption_key")
	if err != nil {
		t.Fatalf("re-read sync_encryption_key: %v", err)
	}
	if !syncpkg.IsWrappedConfigValue(got) {
		t.Fatalf("sync_encryption_key was not migrated to wrapped form")
	}
}
