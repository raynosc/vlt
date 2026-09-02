package store

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/secret"
)

// TestStore_EncryptedOTPSeed_RoundTrip ensures the encrypted_otp_seed
// column survives a write/read round-trip and stays nil for secrets that
// have no OTP component.
func TestStore_EncryptedOTPSeed_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	withSeed := secret.NewSecret(
		"id-with-seed", "with-otp", secret.KindPassword,
		[]byte{0x01, 0x02, 0x03},
		"notes", "tags",
	)
	withSeed.EncryptedOTPSeed = []byte{0xAA, 0xBB, 0xCC, 0xDD}
	withSeed.NameLookup = crypto.ComputeNameLookup(testMasterKey, "with-otp")
	withSeed.EncryptedName = []byte("enc-with-otp")
	withSeed.EncryptedNotes = []byte("enc-notes")
	withSeed.EncryptedTags = []byte("enc-tags")
	withSeed.EncryptedMetadata = []byte("enc-meta")

	without := secret.NewSecret(
		"id-without", "no-otp", secret.KindPassword,
		[]byte{0xAA},
		"", "",
	)
	without.NameLookup = crypto.ComputeNameLookup(testMasterKey, "no-otp")
	without.EncryptedName = []byte("enc-no-otp")
	without.EncryptedNotes = []byte{}
	without.EncryptedTags = []byte{}
	without.EncryptedMetadata = []byte{}

	if err := s.Store(withSeed); err != nil {
		t.Fatalf("store withSeed: %v", err)
	}
	if err := s.Store(without); err != nil {
		t.Fatalf("store without: %v", err)
	}

	gotSeed, err := s.GetByNameLookup(withSeed.NameLookup)
	if err != nil {
		t.Fatalf("get with-otp: %v", err)
	}
	if !bytes.Equal(gotSeed.EncryptedOTPSeed, withSeed.EncryptedOTPSeed) {
		t.Fatalf("EncryptedOTPSeed roundtrip mismatch: got %x, want %x",
			gotSeed.EncryptedOTPSeed, withSeed.EncryptedOTPSeed)
	}

	gotNone, err := s.GetByNameLookup(without.NameLookup)
	if err != nil {
		t.Fatalf("get no-otp: %v", err)
	}
	if len(gotNone.EncryptedOTPSeed) != 0 {
		t.Fatalf("expected no EncryptedOTPSeed for non-OTP secret, got %x",
			gotNone.EncryptedOTPSeed)
	}
}

// TestStore_SchemaVersion_AfterInit confirms a fresh vault is at the latest
// schema version. If we ship a vault and CurrentSchemaVersion drifts from the
// applied migrations, this guards future audits.
func TestStore_SchemaVersion_AfterInit(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "version-check.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	var v int
	if err := s.db.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&v); err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	if v != CurrentSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", v, CurrentSchemaVersion)
	}
}
