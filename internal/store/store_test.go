package store

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/secret"
)

// testMasterKey is a deterministic 32-byte key for HMAC name_lookup in tests.
var testMasterKey = bytes.Repeat([]byte{0xAB}, 32)

// testSecret returns a minimal secret for testing with v7 encrypted fields populated.
func testSecret(name string, encryptedValue []byte) secret.Secret {
	s := secret.NewSecret("", name, secret.KindPassword, encryptedValue, "test notes", "test,fixture")
	s.NameLookup = crypto.ComputeNameLookup(testMasterKey, name)
	s.EncryptedName = []byte("enc-name-" + name)
	s.EncryptedNotes = []byte("enc-notes-" + name)
	s.EncryptedTags = []byte("enc-tags-" + name)
	s.EncryptedMetadata = []byte("enc-meta-" + name)
	return s
}

func TestInit_CreatesSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()

	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Verify schema_version table exists and has the current version
	var version int
	err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Errorf("expected version %d, got %d", CurrentSchemaVersion, version)
	}

	// Verify secrets table exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='secrets'").Scan(&count)
	if err != nil {
		t.Fatalf("check secrets table: %v", err)
	}
	if count != 1 {
		t.Error("secrets table not created")
	}
}

func TestUpdateOTPSeedAndMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Store(secret.Secret{
		Name:              "svc",
		NameLookup:        crypto.ComputeNameLookup(testMasterKey, "svc"),
		Kind:              secret.KindPassword,
		EncryptedValue:    []byte("original-value"),
		EncryptedName:     []byte("enc-name-svc"),
		EncryptedNotes:    []byte("enc-notes-svc"),
		EncryptedTags:     []byte("enc-tags-svc"),
		EncryptedMetadata: []byte(`{"otpauth":"otpauth://totp/x?secret=PLAINTEXT"}`),
	}); err != nil {
		t.Fatalf("store: %v", err)
	}

	newSeed := []byte("encrypted-seed-blob")
	newMeta := `{"otpauth":"otpauth://totp/x?secret=REDACTED"}`
	if err := s.UpdateOTPSeedAndMetadata(crypto.ComputeNameLookup(testMasterKey, "svc"), newSeed, []byte(newMeta)); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, "svc"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.EncryptedOTPSeed) != string(newSeed) {
		t.Errorf("seed: got %q, want %q", got.EncryptedOTPSeed, newSeed)
	}
	if string(got.EncryptedMetadata) != newMeta {
		t.Errorf("EncryptedMetadata: got %q, want %q", string(got.EncryptedMetadata), newMeta)
	}
	// The encrypted value must be preserved by the update.
	if string(got.EncryptedValue) != "original-value" {
		t.Errorf("encrypted value changed: got %q", got.EncryptedValue)
	}

	// Unknown name must report ErrNotFound, not silently succeed.
	if err := s.UpdateOTPSeedAndMetadata(crypto.ComputeNameLookup(testMasterKey, "nope"), newSeed, []byte(newMeta)); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for unknown name, got %v", err)
	}
}

func TestInit_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()

	// Init twice — second call should be a no-op
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("first Init failed: %v", err)
	}
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("second Init failed: %v", err)
	}
	_ = s.Close()
}

func TestStore_And_GetByName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	encryptedBlob := []byte("this-is-ciphertext-from-crypto-layer")
	sec := testSecret("my-test-key", encryptedBlob)

	if err := s.Store(sec); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	got, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, "my-test-key"))
	if err != nil {
		t.Fatalf("GetByName failed: %v", err)
	}

	if !bytes.Equal(got.EncryptedName, []byte("enc-name-my-test-key")) {
		t.Errorf("expected EncryptedName for my-test-key, got %x", got.EncryptedName)
	}
	if string(got.EncryptedValue) != string(encryptedBlob) {
		t.Errorf("encrypted value mismatch: got %x, want %x", got.EncryptedValue, encryptedBlob)
	}
	if got.Kind != secret.KindPassword {
		t.Errorf("expected kind 'password', got %q", got.Kind)
	}
}

func TestStore_DuplicateName_ReturnsErrDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	sec := testSecret("duplicate-key", []byte("ciphertext-a"))
	if err := s.Store(sec); err != nil {
		t.Fatalf("first Store failed: %v", err)
	}

	sec2 := testSecret("duplicate-key", []byte("ciphertext-b"))
	err := s.Store(sec2)
	if err == nil {
		t.Fatal("expected ErrDuplicate, got nil")
	}
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
}

func TestGetByName_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, "nonexistent"))
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetByID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	sec := testSecret("get-by-id-key", []byte("ciphertext-data"))
	if err := s.Store(sec); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Retrieve the ID by getting the secret back
	stored, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, "get-by-id-key"))
	if err != nil {
		t.Fatalf("GetByName failed: %v", err)
	}

	// Now fetch by ID
	got, err := s.GetByID(stored.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}

	if got.ID != stored.ID {
		t.Errorf("ID mismatch: got %q, want %q", got.ID, stored.ID)
	}
	if !bytes.Equal(got.EncryptedName, []byte("enc-name-get-by-id-key")) {
		t.Errorf("EncryptedName mismatch: got %x", got.EncryptedName)
	}
}

func TestGetByID_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, err := s.GetByID("00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestList_ReturnsAll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	secrets := []secret.Secret{
		testSecret("alpha", []byte("cipher-a")),
		testSecret("beta", []byte("cipher-b")),
		testSecret("gamma", []byte("cipher-c")),
	}
	for _, sec := range secrets {
		if err := s.Store(sec); err != nil {
			t.Fatalf("Store %q failed: %v", sec.Name, err)
		}
	}

	got, err := s.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(got))
	}

	// Verify all three are present by EncryptedName
	found := make(map[string]bool)
	for _, sec := range got {
		found[string(sec.EncryptedName)] = true
	}
	if !found["enc-name-alpha"] || !found["enc-name-beta"] || !found["enc-name-gamma"] {
		t.Errorf("missing secrets: %v", names(got))
	}

	// Verify encrypted values are nil (metadata only)
	for _, sec := range got {
		if sec.EncryptedValue != nil {
			t.Errorf("secret %q has non-nil EncryptedValue in list: %x", sec.Name, sec.EncryptedValue)
		}
	}
}

func TestList_EmptyVault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	got, err := s.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty list, got %d secrets", len(got))
	}
}

func TestDelete_Existing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	sec := testSecret("delete-me", []byte("ciphertext"))
	if err := s.Store(sec); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	if err := s.DeleteByLookup(crypto.ComputeNameLookup(testMasterKey, "delete-me")); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it's gone
	_, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, "delete-me"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestDelete_NonExistent_ReturnsErrNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	err := s.DeleteByLookup(crypto.ComputeNameLookup(testMasterKey, "does-not-exist"))
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRoundTrip_CiphertextPreserved(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// This test simulates what a full encrypt→store→get→decrypt round trip looks like.
	// The store layer does NOT do encryption — it just stores and retrieves blobs.
	// The crypto layer produces the ciphertext; the store layer stores it as-is.
	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Simulate what crypto.Encrypt would produce: nonce || ciphertext+tag
	preEncrypted := []byte{
		// 12-byte nonce
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
		// ciphertext + 16-byte GCM tag
		0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}

	sec := testSecret("roundtrip-test", preEncrypted)
	if err := s.Store(sec); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	got, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, "roundtrip-test"))
	if err != nil {
		t.Fatalf("GetByName failed: %v", err)
	}

	// Verify the encrypted blob is byte-for-byte identical
	if len(got.EncryptedValue) != len(preEncrypted) {
		t.Fatalf("encrypted value length mismatch: got %d, want %d", len(got.EncryptedValue), len(preEncrypted))
	}
	for i := range preEncrypted {
		if got.EncryptedValue[i] != preEncrypted[i] {
			t.Fatalf("encrypted value differs at byte %d: got %02x, want %02x", i, got.EncryptedValue[i], preEncrypted[i])
		}
	}
}

func TestSchemaMigration_FromV0(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a database WITHOUT schema_version to simulate v0
	dbPath := filepath.Join(t.TempDir(), "fresh-vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify version is current
	var version int
	err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Errorf("expected version %d, got %d", CurrentSchemaVersion, version)
	}

	// Verify audit_log table exists
	var auditCount int
	err = s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_log'").Scan(&auditCount)
	if err != nil {
		t.Fatalf("check audit_log table: %v", err)
	}
	if auditCount != 1 {
		t.Error("audit_log table not created after migration")
	}

	// Verify secrets table is functional
	sec := testSecret("post-migration", []byte("cipher"))
	if err := s.Store(sec); err != nil {
		t.Fatalf("Store after migration failed: %v", err)
	}
	_ = s.Close()
}

func TestSchemaMigration_FromV1_ToV2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a v1 database manually using raw migration001 SQL,
	// seed data, then open with Init() to verify v1→v2 migration.
	dbPath := filepath.Join(t.TempDir(), "v1-vault.sqlite")

	// Step 1: Create v1 database with raw SQL
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}

	// Execute v1 migration SQL
	if _, err := rawDB.Exec(migration001); err != nil {
		_ = rawDB.Close()
		t.Fatalf("apply migration001: %v", err)
	}

	// Set schema version to 1
	if _, err := rawDB.Exec("INSERT INTO schema_version (version) VALUES (1)"); err != nil {
		_ = rawDB.Close()
		t.Fatalf("set schema version to 1: %v", err)
	}

	// Seed some v1 data
	_, err = rawDB.Exec(`INSERT INTO secrets (id, name, kind, encrypted_value, notes, tags, created_at, updated_at)
		VALUES ('v1-id-1', 'v1-secret', 'password', X'010203', 'legacy note', 'legacy,tag', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')`)
	if err != nil {
		_ = rawDB.Close()
		t.Fatalf("seed data: %v", err)
	}
	_ = rawDB.Close()

	// Step 2: Open with current code — should migrate v1→v2
	s := NewSQLStore()
	err = s.Init(dbPath)
	if !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("expected ErrMigrationRequired for v1 vault, got %v", err)
	}
}

func TestStore_WithMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Store a certificate with metadata
	notAfter := time.Now().AddDate(0, 1, 0).UTC().Format(time.RFC3339)
	metaJSON := fmt.Sprintf(`{"subject_cn":"example.com","not_after":"%s","fingerprint_sha256":"abc123"}`, notAfter)
	sec := secret.Secret{
		Name:              "my-cert",
		NameLookup:        crypto.ComputeNameLookup(testMasterKey, "my-cert"),
		Kind:              secret.KindCertificate,
		EncryptedValue:    []byte("ciphertext"),
		EncryptedName:     []byte("enc-name-my-cert"),
		EncryptedNotes:    []byte("enc-notes-my-cert"),
		EncryptedTags:     []byte("enc-tags-my-cert"),
		EncryptedMetadata: []byte(metaJSON),
	}
	if err := s.Store(sec); err != nil {
		t.Fatalf("Store with metadata failed: %v", err)
	}

	// Retrieve by name
	got, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, "my-cert"))
	if err != nil {
		t.Fatalf("GetByName failed: %v", err)
	}
	if string(got.EncryptedMetadata) != metaJSON {
		t.Errorf("EncryptedMetadata mismatch:\ngot:  %q\nwant: %q", string(got.EncryptedMetadata), metaJSON)
	}

	// Retrieve by ID
	got2, err := s.GetByID(got.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if string(got2.EncryptedMetadata) != metaJSON {
		t.Errorf("GetByID EncryptedMetadata mismatch:\ngot:  %q\nwant: %q", string(got2.EncryptedMetadata), metaJSON)
	}
}

func TestStore_BackwardCompat_EmptyMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Store a secret WITHOUT metadata (v7: empty EncryptedMetadata BLOB)
	sec := secret.Secret{
		Name:              "legacy-password",
		NameLookup:        crypto.ComputeNameLookup(testMasterKey, "legacy-password"),
		Kind:              secret.KindPassword,
		EncryptedValue:    []byte("ciphertext"),
		EncryptedName:     []byte("enc-name-legacy-password"),
		EncryptedNotes:    []byte("enc-notes-legacy-password"),
		EncryptedTags:     []byte("enc-tags-legacy-password"),
		EncryptedMetadata: []byte{},
	}
	if err := s.Store(sec); err != nil {
		t.Fatalf("Store without metadata failed: %v", err)
	}

	// Retrieve and verify EncryptedMetadata is empty
	got, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, "legacy-password"))
	if err != nil {
		t.Fatalf("GetByNameLookup failed: %v", err)
	}
	if len(got.EncryptedMetadata) != 0 {
		t.Errorf("expected empty EncryptedMetadata, got %q", got.EncryptedMetadata)
	}
	if string(got.EncryptedNotes) != "enc-notes-legacy-password" {
		t.Errorf("EncryptedNotes mismatch: got %q", string(got.EncryptedNotes))
	}
}

func TestList_IncludesMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	secrets := []secret.Secret{
		{Name: "cert-a", NameLookup: crypto.ComputeNameLookup(testMasterKey, "cert-a"), Kind: secret.KindCertificate, EncryptedValue: []byte("c1"), EncryptedName: []byte("enc-name-cert-a"), EncryptedNotes: []byte("enc-notes-cert-a"), EncryptedTags: []byte("enc-tags-cert-a"), EncryptedMetadata: []byte(`{"subject_cn":"a.com"}`)},
		{Name: "pass-a", NameLookup: crypto.ComputeNameLookup(testMasterKey, "pass-a"), Kind: secret.KindPassword, EncryptedValue: []byte("c2"), EncryptedName: []byte("enc-name-pass-a"), EncryptedNotes: []byte("enc-notes-pass-a"), EncryptedTags: []byte("enc-tags-pass-a"), EncryptedMetadata: []byte("enc-meta-pass-a")},
		{Name: "cert-b", NameLookup: crypto.ComputeNameLookup(testMasterKey, "cert-b"), Kind: secret.KindCertificate, EncryptedValue: []byte("c3"), EncryptedName: []byte("enc-name-cert-b"), EncryptedNotes: []byte("enc-notes-cert-b"), EncryptedTags: []byte("enc-tags-cert-b"), EncryptedMetadata: []byte(`{"subject_cn":"b.com"}`)},
	}
	for _, sec := range secrets {
		if err := s.Store(sec); err != nil {
			t.Fatalf("Store %q failed: %v", sec.Name, err)
		}
	}

	got, err := s.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(got))
	}

	// Cert with metadata should have it populated
	for _, sec := range got {
		if sec.Name == "cert-a" && sec.Metadata == "" {
			t.Error("cert-a metadata should not be empty in List")
		}
		if sec.Name == "pass-a" && sec.Metadata != "" {
			t.Errorf("pass-a should have empty metadata, got %q", sec.Metadata)
		}
	}
}

func TestConfigSetGet_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Set and get a value
	key := "test-key"
	value := []byte("test-value-data")
	if err := s.ConfigSet(key, value); err != nil {
		t.Fatalf("ConfigSet failed: %v", err)
	}

	got, err := s.ConfigGet(key)
	if err != nil {
		t.Fatalf("ConfigGet failed: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("ConfigGet = %q, want %q", string(got), string(value))
	}
}

func TestConfigSet_OverwritesExistingKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.ConfigSet("same-key", []byte("first")); err != nil {
		t.Fatalf("first ConfigSet: %v", err)
	}
	if err := s.ConfigSet("same-key", []byte("second")); err != nil {
		t.Fatalf("second ConfigSet: %v", err)
	}

	got, err := s.ConfigGet("same-key")
	if err != nil {
		t.Fatalf("ConfigGet: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("got %q, want %q", string(got), "second")
	}
}

func TestConfigGet_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, err := s.ConfigGet("nonexistent-key")
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSchemaMigration_V004_SyncConflicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "v4-vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// A fresh Init runs every migration, so it lands on the current version.
	// Pin to CurrentSchemaVersion so future bumps don't break this test; the
	// sync_conflicts check below is what guards the v004 migration itself.
	var version int
	err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("expected schema version %d, got %d", CurrentSchemaVersion, version)
	}

	// Verify sync_conflicts table exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sync_conflicts'").Scan(&count)
	if err != nil {
		t.Fatalf("check sync_conflicts table: %v", err)
	}
	if count != 1 {
		t.Fatal("sync_conflicts table not created after migration v004")
	}

	// Verify existing tables still work
	sec := testSecret("post-v4-migration", []byte("cipher"))
	if err := s.Store(sec); err != nil {
		t.Fatalf("Store after migration v004 failed: %v", err)
	}

	// Verify sync config keys can be stored and retrieved
	if err := s.ConfigSet("vault_uuid", []byte("test-uuid")); err != nil {
		t.Fatalf("ConfigSet vault_uuid failed: %v", err)
	}
	got, err := s.ConfigGet("vault_uuid")
	if err != nil {
		t.Fatalf("ConfigGet vault_uuid failed: %v", err)
	}
	if string(got) != "test-uuid" {
		t.Errorf("vault_uuid = %q, want %q", string(got), "test-uuid")
	}

	// Verify sync_encryption_key can be stored
	if err := s.ConfigSet("sync_encryption_key", []byte("32-byte-key-here-for-aes-256")); err != nil {
		t.Fatalf("ConfigSet sync_encryption_key failed: %v", err)
	}

	// Verify last_sync_seq can be stored
	if err := s.ConfigSet("last_sync_seq", []byte("42")); err != nil {
		t.Fatalf("ConfigSet last_sync_seq failed: %v", err)
	}
}

// ── Close edge cases ──

func TestClose_DoubleClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// First close should succeed
	if err := s.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}

	// Second close should be a no-op (not panic)
	if err := s.Close(); err != nil {
		t.Errorf("second Close should not error, got: %v", err)
	}
}

func TestGetByName_MalformedTimestamp_ReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Insert a secret with malformed created_at directly via SQL
	_, err := s.db.Exec(`INSERT INTO secrets (id, name_lookup, kind, encrypted_value, encrypted_name, encrypted_notes, encrypted_tags, encrypted_metadata, created_at, updated_at)
		VALUES ('test-id', X'AB', 'password', X'0102', X'', X'', X'', X'', 'not-a-timestamp', '2024-01-01T00:00:00Z')`)
	if err != nil {
		t.Fatalf("insert malformed secret: %v", err)
	}

	_, err = s.GetByNameLookup([]byte{0xAB})
	if err == nil {
		t.Fatal("expected error for malformed timestamp, got nil")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestList_MalformedTimestamp_ReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, err := s.db.Exec(`INSERT INTO secrets (id, name_lookup, kind, encrypted_value, encrypted_name, encrypted_notes, encrypted_tags, encrypted_metadata, created_at, updated_at)
		VALUES ('test-id', X'AB', 'password', X'0102', X'', X'', X'', X'', 'not-a-timestamp', '2024-01-01T00:00:00Z')`)
	if err != nil {
		t.Fatalf("insert malformed secret: %v", err)
	}

	_, err = s.List()
	if err == nil {
		t.Fatal("expected error for malformed timestamp, got nil")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestClose_WithoutInit(t *testing.T) {
	s := NewSQLStore()
	// Close without Init should be a no-op
	if err := s.Close(); err != nil {
		t.Errorf("Close without Init should not error, got: %v", err)
	}
}

func TestStore_WithoutInit_ReturnsError(t *testing.T) {
	s := NewSQLStore()

	// All operations should fail gracefully without Init
	tests := []struct {
		name string
		fn   func() error
	}{
		{"Store", func() error { return s.Store(testSecret("x", []byte("v"))) }},
		{"GetByName", func() error { _, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, "x")); return err }},
		{"GetByID", func() error { _, err := s.GetByID("x"); return err }},
		{"List", func() error { _, err := s.List(); return err }},

		{"Delete", func() error { return s.DeleteByLookup(crypto.ComputeNameLookup(testMasterKey, "x")) }},
		{"ConfigGet", func() error { _, err := s.ConfigGet("x"); return err }},
		{"ConfigSet", func() error { return s.ConfigSet("x", []byte("v")) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatal("expected error for uninitialized store, got nil")
			}
		})
	}
}

// ── Concurrent access tests ──

func TestConcurrentAccess_Safe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	const numGoroutines = 10
	const numSecrets = 20

	// Pre-store some secrets
	for i := 0; i < numSecrets; i++ {
		name := fmt.Sprintf("concurrent-%d", i)
		if err := s.Store(testSecret(name, []byte("data"))); err != nil {
			t.Fatalf("store %q: %v", name, err)
		}
	}

	errChan := make(chan error, numGoroutines*2)
	done := make(chan struct{})

	// Launch concurrent readers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numSecrets; j++ {
				name := fmt.Sprintf("concurrent-%d", j)
				_, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, name))
				if err != nil {
					errChan <- fmt.Errorf("reader %d: GetByNameLookup %q: %w", id, name, err)
					return
				}
				// Also test List concurrently
				_, err = s.List()
				if err != nil {
					errChan <- fmt.Errorf("reader %d: List: %w", id, err)
					return
				}
			}
			done <- struct{}{}
		}(i)
	}

	// Launch concurrent writer
	go func() {
		for j := 0; j < 5; j++ {
			name := fmt.Sprintf("writer-%d", j)
			if err := s.Store(testSecret(name, []byte("writer-data"))); err != nil {
				if errors.Is(err, ErrDuplicate) {
					continue // expected on retry
				}
				errChan <- fmt.Errorf("writer: Store %q: %w", name, err)
				return
			}
			// Delete what we just wrote
			if err := s.DeleteByLookup(crypto.ComputeNameLookup(testMasterKey, name)); err != nil {
				errChan <- fmt.Errorf("writer: DeleteByLookup %q: %w", name, err)
				return
			}
		}
		done <- struct{}{}
	}()

	// Wait for all goroutines
	expectedSignals := numGoroutines + 1
	for i := 0; i < expectedSignals; i++ {
		select {
		case err := <-errChan:
			t.Fatalf("concurrent access error: %v", err)
		case <-done:
		}
	}
}

// ── ListExpiring edge cases ──

func TestAuditLog_LogAndRetrieve(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Log a few actions
	if err := s.LogAction("vault_init", "", ""); err != nil {
		t.Fatalf("LogAction failed: %v", err)
	}
	if err := s.LogAction("secret_add", "my-key", "password"); err != nil {
		t.Fatalf("LogAction failed: %v", err)
	}
	if err := s.LogAction("secret_get", "my-key", ""); err != nil {
		t.Fatalf("LogAction failed: %v", err)
	}

	// Retrieve audit log
	entries, err := s.GetAuditLog(10)
	if err != nil {
		t.Fatalf("GetAuditLog failed: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Most recent first
	if entries[0].Action != "secret_get" {
		t.Errorf("expected first entry action 'secret_get', got %q", entries[0].Action)
	}
	if entries[0].SecretName != "my-key" {
		t.Errorf("expected SecretName 'my-key', got %q", entries[0].SecretName)
	}
	if entries[2].Action != "vault_init" {
		t.Errorf("expected last entry action 'vault_init', got %q", entries[2].Action)
	}

	// Verify timestamps are non-empty
	for _, e := range entries {
		if e.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp for audit entry")
		}
	}
}

func TestAuditLog_Limit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Log 5 actions
	for i := 0; i < 5; i++ {
		if err := s.LogAction("test", fmt.Sprintf("secret-%d", i), ""); err != nil {
			t.Fatalf("LogAction failed: %v", err)
		}
	}

	// Retrieve with limit 2
	entries, err := s.GetAuditLog(2)
	if err != nil {
		t.Fatalf("GetAuditLog failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries with limit 2, got %d", len(entries))
	}
	if entries[0].SecretName != "secret-4" {
		t.Errorf("expected most recent 'secret-4', got %q", entries[0].SecretName)
	}
}

func TestAuditLog_DefaultLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Log some entries
	for i := 0; i < 5; i++ {
		if err := s.LogAction("test", fmt.Sprintf("s-%d", i), ""); err != nil {
			t.Fatalf("LogAction failed: %v", err)
		}
	}

	// Get with limit 0 should use default (50) and return all 5
	entries, err := s.GetAuditLog(0)
	if err != nil {
		t.Fatalf("GetAuditLog failed: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries with default limit, got %d", len(entries))
	}
}

func TestAuditLog_EmptyReturnEmptySlice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	entries, err := s.GetAuditLog(10)
	if err != nil {
		t.Fatalf("GetAuditLog failed: %v", err)
	}
	if entries == nil {
		t.Error("expected empty slice, not nil")
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

// --- H2 Tombstone tests (RED phase) ---

func TestSoftDelete_MarksDeletedAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	_ = s.Store(testSecret("alpha", []byte("cipher-a")))
	_ = s.Store(testSecret("beta", []byte("cipher-b")))

	// SoftDelete sets deleted_at; row must persist
	if err := s.SoftDeleteByLookup(crypto.ComputeNameLookup(testMasterKey, "alpha")); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	// List / Search / GetByName / GetByID exclude soft-deleted rows
	list, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, sec := range list {
		if sec.Name == "alpha" {
			t.Error("List included soft-deleted secret 'alpha'")
		}
	}

	if _, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, "alpha")); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByName for soft-deleted secret: want ErrNotFound, got %v", err)
	}

	// ListWithTombstones must include it
	all, err := s.ListWithTombstones()
	if err != nil {
		t.Fatalf("ListWithTombstones: %v", err)
	}
	found := false
	for _, sec := range all {
		if bytes.Equal(sec.NameLookup, crypto.ComputeNameLookup(testMasterKey, "alpha")) {
			found = true
			if sec.DeletedAt == nil {
				t.Error("tombstone row has nil DeletedAt")
			}
		}
	}
	if !found {
		t.Error("ListWithTombstones did not include soft-deleted 'alpha'")
	}
}

func TestSoftDelete_GetByID_ExcludesTombstone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	_ = s.Store(testSecret("to-delete", []byte("cipher")))
	stored, err := s.GetByNameLookup(crypto.ComputeNameLookup(testMasterKey, "to-delete"))
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	_ = s.SoftDeleteByLookup(crypto.ComputeNameLookup(testMasterKey, "to-delete"))

	if _, err := s.GetByID(stored.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID for soft-deleted secret: want ErrNotFound, got %v", err)
	}
}

func TestSoftDelete_MissingName_ReturnsErrNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.SoftDeleteByLookup(crypto.ComputeNameLookup(testMasterKey, "does-not-exist")); !errors.Is(err, ErrNotFound) {
		t.Errorf("SoftDelete missing name: want ErrNotFound, got %v", err)
	}
}

func TestSoftDelete_AlreadyDeleted_ReturnsErrNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	_ = s.Store(testSecret("already-gone", []byte("cipher")))
	_ = s.SoftDeleteByLookup(crypto.ComputeNameLookup(testMasterKey, "already-gone"))

	if err := s.SoftDeleteByLookup(crypto.ComputeNameLookup(testMasterKey, "already-gone")); !errors.Is(err, ErrNotFound) {
		t.Errorf("double SoftDelete: want ErrNotFound, got %v", err)
	}
}

func TestPurgeTombstones_DeletesOlderThanHorizon(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Store two secrets, soft-delete both
	_ = s.Store(testSecret("old-tomb", []byte("c1")))
	_ = s.Store(testSecret("new-tomb", []byte("c2")))
	_ = s.SoftDeleteByLookup(crypto.ComputeNameLookup(testMasterKey, "old-tomb"))
	_ = s.SoftDeleteByLookup(crypto.ComputeNameLookup(testMasterKey, "new-tomb"))

	// Manually backdate old-tomb's deleted_at to 31 days ago
	oldTime := time.Now().UTC().Add(-31 * 24 * time.Hour).Format(time.RFC3339)
	_, err := s.db.Exec("UPDATE secrets SET deleted_at = ? WHERE name_lookup = ?", oldTime, crypto.ComputeNameLookup(testMasterKey, "old-tomb"))
	if err != nil {
		t.Fatalf("backdate deleted_at: %v", err)
	}

	// Purge with horizon = now-30d
	horizon := time.Now().UTC().Add(-30 * 24 * time.Hour)
	count, err := s.PurgeTombstones(horizon)
	if err != nil {
		t.Fatalf("PurgeTombstones: %v", err)
	}
	if count != 1 {
		t.Errorf("PurgeTombstones count = %d, want 1", count)
	}

	// new-tomb (29-ish days old) must survive
	all, err := s.ListWithTombstones()
	if err != nil {
		t.Fatalf("ListWithTombstones: %v", err)
	}
	foundNew := false
	foundOld := false
	for _, sec := range all {
		if bytes.Equal(sec.NameLookup, crypto.ComputeNameLookup(testMasterKey, "new-tomb")) {
			foundNew = true
		}
		if bytes.Equal(sec.NameLookup, crypto.ComputeNameLookup(testMasterKey, "old-tomb")) {
			foundOld = true
		}
	}
	if !foundNew {
		t.Error("new-tomb should survive purge (< 30d old)")
	}
	if foundOld {
		t.Error("old-tomb should be purged (31d old)")
	}
}

func TestStore_RevivesSoftDeletedTombstone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	sec := testSecret("recreated-item", []byte("cipher1"))
	if err := s.Store(sec); err != nil {
		t.Fatalf("first store: %v", err)
	}

	// Soft delete
	lookup := crypto.ComputeNameLookup(testMasterKey, "recreated-item")
	if err := s.SoftDeleteByLookup(lookup); err != nil {
		t.Fatalf("soft delete: %v", err)
	}

	// Should not be findable as live
	if _, err := s.GetByNameLookup(lookup); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound after soft delete, got %v", err)
	}

	// Re-storing (e.g. via Import or Add) must succeed and revive the row
	sec2 := testSecret("recreated-item", []byte("cipher2"))
	if err := s.Store(sec2); err != nil {
		t.Fatalf("store over tombstone should succeed, got: %v", err)
	}

	// Now it must be retrieved with new ciphertext and no deleted_at
	got, err := s.GetByNameLookup(lookup)
	if err != nil {
		t.Fatalf("get after revival: %v", err)
	}
	if string(got.EncryptedValue) != "cipher2" {
		t.Errorf("got cipher %q, want cipher2", string(got.EncryptedValue))
	}
}

// helpers

func names(secrets []secret.Secret) []string {
	ns := make([]string, len(secrets))
	for i, s := range secrets {
		ns[i] = s.Name
	}
	return ns
}
