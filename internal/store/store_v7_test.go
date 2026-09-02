package store

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/secret"
)

// testSecretV7 returns a secret with encrypted-metadata fields populated for v7 tests.
func testSecretV7(name string, encryptedValue []byte) secret.Secret {
	s := secret.NewSecret("", name, secret.KindPassword, encryptedValue, "notes-"+name, "tag1,tag2")
	s.NameLookup = crypto.ComputeNameLookup(testMasterKey, name)
	s.EncryptedName = []byte("enc-name-" + name)
	s.EncryptedNotes = []byte("enc-notes-" + name)
	s.EncryptedTags = []byte("enc-tags-" + name)
	s.EncryptedMetadata = []byte("enc-meta-" + name)
	return s
}

func TestInit_V7_FreshCreatesV7(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Close()

	var version int
	err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("expected version %d, got %d", CurrentSchemaVersion, version)
	}

	// Verify encrypted columns exist
	cols := []string{"name_lookup", "encrypted_name", "encrypted_notes", "encrypted_tags", "encrypted_metadata"}
	for _, col := range cols {
		var count int
		err := s.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name=?", col).Scan(&count)
		if err != nil {
			t.Fatalf("check %s column: %v", col, err)
		}
		if count != 1 {
			t.Errorf("column %s missing in v7 schema", col)
		}
	}
}

func TestInit_V6_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a v6 database manually
	dbPath := filepath.Join(t.TempDir(), "v6-vault.sqlite")
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}

	// Apply v1 through v6 migrations
	migrations := []string{migration001, migration002, migration003, migration004, migration005, migration006}
	for _, m := range migrations {
		if _, err := rawDB.Exec(m); err != nil {
			_ = rawDB.Close()
			t.Fatalf("apply migration: %v", err)
		}
	}
	if _, err := rawDB.Exec("INSERT INTO schema_version (version) VALUES (6)"); err != nil {
		_ = rawDB.Close()
		t.Fatalf("set schema version to 6: %v", err)
	}
	_ = rawDB.Close()

	s := NewSQLStore()
	err = s.Init(dbPath)
	if !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("expected ErrMigrationRequired for v6 vault, got %v", err)
	}
}

func TestStore_V7_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Close()

	sec := testSecretV7("github", []byte("ciphertext-github"))
	if err := s.Store(sec); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Lookup by HMAC
	got, err := s.GetByNameLookup(sec.NameLookup)
	if err != nil {
		t.Fatalf("GetByNameLookup failed: %v", err)
	}
	if !bytes.Equal(got.EncryptedName, sec.EncryptedName) {
		t.Errorf("EncryptedName mismatch: got %x, want %x", got.EncryptedName, sec.EncryptedName)
	}
	if !bytes.Equal(got.EncryptedNotes, sec.EncryptedNotes) {
		t.Errorf("EncryptedNotes mismatch: got %x, want %x", got.EncryptedNotes, sec.EncryptedNotes)
	}
	if !bytes.Equal(got.EncryptedTags, sec.EncryptedTags) {
		t.Errorf("EncryptedTags mismatch: got %x, want %x", got.EncryptedTags, sec.EncryptedTags)
	}
	if got.ID == "" {
		t.Error("expected ID to be generated")
	}
}

func TestStore_V7_DuplicateNameLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Close()

	sec1 := testSecretV7("dup", []byte("cipher1"))
	sec2 := testSecretV7("dup", []byte("cipher2"))
	if err := s.Store(sec1); err != nil {
		t.Fatalf("first Store failed: %v", err)
	}
	err := s.Store(sec2)
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
}

func TestStore_V7_NoPlaintextInFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Close()

	sec := testSecretV7("github", []byte("ciphertext"))
	if err := s.Store(sec); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Read raw SQLite bytes and grep for plaintext name
	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	if strings.Contains(string(data), "github") {
		t.Error("vault.sqlite contains plaintext secret name 'github'")
	}
	if strings.Contains(string(data), "notes-github") {
		t.Error("vault.sqlite contains plaintext notes")
	}
}

func TestStore_V7_ListReturnsEncryptedMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Close()

	secrets := []secret.Secret{
		testSecretV7("alpha", []byte("cipher-a")),
		testSecretV7("beta", []byte("cipher-b")),
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
	if len(got) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(got))
	}
	for _, sec := range got {
		if sec.EncryptedValue != nil {
			t.Errorf("List should not return EncryptedValue, got %x for %q", sec.EncryptedValue, sec.Name)
		}
		if len(sec.EncryptedName) == 0 {
			t.Errorf("List should return EncryptedName for %q", sec.Name)
		}
	}
}

func TestStore_V7_Count(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Close()

	n, err := s.Count()
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected Count=0, got %d", n)
	}

	_ = s.Store(testSecretV7("one", []byte("c1")))
	_ = s.Store(testSecretV7("two", []byte("c2")))

	n, err = s.Count()
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected Count=2, got %d", n)
	}
}

func TestStore_V7_ListWithEncryptedAll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer s.Close()

	sec := testSecretV7("all", []byte("cipher-all"))
	if err := s.Store(sec); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	got, err := s.ListWithEncryptedAll()
	if err != nil {
		t.Fatalf("ListWithEncryptedAll failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(got))
	}
	if !bytes.Equal(got[0].EncryptedValue, sec.EncryptedValue) {
		t.Error("ListWithEncryptedAll should include EncryptedValue")
	}
}
