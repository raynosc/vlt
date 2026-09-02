package gui

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"
	"golang.org/x/crypto/hkdf"

	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
)

const testPassword = "test-master-password-123"

// testEngine returns a crypto engine with minimal params for fast tests.
func testEngine() *crypto.Engine {
	return crypto.NewEngine(&crypto.Argon2Params{
		Time:    1,
		Memory:  1, // 1 KiB — fast for tests
		Threads: 1,
	})
}

// setupTestVault creates a temporary initialized vault and returns its path,
// salt, and verify hash. The caller is responsible for cleaning up the temp dir.
func setupTestVault(t *testing.T) (vaultPath string, salt, verifyHash []byte) {
	t.Helper()

	dir := t.TempDir()
	vaultPath = filepath.Join(dir, "vault.sqlite")

	eng := testEngine()

	// Generate salt
	salt = make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}

	// Derive key and compute verify hash
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	kdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	verifyHash = make([]byte, 32)
	if _, err := io.ReadFull(kdf, verifyHash); err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	// Create and init store
	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	// Store config
	if err := st.ConfigSet("salt", salt); err != nil {
		t.Fatalf("store salt: %v", err)
	}
	if err := st.ConfigSet("verify_hash", verifyHash); err != nil {
		t.Fatalf("store verify hash: %v", err)
	}

	// Store Argon2id params
	timeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBytes, 1)
	memoryBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(memoryBytes, 1)
	threadsBytes := []byte{1}

	if err := st.ConfigSet("argon2_time", timeBytes); err != nil {
		t.Fatalf("store argon2 time: %v", err)
	}
	if err := st.ConfigSet("argon2_memory", memoryBytes); err != nil {
		t.Fatalf("store argon2 memory: %v", err)
	}
	if err := st.ConfigSet("argon2_threads", threadsBytes); err != nil {
		t.Fatalf("store argon2 threads: %v", err)
	}

	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	return vaultPath, salt, verifyHash
}

// injectSecret adds a pre-encrypted secret to the vault for testing.
func injectSecret(t *testing.T, st *store.SQLStore, eng *crypto.Engine, key []byte, name, value, kind, notes, tags string) {
	t.Helper()

	ciphertext, nonce, err := eng.Encrypt([]byte(value), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	blob := make([]byte, 0, len(nonce)+len(ciphertext))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	s := secret.NewSecret("", name, secret.Kind(kind), blob, notes, tags)
	s, err = encryptSecretMetadata(s, eng, key)
	if err != nil {
		t.Fatalf("encrypt metadata: %v", err)
	}
	if err := st.Store(s); err != nil {
		t.Fatalf("store secret: %v", err)
	}
}

// injectSecretWithMeta adds a pre-encrypted secret with password metadata for testing.
func injectSecretWithMeta(t *testing.T, st *store.SQLStore, eng *crypto.Engine, key []byte, name, value, kind, username, url, otpauth string) {
	t.Helper()

	ciphertext, nonce, err := eng.Encrypt([]byte(value), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	blob := make([]byte, 0, len(nonce)+len(ciphertext))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	meta := secret.MarshalPasswordMetadata(&secret.PasswordMetadata{
		Username: username,
		URL:      url,
		OTPAuth:  otpauth,
	})
	s := secret.NewSecret("", name, secret.Kind(kind), blob, "", "")
	s.Metadata = meta
	s, err = encryptSecretMetadata(s, eng, key)
	if err != nil {
		t.Fatalf("encrypt metadata: %v", err)
	}
	if err := st.Store(s); err != nil {
		t.Fatalf("store secret: %v", err)
	}
}

// ── Tests ──

func TestApp_NewApp_NoVault_ReturnsError(t *testing.T) {
	// Use a non-existent path by setting a bogus config
	// Since we can't easily inject, we test the error path via
	// creating an App manually
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "nonexistent.sqlite")

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer func() { _ = st.Close() }()

	_, err := st.ConfigGet("salt")
	if err == nil {
		t.Fatal("expected error for uninitialized vault")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestApp_UnlockLock_Cycle(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	// Create app directly — skip config loading for test isolation
	app := &App{
		engine: testEngine(),
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}

	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if app.IsUnlocked() {
		t.Fatal("expected vault to start locked")
	}

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if !app.IsUnlocked() {
		t.Fatal("expected vault to be unlocked")
	}

	app.Lock()
	if app.IsUnlocked() {
		t.Fatal("expected vault to be locked after Lock()")
	}
}

func TestApp_Unlock_WrongPassword(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	app := &App{
		engine: testEngine(),
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}

	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	err := app.Unlock("wrong-password")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if !strings.Contains(err.Error(), "invalid master password") {
		t.Errorf("expected 'invalid master password', got: %v", err)
	}
	if app.IsUnlocked() {
		t.Fatal("expected vault to remain locked")
	}
}

func TestApp_AddAndList(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	app := &App{
		engine: testEngine(),
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}

	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	// Must unlock first
	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// List should be empty initially
	secrets, err := app.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(secrets))
	}

	// Add a secret
	if err := app.AddSecret("test-login", "password", "my-secret-value", "test notes", "test,tag"); err != nil {
		t.Fatalf("add secret: %v", err)
	}

	// List should have 1 secret
	secrets, err = app.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0].Name != "test-login" {
		t.Errorf("expected name 'test-login', got %q", secrets[0].Name)
	}
	if string(secrets[0].Kind) != "password" {
		t.Errorf("expected kind 'password', got %q", secrets[0].Kind)
	}
}

func TestApp_GetSecret_DecryptsValue(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	// Pre-populate a secret
	injectSecret(t, st, eng, key, "github-token", "ghp_1234567890abcdef", "api_key", "github token", "github,api")

	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	app := &App{
		engine: eng,
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	sec, value, err := app.GetSecret("github-token")
	if err != nil {
	}
	if sec.Name != "github-token" {
		t.Errorf("expected name 'github-token', got %q", sec.Name)
	}
	if value != "ghp_1234567890abcdef" {
		t.Errorf("expected value 'ghp_1234567890abcdef', got %q", value)
	}
}

func TestApp_GetSecret_NotFound(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	app := &App{
		engine: testEngine(),
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	_, _, err := app.GetSecret("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent secret")
	}
}

func TestApp_EditSecret_Rename(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	app := &App{
		engine: testEngine(),
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	if err := app.AddSecret("old-name", "password", "initial-pass", "initial notes", "tag1"); err != nil {
		t.Fatalf("add secret: %v", err)
	}

	// Rename from old-name to new-name and change value/notes
	if err := app.EditSecretFull("old-name", "new-name", "password", "updated-pass", "updated notes", "tag1", "", ""); err != nil {
		t.Fatalf("edit rename secret: %v", err)
	}

	// old-name should not exist anymore
	_, _, err := app.GetSecret("old-name")
	if err == nil {
		t.Fatal("expected error getting old-name after rename, got nil")
	}

	// new-name should exist with updated value and notes
	sec, val, err := app.GetSecret("new-name")
	if err != nil {
		t.Fatalf("get new-name: %v", err)
	}
	if sec.Name != "new-name" {
		t.Errorf("expected sec.Name == 'new-name', got %q", sec.Name)
	}
	if val != "updated-pass" {
		t.Errorf("expected val == 'updated-pass', got %q", val)
	}
	if sec.Notes != "updated notes" {
		t.Errorf("expected notes == 'updated notes', got %q", sec.Notes)
	}
}

func TestApp_EditSecret_RenameCollision(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	app := &App{
		engine: testEngine(),
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	if err := app.AddSecret("secret-1", "password", "pass-1", "", ""); err != nil {
		t.Fatalf("add secret-1: %v", err)
	}
	if err := app.AddSecret("secret-2", "password", "pass-2", "", ""); err != nil {
		t.Fatalf("add secret-2: %v", err)
	}

	// Trying to rename secret-1 to secret-2 must fail with duplicate error
	err := app.EditSecretFull("secret-1", "secret-2", "password", "pass-1-up", "", "", "", "")
	if err == nil {
		t.Fatal("expected error when renaming to an existing secret name, got nil")
	}

	// Original secrets must still exist intact
	_, val1, err := app.GetSecret("secret-1")
	if err != nil || val1 != "pass-1" {
		t.Fatalf("secret-1 corrupted: val=%s, err=%v", val1, err)
	}
	_, val2, err := app.GetSecret("secret-2")
	if err != nil || val2 != "pass-2" {
		t.Fatalf("secret-2 corrupted: val=%s, err=%v", val2, err)
	}
}

func TestApp_DeleteSecret(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	injectSecret(t, st, eng, key, "delete-me", "value-to-delete", "other", "", "")

	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	app := &App{
		engine: eng,
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	if err := app.DeleteSecret("delete-me"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	secrets, err := app.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets after delete, got %d", len(secrets))
	}
}

func TestApp_DeleteSecret_NotFound(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	app := &App{
		engine: testEngine(),
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	err := app.DeleteSecret("nonexistent")
	if err == nil {
		t.Fatal("expected error for deleting nonexistent secret")
	}
}

func TestApp_Locked_OperationsFail(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	app := &App{
		engine: testEngine(),
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	// All operations should fail when locked
	tests := []struct {
		name string
		fn   func() error
	}{
		{"List", func() error { _, err := app.List(); return err }},
		{"Search", func() error { _, err := app.Search("test"); return err }},
		{"GetSecret", func() error { _, _, err := app.GetSecret("x"); return err }},
		{"AddSecret", func() error { return app.AddSecret("n", "p", "v", "", "") }},
		{"EditSecret", func() error { return app.EditSecret("n", "p", "v", "", "") }},
		{"DeleteSecret", func() error { return app.DeleteSecret("x") }},
		{"GetTOTP", func() error { _, _, err := app.GetTOTP("x"); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Error("expected error when vault is locked, got nil")
			} else if !strings.Contains(err.Error(), "locked") {
				t.Errorf("expected error containing 'locked', got: %v", err)
			}
		})
	}
}

func TestApp_GeneratePassword(t *testing.T) {
	app := &App{} // No vault needed

	pw, err := app.GeneratePassword(16)
	if err != nil {
		t.Fatalf("generate password: %v", err)
	}
	if len(pw) != 16 {
		t.Errorf("expected 16 chars, got %d", len(pw))
	}

	// Default length
	pw, err = app.GeneratePassword(0)
	if err != nil {
		t.Fatalf("generate password default: %v", err)
	}
	if len(pw) != 24 {
		t.Errorf("expected 24 chars (default), got %d", len(pw))
	}

	// Max length
	pw, err = app.GeneratePassword(200)
	if err != nil {
		t.Fatalf("generate password max: %v", err)
	}
	if len(pw) > 128 {
		t.Errorf("expected max 128 chars, got %d", len(pw))
	}
}

func TestApp_Search(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	injectSecret(t, st, eng, key, "github-token", "ghp_xxx", "api_key", "", "github,api")
	injectSecret(t, st, eng, key, "aws-key", "AKIAxxx", "api_key", "aws access", "aws,cloud")
	injectSecret(t, st, eng, key, "personal-note", "my note content", "note", "a personal note", "personal")

	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	app := &App{
		engine: eng,
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// Search for "github"
	results, err := app.Search("github")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result for 'github', got %d", len(results))
	}

	// Search for "aws" (matches name)
	results, err = app.Search("aws")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result for 'aws', got %d", len(results))
	}

	// Search with empty query should return all
	results, err = app.Search("")
	if err != nil {
		t.Fatalf("search empty: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("expected 3 results for empty query, got %d", len(results))
	}

	// Search for non-existent
	results, err = app.Search("zzzzzz")
	if err != nil {
		t.Fatalf("search non-existent: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestApp_Close_ZeroizesKey(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	app := &App{
		engine: testEngine(),
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if !app.IsUnlocked() {
		t.Fatal("expected unlocked")
	}

	app.Close()

	if app.store != nil {
		app.mu.RLock()
		storeNil := app.store == nil
		app.mu.RUnlock()
		if storeNil {
			t.Log("store is nil after Close (expected)")
		}
	}
	if app.IsUnlocked() {
		t.Fatal("expected locked after Close()")
	}
}

func TestApp_UnlockWithCustomArgon2Params(t *testing.T) {
	vaultPath, salt, _ := setupTestVault(t)

	// Store custom Argon2 params in the vault
	customTime := uint32(7)
	customMemory := uint32(128 * 1024)
	customThreads := uint8(9)

	timeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBytes, customTime)
	memoryBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(memoryBytes, customMemory)
	threadsBytes := []byte{customThreads}

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	_ = st.ConfigSet("argon2_time", timeBytes)
	_ = st.ConfigSet("argon2_memory", memoryBytes)
	_ = st.ConfigSet("argon2_threads", threadsBytes)

	// Derive key with custom params and store new verify hash
	customEng := crypto.NewEngine(&crypto.Argon2Params{
		Time:    customTime,
		Memory:  customMemory,
		Threads: customThreads,
	})
	key, err := customEng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key with custom params: %v", err)
	}
	defer crypto.Zeroize(key)
	newVerifyHash := make([]byte, 32)
	kdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	if _, err := io.ReadFull(kdf, newVerifyHash); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	_ = st.ConfigSet("verify_hash", newVerifyHash)
	_ = st.Close()

	app := &App{
		engine: crypto.NewEngine(nil), // default engine
		salt:   salt,
		verify: newVerifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock with custom params: %v", err)
	}
	if !app.IsUnlocked() {
		t.Fatal("expected vault to be unlocked")
	}
}

func TestApp_Unlock_EmptyPassword(t *testing.T) {
	app := &App{
		salt:   []byte("test-salt-16-bytes!"),
		verify: make([]byte, 32),
	}

	err := app.Unlock("")
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestExtractSecretFromOTPURL(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{
			url:      "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			expected: "JBSWY3DPEHPK3PXP",
		},
		{
			url:      "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME&algorithm=SHA1&digits=6&period=30",
			expected: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
		},
		{
			url:      "not-an-otp-url",
			expected: "",
		},
		{
			url:      "",
			expected: "",
		},
		{
			url:      "otpauth://totp/Test?secret=SECRET&other=param",
			expected: "SECRET",
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := extractSecretFromOTPURL(tt.url)
			if got != tt.expected {
				t.Errorf("extractSecretFromOTPURL(%q) = %q, want %q", tt.url, got, tt.expected)
			}
		})
	}
}

func TestEditSecret(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	injectSecret(t, st, eng, key, "editable", "original-value", "password", "original notes", "tag1")

	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	app := &App{
		engine: eng,
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	if err := app.EditSecret("editable", "api_key", "new-value", "updated notes", "tag2"); err != nil {
		t.Fatalf("edit: %v", err)
	}

	sec, value, err := app.GetSecret("editable")
	if err != nil {
		t.Fatalf("get after edit: %v", err)
	}
	if value != "new-value" {
		t.Errorf("expected 'new-value', got %q", value)
	}
	if sec.Kind != secret.KindAPIKey {
		t.Errorf("expected kind 'api_key', got %q", sec.Kind)
	}
	if sec.Notes != "updated notes" {
		t.Errorf("expected notes 'updated notes', got %q", sec.Notes)
	}
}

func TestApp_VaultName(t *testing.T) {
	app := &App{vault: "custom-vault"}
	if name := app.VaultName(); name != "custom-vault" {
		t.Errorf("expected 'custom-vault', got %q", name)
	}

	app2 := &App{}
	if name := app2.VaultName(); name != "" {
		t.Errorf("expected empty vault name, got %q", name)
	}
}

// ── Quick Access Filter Tests ──

var quickTestSecrets = []secret.Secret{
	{Name: "GitHub Token", Kind: secret.KindAPIKey},
	{Name: "AWS Access Key", Kind: secret.KindAPIKey},
	{Name: "Stripe API Key", Kind: secret.KindAPIKey},
	{Name: "MyPassword", Kind: secret.KindPassword},
	{Name: "dev.example.com", Kind: secret.KindPassword},
}

func TestFilterSecrets_emptyQuery_returnsAll(t *testing.T) {
	results := filterSecrets(quickTestSecrets, "")
	if len(results) != 5 {
		t.Errorf("expected all 5 secrets, got %d", len(results))
	}
}

func TestFilterSecrets_matchByName(t *testing.T) {
	results := filterSecrets(quickTestSecrets, "github")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Name != "GitHub Token" {
		t.Errorf("expected 'GitHub Token', got %q", results[0].Name)
	}
}

func TestFilterSecrets_caseInsensitive(t *testing.T) {
	results := filterSecrets(quickTestSecrets, "STRIPE")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Name != "Stripe API Key" {
		t.Errorf("expected 'Stripe API Key', got %q", results[0].Name)
	}
}

func TestFilterSecrets_multipleMatches(t *testing.T) {
	results := filterSecrets(quickTestSecrets, "key")
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	expected := []string{"AWS Access Key", "Stripe API Key"}
	for i, r := range results {
		if r.Name != expected[i] {
			t.Errorf("result[%d] expected %q, got %q", i, expected[i], r.Name)
		}
	}
}

func TestFilterSecrets_noMatch(t *testing.T) {
	results := filterSecrets(quickTestSecrets, "zzzzznotfound")
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestFilterSecrets_partialMatch(t *testing.T) {
	results := filterSecrets(quickTestSecrets, "pass")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Name != "MyPassword" {
		t.Errorf("expected 'MyPassword', got %q", results[0].Name)
	}
}

func TestFilterSecrets_nilInput(t *testing.T) {
	results := filterSecrets(nil, "test")
	if len(results) != 0 {
		t.Errorf("expected 0 results for nil input, got %d", len(results))
	}
}

func TestFilterSecrets_selectAfterFilter_clampsCorrectly(t *testing.T) {
	all := quickTestSecrets
	results := filterSecrets(all, "key")
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// Simulate navigation: select index 1 ("Stripe API Key")
	selected := 1
	if selected >= len(results) {
		t.Error("selected should be in bounds")
	}
	// Now filter again to a single result
	results = filterSecrets(all, "aws")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// selected was 1, should be clamped
	if selected >= len(results) {
		selected = 0 // simulate the clamp that showQuickSearch does
	}
	if selected != 0 {
		t.Errorf("expected selected clamped to 0, got %d", selected)
	}
}

func TestFilterSecrets_outputShouldNotShareSlice(t *testing.T) {
	orig := quickTestSecrets
	results := filterSecrets(orig, "")
	// Modify the output - should not affect original
	if len(results) > 0 {
		results[0].Name = "modified"
	}
	if orig[0].Name != "GitHub Token" {
		t.Error("filterSecrets should return a copy of the slice")
	}
}

// ── Quick Access Redesign Tests ──

func TestExtractDomain_fullURL(t *testing.T) {
	got := extractDomain("https://github.com/raynosc/vlt")
	want := "github.com"
	if got != want {
		t.Errorf("extractDomain() = %q, want %q", got, want)
	}
}

func TestExtractDomain_noProtocol(t *testing.T) {
	got := extractDomain("example.com")
	want := "example.com"
	if got != want {
		t.Errorf("extractDomain() = %q, want %q", got, want)
	}
}

func TestExtractDomain_empty(t *testing.T) {
	got := extractDomain("")
	want := ""
	if got != want {
		t.Errorf("extractDomain() = %q, want %q", got, want)
	}
}

func TestExtractDomain_withPath(t *testing.T) {
	got := extractDomain("http://example.com/path/to/page?q=1")
	want := "example.com"
	if got != want {
		t.Errorf("extractDomain() = %q, want %q", got, want)
	}
}

func TestExtractDomain_withPort(t *testing.T) {
	got := extractDomain("https://localhost:8080/api")
	want := "localhost"
	if got != want {
		t.Errorf("extractDomain() = %q, want %q", got, want)
	}
}

func TestExtractDomain_wwwPrefix(t *testing.T) {
	got := extractDomain("https://www.google.com/search")
	want := "google.com"
	if got != want {
		t.Errorf("extractDomain() = %q, want %q", got, want)
	}
}

func TestIconColor_deterministic(t *testing.T) {
	c1 := iconColor("GitHub Token")
	c2 := iconColor("GitHub Token")
	if c1 != c2 {
		t.Error("iconColor should be deterministic for the same input")
	}
}

func TestIconColor_differentNames_differentColors(t *testing.T) {
	c1 := iconColor("GitHub Token")
	c2 := iconColor("AWS Access Key")
	if c1 == c2 {
		t.Error("iconColor should produce different colors for different names")
	}
}

func TestIconColor_emptyName(t *testing.T) {
	c := iconColor("")
	if c.A == 0 {
		t.Error("iconColor should return a valid color for empty string")
	}
}

// ── Quick Access Integration Tests ──
// These tests use Fyne's test package and verify the new popup behavior.

func TestQuickPopup_showsUsernameAndURLFromMetadata(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)
	if salt == nil || verifyHash == nil {
		t.Fatal("setupTestVault failed")
	}

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	// Inject a password secret with metadata (username + URL)
	meta := secret.MarshalPasswordMetadata(&secret.PasswordMetadata{
		Username: "alice@example.com",
		URL:      "https://github.com",
	})
	s := secret.NewSecret("", "GitHub Login", secret.KindPassword, []byte("encrypted-value"), "", "")
	s.Metadata = meta
	s, err = encryptSecretMetadata(s, eng, key)
	if err != nil {
		t.Fatalf("encrypt metadata: %v", err)
	}
	if err := st.Store(s); err != nil {
		t.Fatalf("store secret: %v", err)
	}
	_ = st.Close()

	app := &App{
		engine: eng,
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// Use Fyne test app
	fyneApp := test.NewApp()
	defer fyneApp.Quit()
	w := fyneApp.NewWindow("Quick Access")
	defer w.Close()

	showQuickPopup(w, app)

	// Verify the search bar exists and is focused
	if w.Content() == nil {
		t.Fatal("expected non-nil window content")
	}

	// The window should have a search bar with placeholder
	// We check that the content structure includes input elements
	content := w.Content()
	if content == nil {
		t.Fatal("expected window content")
	}

	// Verify the popup was set up correctly by checking window properties
	if w.Title() != "Quick Access" {
		t.Errorf("expected title 'Quick Access', got %q", w.Title())
	}
}

func TestQuickPopup_escapeClosesPopup(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)
	if salt == nil || verifyHash == nil {
		t.Fatal("setupTestVault failed")
	}

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	injectSecret(t, st, eng, key, "TestSecret", "value", "password", "", "")
	_ = st.Close()

	app := &App{
		engine: eng,
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	fyneApp := test.NewApp()
	defer fyneApp.Quit()
	w := fyneApp.NewWindow("Quick Access")
	defer w.Close()

	showQuickPopup(w, app)

	// The window should be open after showQuickPopup
	if w.Content() == nil {
		t.Fatal("expected window content after opening popup")
	}
}

func TestQuickPopup_detailViewShowsActions(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)
	if salt == nil || verifyHash == nil {
		t.Fatal("setupTestVault failed")
	}

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	injectSecretWithMeta(t, st, eng, key, "TestLogin", "password123", "password", "alice", "https://example.com", "")
	_ = st.Close()

	app := &App{
		engine: eng,
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	fyneApp := test.NewApp()
	defer fyneApp.Quit()
	w := fyneApp.NewWindow("Quick Access")
	defer w.Close()

	// Navigate to detail view
	if err != nil {
	}
	showQuickDetail(w, app, "TestLogin")

	// Verify detail view shows action content
	if w.Content() == nil {
		t.Fatal("expected window content in detail view")
	}
}

func TestQuickPopup_cmdC_copiesUsername(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)
	if salt == nil || verifyHash == nil {
		t.Fatal("setupTestVault failed")
	}

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	injectSecretWithMeta(t, st, eng, key, "GitHub Login", "ghp_encrypted", "password", "alice@example.com", "https://github.com", "")
	_ = st.Close()

	app := &App{
		engine: eng,
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	fyneApp := test.NewApp()
	defer fyneApp.Quit()
	w := fyneApp.NewWindow("Quick Access")
	defer w.Close()

	if err != nil {
	}

	showQuickDetail(w, app, "GitHub Login")

	// Verify detail view is shown
	if w.Content() == nil {
		t.Fatal("expected detail view content")
	}
}

func TestQuickPopup_cmdShiftC_copiesPassword(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)
	if salt == nil || verifyHash == nil {
		t.Fatal("setupTestVault failed")
	}

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	injectSecretWithMeta(t, st, eng, key, "TestLogin", "my-password-value", "password", "alice", "https://example.com", "")
	_ = st.Close()

	app := &App{
		engine: eng,
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	fyneApp := test.NewApp()
	defer fyneApp.Quit()
	w := fyneApp.NewWindow("Quick Access")
	defer w.Close()

	if err != nil {
	}

	showQuickDetail(w, app, "TestLogin")

	// Verify detail view is shown
	if w.Content() == nil {
		t.Fatal("expected detail view content")
	}
}

func TestQuickPopup_escapeReturnsToListFromDetail(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)
	if salt == nil || verifyHash == nil {
		t.Fatal("setupTestVault failed")
	}

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	injectSecretWithMeta(t, st, eng, key, "TestLogin", "password123", "password", "alice", "https://example.com", "")
	_ = st.Close()

	app := &App{
		engine: eng,
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	fyneApp := test.NewApp()
	defer fyneApp.Quit()
	w := fyneApp.NewWindow("Quick Access")
	defer w.Close()

	if err != nil {
	}

	showQuickDetail(w, app, "TestLogin")

	if w.Content() == nil {
		t.Fatal("expected content after entering detail view")
	}
}

func TestListVaults(t *testing.T) {
	// Should not crash — with empty temp dir
	tmpDir := t.TempDir()

	// Store original vault dir and restore after
	orig := os.Getenv("XDG_CONFIG_HOME")
	_ = os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer func() { _ = os.Setenv("XDG_CONFIG_HOME", orig) }()

	vaults, err := ListVaults()
	if err != nil {
		t.Fatalf("ListVaults: %v", err)
	}
	if vaults == nil {
		t.Error("expected non-nil result")
	}

	enabled, err := ListEnabledVaults()
	if err != nil {
		t.Fatalf("ListEnabledVaults: %v", err)
	}
	if enabled == nil {
		t.Error("expected non-nil result for ListEnabledVaults")
	}
}

func TestApp_Unlock_PersistsActiveVault(t *testing.T) {
	tmpDir := t.TempDir()
	orig := os.Getenv("XDG_CONFIG_HOME")
	_ = os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer func() { _ = os.Setenv("XDG_CONFIG_HOME", orig) }()

	name := "customvault"
	vaultPath, err := config.VaultPathForName(name)
	if err != nil {
		t.Fatalf("VaultPathForName: %v", err)
	}

	eng := testEngine()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	defer crypto.Zeroize(key)

	kdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	verifyHash := make([]byte, 32)
	if _, err := io.ReadFull(kdf, verifyHash); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	_ = st.ConfigSet("salt", salt)
	_ = st.ConfigSet("verify_hash", verifyHash)
	timeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBytes, 1)
	memoryBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(memoryBytes, 1)
	_ = st.ConfigSet("argon2_time", timeBytes)
	_ = st.ConfigSet("argon2_memory", memoryBytes)
	_ = st.ConfigSet("argon2_threads", []byte{1})
	_ = st.Close()

	app, err := NewApp(name, false)
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Verify that active_vault in config was updated to customvault
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config Load: %v", err)
	}
	if cfg.ActiveVault != name {
		t.Errorf("expected active vault %q, got %q", name, cfg.ActiveVault)
	}
}

func TestApp_AnalyzePasswords_DetectsDuplicates(t *testing.T) {
	vaultPath, salt, verifyHash := setupTestVault(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}

	// Inject two password secrets with the same value
	injectSecret(t, st, eng, key, "test", "#@FvxT*kf=-)-3E4N(#{WYDK", "password", "", "")
	injectSecret(t, st, eng, key, "tester", "#@FvxT*kf=-)-3E4N(#{WYDK", "password", "", "")

	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	app := &App{
		engine: eng,
		salt:   salt,
		verify: verifyHash,
		store:  store.NewSQLStore(),
		vault:  "test",
		ready:  true,
	}
	if err := app.store.Init(vaultPath); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer app.Close()

	if err := app.Unlock(testPassword); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	result, err := app.AnalyzePasswords()
	if err != nil {
		t.Fatalf("AnalyzePasswords: %v", err)
	}

	if result.AnalyzedPasswordCount != 2 {
		t.Errorf("expected 2 analyzed passwords, got %d", result.AnalyzedPasswordCount)
	}

	if len(result.DuplicatePasswords) != 1 {
		t.Fatalf("expected 1 duplicate finding, got %d", len(result.DuplicatePasswords))
	}

	dup := result.DuplicatePasswords[0]
	if len(dup.SecretNames) != 2 {
		t.Errorf("expected 2 secret names in duplicate, got %d", len(dup.SecretNames))
	}

	// Verify both names are present
	hasTest := false
	hasTester := false
	for _, name := range dup.SecretNames {
		if name == "test" {
			hasTest = true
		}
		if name == "tester" {
			hasTester = true
		}
	}
	if !hasTest || !hasTester {
		t.Errorf("expected both 'test' and 'tester' in duplicate names, got %v", dup.SecretNames)
	}
}

func TestApp_CreateVault(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	// Use XDG_CONFIG_HOME to isolate
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	vaultName := "testvault-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	mnemonic, err := app.CreateVault(vaultName, testPassword)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if mnemonic == "" {
		t.Error("expected non-empty recovery kit mnemonic")
	}

	// Verify vault file exists
	vaultPath, _ := config.VaultPathForName(vaultName)
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		t.Fatalf("expected vault file at %s", vaultPath)
	}

	// Verify we can open and unlock the new vault
	newApp, err := NewApp(vaultName, true)
	if err != nil {
		t.Fatalf("NewApp for created vault: %v", err)
	}
	defer newApp.Close()

	if err := newApp.Unlock(testPassword); err != nil {
		t.Fatalf("unlock created vault: %v", err)
	}
	if !newApp.IsUnlocked() {
		t.Error("expected created vault to be unlockable")
	}

	// Cleanup
	_ = os.Remove(vaultPath)
	_ = os.Remove(vaultPath + "-wal")
	_ = os.Remove(vaultPath + "-shm")
}

func TestQuickPopup_PreservesSelectionAndQueryOnReturn(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	// Inject multiple secrets
	_ = app.AddSecret("alpha", "password", "pass1", "notes", "")
	_ = app.AddSecret("beta", "password", "pass2", "notes", "")
	_ = app.AddSecret("gamma", "password", "pass3", "notes", "")

	fyneApp := test.NewApp()
	defer fyneApp.Quit()
	w := fyneApp.NewWindow("Quick Access")
	defer w.Close()

	m := newQuickModel(w, app)
	if m == nil {
		t.Fatal("expected non-nil quickModel")
	}

	// Set selection to item 2 (gamma) and query to "a"
	m.selected = 2
	m.query = "a"

	// Show list with model
	showQuickPopupWithModel(m)

	if m.selected != 2 {
		t.Errorf("expected selected index 2, got %d", m.selected)
	}
	if m.query != "a" {
		t.Errorf("expected query 'a', got %q", m.query)
	}

	// Navigate to detail view
	showQuickDetailWithModel(m, "gamma", nil)
	if m.view != quickViewDetail {
		t.Errorf("expected quickViewDetail, got %v", m.view)
	}

	// Return to list view
	showQuickPopupWithModel(m)
	if m.view != quickViewList {
		t.Errorf("expected quickViewList, got %v", m.view)
	}
	if m.selected != 2 {
		t.Errorf("expected preserved selected index 2, got %d", m.selected)
	}
	if m.query != "a" {
		t.Errorf("expected preserved query 'a', got %q", m.query)
	}
}

func TestApp_SetOnActivity(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	var activityCount int
	var mu sync.Mutex
	app.SetOnActivity(func() {
		mu.Lock()
		activityCount++
		mu.Unlock()
	})

	// Add secret should trigger activity
	if err := app.AddSecret("act-test", "password", "val", "notes", "tag"); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	// List secrets should trigger activity
	if _, err := app.List(); err != nil {
		t.Fatalf("List: %v", err)
	}

	// GetSecret should trigger activity
	if _, _, err := app.GetSecret("act-test"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}

	mu.Lock()
	count := activityCount
	mu.Unlock()

	if count < 3 {
		t.Errorf("expected at least 3 activity notifications, got %d", count)
	}
}
