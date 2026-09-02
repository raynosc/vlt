package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/keychain"
)

// mockKC implements keychain.Keychain for deterministic testing.
type mockKC struct {
	data map[string][]byte
}

func newMockKC() *mockKC {
	return &mockKC{data: make(map[string][]byte)}
}

func (m *mockKC) Save(key []byte, service, account string) error {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	m.data[service+"|"+account] = keyCopy
	return nil
}

func (m *mockKC) Load(service, account string) ([]byte, error) {
	key, ok := m.data[service+"|"+account]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return keyCopy, nil
}

func (m *mockKC) Delete(service, account string) error {
	delete(m.data, service+"|"+account)
	return nil
}

// saveKeyToMock derives a key from testMasterPassword and stores it in the mock keychain.
func saveKeyToMock(t *testing.T, m *mockKC, vaultPath, password string) {
	t.Helper()
	s, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s.Close() }()

	salt, err := s.ConfigGet(configKeySalt)
	if err != nil {
		t.Fatalf("read salt: %v", err)
	}

	eng := crypto.NewEngine(nil)
	key, err := eng.DeriveKey([]byte(password), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	if err := m.Save(key, "com.passwd.vlt", "master-key"); err != nil {
		t.Fatalf("save to mock keychain: %v", err)
	}
}

// ── TDD: Keychain status shows stored key ──

func TestKeychain_StatusShowsStored(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}
	oldKC := kc
	mock := newMockKC()
	kc = mock
	t.Cleanup(func() { kc = oldKC })

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	// Store a valid key in mock
	saveKeyToMock(t, mock, vaultPath, testMasterPassword)

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, stderr, err := executeCmdWithOutput("keychain", "status", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("keychain status failed: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stderr, "stored") {
		t.Errorf("expected 'stored' in status output, got: %s", stderr)
	}
}

// ── TDD: Keychain forget removes key ──

func TestKeychain_ForgetRemovesKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}
	oldKC := kc
	mock := newMockKC()
	kc = mock
	t.Cleanup(func() { kc = oldKC })

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	// Store a valid key in mock
	saveKeyToMock(t, mock, vaultPath, testMasterPassword)

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Forget the key
	_, stderr, err := executeCmdWithOutput("keychain", "forget", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("keychain forget failed: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stderr, "removed") {
		t.Errorf("expected 'removed' in forget output, got: %s", stderr)
	}

	// Verify key is gone — should need password to unlock
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	err = executeCmd("get", "nonexistent", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error (secret not found), got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error (password unlock worked after forget), got: %v", err)
	}
}

// ── TDD: Keychain status shows nothing when not stored ──

func TestKeychain_StatusNotStored(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}
	oldKC := kc
	kc = newMockKC()
	t.Cleanup(func() { kc = oldKC })

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, stderr, err := executeCmdWithOutput("keychain", "status", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("keychain status failed: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stderr, "not stored") {
		t.Errorf("expected 'not stored' in status output, got: %s", stderr)
	}
}

// ── TDD: Init with env var does not save to keychain ──

func TestInit_NonInteractive_DoesNotSaveToKeychain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}
	oldKC := kc
	mock := newMockKC()
	kc = mock
	t.Cleanup(func() { kc = oldKC })

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	err := executeCmd("init", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Key should NOT be saved to keychain (non-interactive init skips prompt)
	_, err = mock.Load("com.passwd.vlt", "master-key")
	if err != keychain.ErrNotFound {
		t.Errorf("expected key not saved to keychain in non-interactive mode, got %v", err)
	}
}
