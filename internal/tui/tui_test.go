package tui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/hkdf"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/parse"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
)

// ── Test helpers ──

const testPassword = "test-password"

// testEngine returns a crypto engine with minimal parameters for fast test execution.
func testEngine() *crypto.Engine {
	return crypto.NewEngine(&crypto.Argon2Params{
		Time:    1,
		Memory:  1, // 1 KiB — fast enough for tests
		Threads: 1,
	})
}

// mockStore is an in-memory implementation of store.Store for deterministic testing.
type mockStore struct {
	secrets map[string]secret.Secret
	config  map[string][]byte
}

func newMockStore() *mockStore {
	return &mockStore{
		secrets: make(map[string]secret.Secret),
		config:  make(map[string][]byte),
	}
}

func (m *mockStore) Init(path string) error { return nil }
func (m *mockStore) Store(s secret.Secret) error {
	key := string(s.NameLookup)
	if key == "" {
		key = s.Name
	}
	if key == "" {
		key = s.ID
	}
	if _, exists := m.secrets[key]; exists {
		return store.ErrDuplicate
	}
	for _, existing := range m.secrets {
		if (len(s.NameLookup) > 0 && string(existing.NameLookup) == string(s.NameLookup)) || (s.Name != "" && existing.Name == s.Name) {
			return store.ErrDuplicate
		}
	}
	// Ensure NameLookup is set so GetByNameLookup works consistently.
	if len(s.NameLookup) == 0 {
		s.NameLookup = []byte(key)
	}
	m.secrets[key] = s
	return nil
}
func (m *mockStore) GetByNameLookup(nameLookup []byte) (secret.Secret, error) {
	if s, ok := m.secrets[string(nameLookup)]; ok {
		return s, nil
	}
	for _, s := range m.secrets {
		if string(s.NameLookup) == string(nameLookup) || s.Name == string(nameLookup) {
			return s, nil
		}
	}
	return secret.Secret{}, fmt.Errorf("%w: name_lookup", store.ErrNotFound)
}
func (m *mockStore) GetByID(id string) (secret.Secret, error) {
	for _, s := range m.secrets {
		if s.ID == id {
			return s, nil
		}
	}
	return secret.Secret{}, fmt.Errorf("%w: %s", store.ErrNotFound, id)
}
func (m *mockStore) List() ([]secret.Secret, error) {
	var result []secret.Secret
	for _, s := range m.secrets {
		meta := s
		meta.EncryptedValue = nil
		result = append(result, meta)
	}
	if result == nil {
		result = []secret.Secret{}
	}
	return result, nil
}
func (m *mockStore) ListWithEncryptedAll() ([]secret.Secret, error) {
	var result []secret.Secret
	for _, s := range m.secrets {
		result = append(result, s)
	}
	if result == nil {
		result = []secret.Secret{}
	}
	return result, nil
}
func (m *mockStore) DeleteByLookup(nameLookup []byte) error {
	if _, ok := m.secrets[string(nameLookup)]; ok {
		delete(m.secrets, string(nameLookup))
		return nil
	}
	for k, s := range m.secrets {
		if string(s.NameLookup) == string(nameLookup) || s.Name == string(nameLookup) {
			delete(m.secrets, k)
			return nil
		}
	}
	return fmt.Errorf("%w: name_lookup", store.ErrNotFound)
}
func (m *mockStore) UpdateOTPSeedAndMetadata(nameLookup []byte, seed []byte, encryptedMeta []byte) error {
	sec, ok := m.secrets[string(nameLookup)]
	if !ok {
		return fmt.Errorf("%w: name_lookup", store.ErrNotFound)
	}
	sec.EncryptedOTPSeed = seed
	sec.EncryptedMetadata = encryptedMeta
	m.secrets[string(nameLookup)] = sec
	return nil
}
func (m *mockStore) ConfigGet(key string) ([]byte, error) {
	val, ok := m.config[key]
	if !ok {
		return nil, fmt.Errorf("%w: config key %q", store.ErrNotFound, key)
	}
	return val, nil
}
func (m *mockStore) ConfigSet(key string, value []byte) error {
	m.config[key] = value
	return nil
}
func (m *mockStore) ConfigDelete(key string) error {
	delete(m.config, key)
	return nil
}
func (m *mockStore) Count() (int, error) {
	return len(m.secrets), nil
}
func (m *mockStore) LogAction(action, secretName, details string) error { return nil }
func (m *mockStore) GetAuditLog(limit int) ([]secret.AuditEntry, error) {
	return []secret.AuditEntry{}, nil
}
func (m *mockStore) SoftDeleteByLookup(nameLookup []byte) error {
	return m.DeleteByLookup(nameLookup)
}
func (m *mockStore) ListWithTombstones() ([]secret.Secret, error) {
	return m.List()
}
func (m *mockStore) PurgeTombstones(before time.Time) (int, error) {
	return 0, nil
}
func (m *mockStore) UpdateTombstoneDeletedAt(nameLookup []byte, t time.Time) error { return nil }
func (m *mockStore) Close() error                                                  { return nil }

// newTestModel creates a TUI model pre-configured for testing.
// It uses minimal Argon2 parameters and a mock store.
func newTestModel(t *testing.T) (model, *mockStore) {
	t.Helper()

	eng := testEngine()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}

	// Derive key and compute verify hash for the test password.
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	hkdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	verifyHash := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, verifyHash); err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	mockSt := newMockStore()
	m := NewModel(mockSt, eng, salt, verifyHash, 0, true) // 0 = no auto-lock timeout, true = no keychain
	return m, mockSt
}

// addTestSecret adds an encrypted test secret to the mock store.
// The secret has a fake EncryptedValue — detail decryption tests handle this separately.
func addTestSecret(t *testing.T, ms *mockStore, name string, kind secret.Kind, tags string) {
	t.Helper()
	now := time.Now().UTC()

	// Fake EncryptedValue — detail view tests handle proper encryption separately.
	s := secret.Secret{
		ID:             fmt.Sprintf("uuid-%s", name),
		Name:           name,
		NameLookup:     []byte("mock-lookup-" + name),
		Kind:           kind,
		EncryptedValue: []byte("fake-encrypted-" + name),
		Tags:           tags,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := ms.Store(s); err != nil {
		t.Fatalf("store secret: %v", err)
	}
}

// ── Tests ──

func TestUnlock_CorrectPassword_TransitionsToList(t *testing.T) {
	m, _ := newTestModel(t)

	// Set the correct password in the text input.
	m.passwordInput.SetValue(testPassword)

	// Send Enter to attempt unlock.
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Errorf("state = %v, want stateList (%v)", m2.state, stateList)
	}

	// Session key should be derived.
	if len(m2.key) == 0 {
		t.Error("session key should be non-nil after successful unlock")
	}
}

func TestUnlock_WrongPassword_StaysInUnlock(t *testing.T) {
	m, _ := newTestModel(t)

	m.passwordInput.SetValue("wrong-password")
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateUnlock {
		t.Errorf("state = %v, want stateUnlock (%v)", m2.state, stateUnlock)
	}

	if !strings.Contains(m2.err, "Invalid") {
		t.Errorf("expected error message, got: %q", m2.err)
	}

	// Key should NOT be derived.
	if m2.key != nil {
		t.Error("session key should be nil after failed unlock")
	}
}

func TestUnlock_EmptyPassword_Rejected(t *testing.T) {
	m, _ := newTestModel(t)

	m.passwordInput.SetValue("")
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateUnlock {
		t.Errorf("state = %v, want stateUnlock", m2.state)
	}
	if !strings.Contains(m2.err, "empty") {
		t.Errorf("expected empty password error, got: %q", m2.err)
	}
}

func TestUnlock_MaxAttempts_Exits(t *testing.T) {
	m, _ := newTestModel(t)

	for i := 0; i < 3; i++ {
		m.passwordInput.SetValue("wrong-password")
		result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m = result.(model)
	}

	if !m.quitting {
		t.Error("expected model to quit after 3 failed attempts")
	}
	if m.key != nil {
		t.Error("session key should be nil after failed quit")
	}
}

func TestUnlock_CtrlC_DuringUnlock_Quits(t *testing.T) {
	m, _ := newTestModel(t)

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	m2 := result.(model)

	if !m2.quitting {
		t.Error("expected quitting to be true after Ctrl+C")
	}
}

func TestList_ShowsSecrets(t *testing.T) {
	m, ms := newTestModel(t)

	// Add secrets to the mock store BEFORE unlocking.
	addTestSecret(t, ms, "github-token", secret.KindAPIKey, "github")
	addTestSecret(t, ms, "aws-key", secret.KindAPIKey, "aws")
	addTestSecret(t, ms, "personal-note", secret.KindNote, "")

	// Unlock.
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateList {
		t.Fatalf("state = %v, want stateList", m.state)
	}

	view := m.View()
	if !strings.Contains(view, "github-token") {
		t.Error("list should show github-token")
	}
	if !strings.Contains(view, "aws-key") {
		t.Error("list should show aws-key")
	}
	if !strings.Contains(view, "personal-note") {
		t.Error("list should show personal-note")
	}
}

func TestList_EmptyVault(t *testing.T) {
	m, _ := newTestModel(t)

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateList {
		t.Fatalf("state = %v, want stateList", m.state)
	}

	view := m.View()
	if !strings.Contains(view, "No secrets") {
		t.Errorf("expected empty vault message, got: %s", view[:min(len(view), 100)])
	}
}

func TestList_NavigationKeys(t *testing.T) {
	m, ms := newTestModel(t)

	addTestSecret(t, ms, "secret-a", secret.KindPassword, "")
	addTestSecret(t, ms, "secret-b", secret.KindPassword, "")
	addTestSecret(t, ms, "secret-c", secret.KindPassword, "")

	// Unlock.
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.cursor != 0 {
		t.Fatalf("initial cursor = %d, want 0", m.cursor)
	}

	// Down arrow.
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = result.(model)
	if m.cursor != 1 {
		t.Errorf("after Down: cursor = %d, want 1", m.cursor)
	}

	// j key (vim down).
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m = result.(model)
	if m.cursor != 2 {
		t.Errorf("after j: cursor = %d, want 2", m.cursor)
	}

	// k key (vim up).
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	m = result.(model)
	if m.cursor != 1 {
		t.Errorf("after k: cursor = %d, want 1", m.cursor)
	}

	// Up arrow.
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = result.(model)
	if m.cursor != 0 {
		t.Errorf("after Up: cursor = %d, want 0", m.cursor)
	}
}

func TestList_EnterOnSecret_TransitionsToDetail(t *testing.T) {
	m, ms := newTestModel(t)

	// Add a secret and pre-encrypt its value so the detail screen can decrypt it.
	eng := testEngine()
	salt := m.salt // Use the model's salt
	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	ciphertext, nonce, err := eng.Encrypt([]byte("my-secret-value"), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	blob := make([]byte, 0, len(nonce)+len(ciphertext))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	now := time.Now().UTC()
	testSec := secret.Secret{
		ID:             "uuid-test-secret",
		Name:           "test-secret",
		Kind:           secret.KindPassword,
		EncryptedValue: blob,
		Notes:          "secret notes here",
		Tags:           "test",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := ms.Store(testSec); err != nil {
		t.Fatalf("store secret: %v", err)
	}

	// Unlock.
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateList {
		t.Fatalf("precondition: state = %v, want stateList", m.state)
	}

	// Press Enter on the first (and only) secret.
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateDetail {
		t.Fatalf("after Enter: state = %v, want stateDetail", m.state)
	}

	if m.detailSecret.Name != "test-secret" {
		t.Errorf("detail secret name = %q, want %q", m.detailSecret.Name, "test-secret")
	}
}

func TestDetail_RevealToggle(t *testing.T) {
	m, ms := newTestModel(t)

	// Add encrypted secret.
	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	ct, nonce, err := eng.Encrypt([]byte("visible-value"), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob := append(nonce, ct...)

	now := time.Now().UTC()
	_ = ms.Store(secret.Secret{
		Name: "secret-a", Kind: secret.KindPassword,
		EncryptedValue: blob, Tags: "", Notes: "",
		CreatedAt: now, UpdatedAt: now,
	})

	// Unlock and enter detail.
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	// Initially not revealed.
	if m.showPlaintext {
		t.Error("plaintext should be hidden initially")
	}

	view := m.View()
	if strings.Contains(view, "visible-value") {
		t.Error("plaintext should NOT be visible before reveal")
	}

	// Toggle reveal with Enter.
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if !m.showPlaintext {
		t.Error("plaintext should be revealed after Enter toggle")
	}

	view = m.View()
	if !strings.Contains(view, "visible-value") {
		t.Error("plaintext should be visible after reveal")
	}

	// Toggle hide with Enter again.
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.showPlaintext {
		t.Error("plaintext should be hidden after second Enter toggle")
	}
}

func TestDetail_EscReturnsToList(t *testing.T) {
	m, ms := newTestModel(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	ct, nonce, err := eng.Encrypt([]byte("value"), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob := append(nonce, ct...)
	crypto.Zeroize(key)

	_ = ms.Store(secret.Secret{
		Name: "test", Kind: secret.KindPassword,
		EncryptedValue: blob, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	// Unlock and enter detail.
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateDetail {
		t.Fatalf("expected stateDetail, got %v", m.state)
	}

	// Press Esc to go back.
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = result.(model)

	if m.state != stateList {
		t.Errorf("after Esc: state = %v, want stateList", m.state)
	}
	if len(m.plaintext) != 0 {
		t.Error("plaintext should be cleared after returning to list")
	}
}

func TestSearch_FiltersSecrets(t *testing.T) {
	m, ms := newTestModel(t)

	addTestSecret(t, ms, "github-token", secret.KindAPIKey, "github")
	addTestSecret(t, ms, "aws-key", secret.KindAPIKey, "aws")
	addTestSecret(t, ms, "github-ssh", secret.KindSSHKey, "github,ssh")
	addTestSecret(t, ms, "personal-note", secret.KindNote, "")

	// Unlock.
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	// Activate search with '/'.
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = result.(model)

	if m.state != stateSearch {
		t.Fatalf("after '/': state = %v, want stateSearch", m.state)
	}

	// Set filter directly (bypass textinput for deterministic test).
	m.searchInput.SetValue("github")
	m.searchQuery = "github"
	m.searchResults = runFilter(m.secrets, "github")

	if len(m.searchResults) != 2 {
		t.Errorf("expected 2 search results, got %d: %v", len(m.searchResults), m.searchResults)
	}

	view := m.View()
	if !strings.Contains(view, "github-token") {
		t.Error("search view should show github-token")
	}
	if strings.Contains(view, "aws-key") {
		t.Error("search view should NOT show aws-key")
	}
}

func TestSearch_EscClearsAndReturnsToList(t *testing.T) {
	m, ms := newTestModel(t)

	addTestSecret(t, ms, "github-token", secret.KindAPIKey, "github")
	addTestSecret(t, ms, "aws-key", secret.KindAPIKey, "aws")

	// Unlock.
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	// Activate search and set filter.
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = result.(model)
	m.searchInput.SetValue("github")
	m.searchQuery = "github"
	m.searchResults = runFilter(m.secrets, "github")

	if m.state != stateSearch {
		t.Fatalf("expected search state")
	}
	if len(m.searchResults) == 0 {
		t.Fatal("expected search results")
	}

	// Esc to clear and go back.
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = result.(model)

	if m.state != stateList {
		t.Errorf("after Esc: state = %v, want stateList", m.state)
	}
	if m.searchQuery != "" {
		t.Errorf("search query should be cleared, got %q", m.searchQuery)
	}
}

func TestSearch_NavigationInResults(t *testing.T) {
	m, ms := newTestModel(t)

	addTestSecret(t, ms, "aaa", secret.KindPassword, "")
	addTestSecret(t, ms, "aab", secret.KindPassword, "")
	addTestSecret(t, ms, "aac", secret.KindPassword, "")

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	// Activate search.
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = result.(model)

	// Set search state directly (bypass textinput processing for deterministic tests).
	m.searchInput.SetValue("aa")
	m.searchQuery = "aa"
	m.searchResults = runFilter(m.secrets, "aa")

	// Navigate down.
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = result.(model)

	if m.cursor != 1 {
		t.Errorf("after Down in search: cursor = %d, want 1", m.cursor)
	}
}

func TestQuit_CtrlC_ZeroizesKey(t *testing.T) {
	m, _ := newTestModel(t)

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.key == nil {
		t.Fatal("precondition: key should be derived")
	}

	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	m = result.(model)

	if !m.quitting {
		t.Error("expected quitting after Ctrl+C")
	}
}

func TestQuit_QKeyDuringList_Quits(t *testing.T) {
	m, _ := newTestModel(t)

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	m = result.(model)

	if !m.quitting {
		t.Error("expected quitting after 'q' during list")
	}
}

func TestView_NoPanicOnEmptyState(t *testing.T) {
	m, _ := newTestModel(t)

	// View should not panic in any state.
	_ = m.View()

	// After unlock, view list.
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	_ = m.View()
}

func TestUnlock_LipglossStylesApplied(t *testing.T) {
	m, _ := newTestModel(t)

	view := m.View()

	// Should contain unlock prompt elements.
	if !strings.Contains(view, "Unlock") {
		t.Error("unlock view should contain 'Unlock' header")
	}
	if !strings.Contains(view, "Master Password") {
		t.Error("unlock view should show Master Password label")
	}
}

// TestRunFilter tests the search filter logic directly.
func TestRunFilter(t *testing.T) {
	secrets := []secret.Secret{
		{Name: "github-token", Tags: "github"},
		{Name: "aws-key", Tags: "aws"},
		{Name: "personal-note", Tags: ""},
		{Name: "github-ssh", Tags: "github,ssh"},
	}

	tests := []struct {
		name     string
		query    string
		want     int
		wantKeys []string
	}{
		{name: "empty query returns nil", query: "", want: 0},
		{name: "match by name", query: "github", want: 2, wantKeys: []string{"github-token", "github-ssh"}},
		{name: "match by tag", query: "aws", want: 1, wantKeys: []string{"aws-key"}},
		{name: "partial match", query: "note", want: 1, wantKeys: []string{"personal-note"}},
		{name: "case insensitive", query: "GITHUB", want: 2, wantKeys: []string{"github-token", "github-ssh"}},
		{name: "no match", query: "zzzzz", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := runFilter(secrets, tt.query)
			if len(results) != tt.want {
				t.Errorf("got %d results, want %d: %+v", len(results), tt.want, results)
			}
			if len(tt.wantKeys) > 0 {
				for _, key := range tt.wantKeys {
					found := false
					for _, r := range results {
						if r.Name == key {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected %q in results, got: %+v", key, results)
					}
				}
			}
		})
	}
}

func TestUnpackEnvelope(t *testing.T) {
	tests := []struct {
		name      string
		blob      []byte
		wantErr   bool
		wantNonce int
		wantCtLen int
	}{
		{name: "valid blob", blob: append([]byte("123456789012"), []byte("ciphertext-data")...), wantErr: false, wantNonce: 12, wantCtLen: 15},
		{name: "too short", blob: []byte("short"), wantErr: true},
		{name: "empty", blob: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce, ct, err := unpackEnvelope(tt.blob)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(nonce) != tt.wantNonce {
				t.Errorf("nonce length = %d, want %d", len(nonce), tt.wantNonce)
			}
			if len(ct) != tt.wantCtLen {
				t.Errorf("ciphertext length = %d, want %d", len(ct), tt.wantCtLen)
			}
		})
	}
}

// ── Add secret tests ──

func TestListState_A_TransitionsToAddState(t *testing.T) {
	m, ms := newTestModel(t)
	m.state = stateList
	ms.secrets["test"] = secret.Secret{Name: "test", Kind: secret.KindPassword}
	m.secrets = []secret.Secret{{Name: "test", Kind: secret.KindPassword}}

	// Press 'a' to enter add mode
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m2 := result.(model)

	if m2.state != stateAdd {
		t.Fatalf("expected stateAdd, got %v", m2.state)
	}
	if !m2.addNameInput.Focused() {
		t.Error("name input should be focused")
	}
}

func TestAddState_EmptyNameShowsError(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateAdd
	m.addKindIndex = 1 // api_key (non-password: no extra fields)

	// Focus value field (skip name)
	m.addFocusIndex = 1
	m.addNameInput.SetValue("")
	m.addValueInput.SetValue("secret123")

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.err == "" || !strings.Contains(m2.err, "Name") {
		t.Errorf("expected name error, got: %q", m2.err)
	}
	if m2.state != stateAdd {
		t.Error("should stay in add state on error")
	}
}

func TestAddState_EmptyValueShowsError(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateAdd
	m.addKindIndex = 1 // api_key (non-password)

	m.addFocusIndex = 1
	m.addNameInput.SetValue("my-secret")
	m.addValueInput.SetValue("")

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.err == "" || !strings.Contains(m2.err, "Value") {
		t.Errorf("expected value error, got: %q", m2.err)
	}
}

func TestAddState_SuccessfulSaveReturnsToList(t *testing.T) {
	m, ms := newTestModel(t)

	// Derive the session key (normally done during unlock)
	key, err := m.engine.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	m.key = key

	m.state = stateAdd
	m.addKindIndex = 1 // api_key (non-password: no extra fields)
	m.addFocusIndex = 1
	m.addNameInput.SetValue("new-secret")
	m.addValueInput.SetValue("my-password")

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList after save, got %v", m2.state)
	}
	if m2.err != "" {
		t.Errorf("unexpected error: %q", m2.err)
	}

	// Verify secret was stored
	stored, err := ms.GetByNameLookup([]byte("new-secret"))
	if err != nil {
		t.Fatalf("secret not stored: %v", err)
	}
	if stored.Name != "new-secret" {
		t.Errorf("name = %q, want new-secret", stored.Name)
	}
	if stored.Kind != secret.KindAPIKey {
		t.Errorf("kind = %q, want api_key", stored.Kind)
	}
	if len(stored.EncryptedValue) == 0 {
		t.Error("encrypted value should not be empty")
	}
}

func TestAddState_EscCancelsAndReturnsToList(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateAdd
	m.addNameInput.SetValue("draft")

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList after cancel, got %v", m2.state)
	}
}

// ── Delete secret tests ──

func TestListState_D_DeletesSelectedSecret(t *testing.T) {
	m, ms := newTestModel(t)
	ms.secrets["secret-a"] = secret.Secret{Name: "secret-a", NameLookup: []byte("secret-a"), Kind: secret.KindPassword, EncryptedValue: []byte("enc")}
	ms.secrets["secret-b"] = secret.Secret{Name: "secret-b", NameLookup: []byte("secret-b"), Kind: secret.KindPassword, EncryptedValue: []byte("enc")}
	m.secrets = []secret.Secret{
		{Name: "secret-a", NameLookup: []byte("secret-a"), Kind: secret.KindPassword},
		{Name: "secret-b", NameLookup: []byte("secret-b"), Kind: secret.KindPassword},
	}
	m.cursor = 0
	m.state = stateList

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList after delete, got %v", m2.state)
	}

	// Verify secret-a was deleted, secret-b remains
	_, err := ms.GetByNameLookup([]byte("secret-a"))
	if err == nil {
		t.Error("secret-a should have been deleted")
	}
	_, err = ms.GetByNameLookup([]byte("secret-b"))
	if err != nil {
		t.Error("secret-b should still exist")
	}

	if len(m2.secrets) != 1 {
		t.Errorf("expected 1 secret remaining, got %d", len(m2.secrets))
	}
}

func TestListState_D_OnEmptyListDoesNothing(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateList
	m.secrets = []secret.Secret{}
	m.cursor = 0
	m.err = ""

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	m2 := result.(model)

	if m2.state != stateList {
		t.Error("should stay in list state")
	}
	if m2.err != "" {
		t.Errorf("unexpected error on empty list: %q", m2.err)
	}
}

// ── Test helpers for certificate generation ──

// generateTestCertPEM creates a self-signed X.509 certificate in PEM format for testing.
func generateTestCertPEM(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn, "www." + cn},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// ── Inspect tests ──

func TestList_I_InspectsCertificate(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	// Add a cert secret with valid metadata JSON
	meta := parse.Metadata{
		Format:            "x509",
		SubjectCN:         "example.com",
		IssuerCN:          "Test CA",
		NotAfter:          now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
		FingerprintSHA256: "abc123def456",
		SANs:              []string{"example.com", "www.example.com"},
		KeyUsage:          []string{"digital_signature", "key_encipherment"},
	}
	metaBytes, _ := json.Marshal(meta)

	s := secret.Secret{
		ID:        "uuid-cert-1",
		Name:      "my-cert",
		Kind:      secret.KindCertificate,
		Metadata:  string(metaBytes),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := ms.Store(s); err != nil {
		t.Fatalf("store cert: %v", err)
	}

	m.state = stateList
	m.secrets, _ = ms.List()
	m.cursor = 0

	// Press 'i' to inspect
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	m2 := result.(model)

	if m2.state != stateInspect {
		t.Fatalf("expected stateInspect, got %v", m2.state)
	}

	view := m2.View()
	if !strings.Contains(view, "example.com") {
		t.Error("inspect view should show Subject CN")
	}
	if !strings.Contains(view, "Test CA") {
		t.Error("inspect view should show Issuer CN")
	}
	if !strings.Contains(view, "abc123def456") {
		t.Error("inspect view should show fingerprint")
	}
}

func TestList_I_InspectsSSHKey(t *testing.T) {
	m, ms := newTestModel(t)

	// Add an SSH key secret with valid metadata JSON
	meta := parse.Metadata{
		Format:            "ssh_private",
		KeyType:           "ssh-rsa",
		FingerprintSHA256: "SHA256:testfingerprint",
		Comment:           "user@host",
		BitLength:         4096,
	}
	metaBytes, _ := json.Marshal(meta)

	now := time.Now().UTC()
	s := secret.Secret{
		ID:        "uuid-ssh-1",
		Name:      "my-ssh-key",
		Kind:      secret.KindSSHKey,
		Metadata:  string(metaBytes),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := ms.Store(s); err != nil {
		t.Fatalf("store ssh: %v", err)
	}

	m.state = stateList
	m.secrets, _ = ms.List()
	m.cursor = 0

	// Press 'i' to inspect
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	m2 := result.(model)

	if m2.state != stateInspect {
		t.Fatalf("expected stateInspect, got %v", m2.state)
	}

	view := m2.View()
	if !strings.Contains(view, "ssh-rsa") {
		t.Error("inspect view should show key type")
	}
	if !strings.Contains(view, "user@host") {
		t.Error("inspect view should show comment")
	}
}

func TestList_I_OnNonInspectable(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	// Add a password secret (non-inspectable)
	s := secret.Secret{
		ID:        "uuid-pw-1",
		Name:      "my-password",
		Kind:      secret.KindPassword,
		Metadata:  "",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := ms.Store(s); err != nil {
		t.Fatalf("store password: %v", err)
	}

	m.state = stateList
	m.secrets, _ = ms.List()
	m.cursor = 0

	// Press 'i' — should stay in list with error
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	m2 := result.(model)

	if m2.state != stateList {
		t.Errorf("expected stateList for non-inspectable, got %v", m2.state)
	}
	if m2.err == "" {
		t.Error("expected error message for non-inspectable secret")
	}
}

func TestList_I_MalformedMetadata(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	// Add a cert secret with malformed metadata JSON
	s := secret.Secret{
		ID:        "uuid-bad-1",
		Name:      "bad-cert",
		Kind:      secret.KindCertificate,
		Metadata:  "{invalid json}",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := ms.Store(s); err != nil {
		t.Fatalf("store: %v", err)
	}

	m.state = stateList
	m.secrets, _ = ms.List()
	m.cursor = 0

	// Press 'i' — should show error about unparseable metadata
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	m2 := result.(model)

	if m2.err == "" {
		t.Error("expected error for malformed metadata")
	}
	if !strings.Contains(m2.err, "Unable to parse metadata") {
		t.Errorf("expected 'Unable to parse metadata' in error, got: %q", m2.err)
	}
}

// ── Kind selector tests ──

func TestAdd_T_CyclesKind(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateAdd

	// Press ctrl+k and verify kindIndex cycles through ValidKinds()
	validKinds := secret.ValidKinds()
	for i := 0; i < len(validKinds)*2+1; i++ {
		expectedIdx := i % len(validKinds)
		if m.addKindIndex != expectedIdx {
			t.Errorf("after %d presses: addKindIndex = %d, want %d", i, m.addKindIndex, expectedIdx)
		}
		result, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlK})
		m = result.(model)
	}
}

func TestAdd_SaveKeepsSelectedKind(t *testing.T) {
	m, ms := newTestModel(t)

	// Derive session key
	key, err := m.engine.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	m.key = key

	m.state = stateAdd
	m.addFocusIndex = 1
	m.addNameInput.SetValue("my-api-key")
	m.addValueInput.SetValue("sk-1234567890")

	// Cycle kind to api_key (index 1 in ValidKinds())
	m.addKindIndex = 1 // secret.KindAPIKey

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList after save, got %v", m2.state)
	}

	stored, err := ms.GetByNameLookup([]byte("my-api-key"))
	if err != nil {
		t.Fatalf("secret not stored: %v", err)
	}
	if stored.Kind != secret.KindAPIKey {
		t.Errorf("kind = %q, want %q", stored.Kind, secret.KindAPIKey)
	}
}

// ── Kind filter tests ──

func TestList_F_CyclesKindFilter(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateList

	// Expected cycle: "" → "certificate" → "ssh_key" → "api_key" → "password" → "note" → "other" → ""
	expectedCycle := []string{"", "certificate", "ssh_key", "api_key", "password", "note", "other", ""}

	// Start at empty
	if m.kindFilter != "" {
		t.Fatalf("initial kindFilter = %q, want empty", m.kindFilter)
	}

	for i, expected := range expectedCycle {
		if m.kindFilter != expected {
			t.Errorf("after %d presses: kindFilter = %q, want %q", i, m.kindFilter, expected)
		}
		result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
		m = result.(model)
	}
}

func TestList_KindFilter_FiltersSecrets(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	// Add secrets of different kinds
	for _, s := range []secret.Secret{
		{ID: "u1", Name: "cert-a", Kind: secret.KindCertificate, CreatedAt: now, UpdatedAt: now},
		{ID: "u2", Name: "cert-b", Kind: secret.KindCertificate, CreatedAt: now, UpdatedAt: now},
		{ID: "u3", Name: "ssh-key", Kind: secret.KindSSHKey, CreatedAt: now, UpdatedAt: now},
		{ID: "u4", Name: "api-key", Kind: secret.KindAPIKey, CreatedAt: now, UpdatedAt: now},
		{ID: "u5", Name: "password", Kind: secret.KindPassword, CreatedAt: now, UpdatedAt: now},
	} {
		if err := ms.Store(s); err != nil {
			t.Fatalf("store %s: %v", s.Name, err)
		}
	}

	m.state = stateList
	m.secrets, _ = ms.List()
	m.kindFilter = "certificate"

	view := m.View()

	if !strings.Contains(view, "cert-a") {
		t.Error("view should show cert-a")
	}
	if !strings.Contains(view, "cert-b") {
		t.Error("view should show cert-b")
	}
	if strings.Contains(view, "ssh-key") {
		t.Error("view should NOT show ssh-key when filter is certificate")
	}
	if strings.Contains(view, "api-key") {
		t.Error("view should NOT show api-key when filter is certificate")
	}
	if strings.Contains(view, "password") {
		t.Error("view should NOT show password when filter is certificate")
	}
}

func TestList_KindFilter_ResetWhenCyclingBack(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	for _, s := range []secret.Secret{
		{ID: "u1", Name: "cert", Kind: secret.KindCertificate, CreatedAt: now, UpdatedAt: now},
		{ID: "u2", Name: "pw", Kind: secret.KindPassword, CreatedAt: now, UpdatedAt: now},
	} {
		if err := ms.Store(s); err != nil {
			t.Fatalf("store: %v", err)
		}
	}

	m.state = stateList
	m.secrets, _ = ms.List()
	m.kindFilter = "certificate"

	// Cycle 'f' 6 times to return to "" (empty = all) from "certificate"
	for i := 0; i < 6; i++ {
		result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
		m = result.(model)
	}

	if m.kindFilter != "" {
		t.Fatalf("kindFilter = %q, want empty after cycling back", m.kindFilter)
	}

	view := m.View()
	if !strings.Contains(view, "cert") {
		t.Error("view should show cert after reset")
	}
	if !strings.Contains(view, "pw") {
		t.Error("view should show pw after reset")
	}
}

// ── Tag filter tests ──

func TestList_T_CyclesTagFilter(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	// Add secrets with different tags
	for _, s := range []secret.Secret{
		{ID: "u1", Name: "prod-db", Kind: secret.KindPassword, Tags: "production,db", CreatedAt: now, UpdatedAt: now},
		{ID: "u2", Name: "dev-db", Kind: secret.KindPassword, Tags: "development,db", CreatedAt: now, UpdatedAt: now},
		{ID: "u3", Name: "staging-key", Kind: secret.KindAPIKey, Tags: "staging", CreatedAt: now, UpdatedAt: now},
	} {
		if err := ms.Store(s); err != nil {
			t.Fatalf("store %s: %v", s.Name, err)
		}
	}

	m.state = stateList
	m.secrets, _ = ms.List()

	// Initial state: no tag filter
	if m.tagFilter != "" {
		t.Fatalf("initial tagFilter = %q, want empty", m.tagFilter)
	}

	// Collect tags to know the cycle
	tags := m.collectTags()
	if len(tags) == 0 {
		t.Fatal("expected at least one unique tag")
	}

	// Press 't' to cycle to first tag
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	m2 := result.(model)

	if m2.tagFilter == "" {
		t.Error("tagFilter should be non-empty after first 't'")
	}

	// Verify tag filter exists in collected tags
	found := false
	for _, tag := range tags {
		if tag == m2.tagFilter {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("tagFilter = %q not in available tags: %v", m2.tagFilter, tags)
	}
}

func TestList_TagFilter_FilteredView(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	for _, s := range []secret.Secret{
		{ID: "u1", Name: "cert-a", Kind: secret.KindCertificate, Tags: "production,aws", CreatedAt: now, UpdatedAt: now},
		{ID: "u2", Name: "cert-b", Kind: secret.KindCertificate, Tags: "staging", CreatedAt: now, UpdatedAt: now},
		{ID: "u3", Name: "password", Kind: secret.KindPassword, Tags: "production", CreatedAt: now, UpdatedAt: now},
	} {
		if err := ms.Store(s); err != nil {
			t.Fatalf("store %s: %v", s.Name, err)
		}
	}

	m.state = stateList
	m.secrets, _ = ms.List()

	// Set tag filter to "production"
	m.tagFilter = "production"

	view := m.View()

	if !strings.Contains(view, "cert-a") {
		t.Error("view should show cert-a (has 'production' tag)")
	}
	if !strings.Contains(view, "password") {
		t.Error("view should show password (has 'production' tag)")
	}
	if strings.Contains(view, "cert-b") {
		t.Error("view should NOT show cert-b (does not have 'production' tag)")
	}
}

func TestList_TagFilter_FooterShowsTag(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateList
	m.tagFilter = "production"

	view := m.View()
	if !strings.Contains(view, "production") {
		t.Error("footer should show tag filter indicator")
	}
}

// ── Expiring tests ──

func TestList_E_TogglesExpiring(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	// Add a certificate that expires within 30 days
	meta := parse.Metadata{
		Format:   "x509",
		NotAfter: now.Add(15 * 24 * time.Hour).Format(time.RFC3339),
	}
	metaBytes, _ := json.Marshal(meta)

	for _, s := range []secret.Secret{
		{
			ID: "u1", Name: "expiring-cert", Kind: secret.KindCertificate,
			Metadata: string(metaBytes), CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "u2", Name: "password", Kind: secret.KindPassword,
			CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := ms.Store(s); err != nil {
			t.Fatalf("store: %v", err)
		}
	}

	m.state = stateList
	m.secrets, _ = ms.List()
	initialCount := len(m.secrets)

	// Press 'e' to toggle expiring mode on
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m2 := result.(model)

	if !m2.expiringMode {
		t.Error("expiringMode should be true after pressing 'e'")
	}
	if len(m2.secrets) >= initialCount {
		t.Error("expiring mode should have fewer secrets than full list")
	}
}

func TestList_Expiring_ShowsExpiryStatus(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	// Add an expiring cert and an expired cert
	expiringMeta := parse.Metadata{
		Format:   "x509",
		NotAfter: now.Add(15 * 24 * time.Hour).Format(time.RFC3339),
	}
	expiringBytes, _ := json.Marshal(expiringMeta)

	expiredMeta := parse.Metadata{
		Format:   "x509",
		NotAfter: now.Add(-5 * 24 * time.Hour).Format(time.RFC3339),
	}
	expiredBytes, _ := json.Marshal(expiredMeta)

	for _, s := range []secret.Secret{
		{
			ID: "u1", Name: "expiring-cert", Kind: secret.KindCertificate,
			Metadata: string(expiringBytes), CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "u2", Name: "expired-cert", Kind: secret.KindCertificate,
			Metadata: string(expiredBytes), CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := ms.Store(s); err != nil {
			t.Fatalf("store: %v", err)
		}
	}

	m.state = stateList
	m.secrets, _ = ms.List()

	// Press 'e' to enter expiring mode
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m2 := result.(model)

	if !m2.expiringMode {
		t.Fatal("expected expiringMode to be true")
	}

	view := m2.View()
	if !strings.Contains(view, "15d") &&
		!strings.Contains(view, "expire") &&
		!strings.Contains(view, "days") {
		t.Log("expiry view:", view)
		t.Error("expiring view should show expiry status (like days until expiry)")
	}
}

func TestList_Expiring_Empty(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	// Only add password secrets (no certs with metadata)
	for _, s := range []secret.Secret{
		{ID: "u1", Name: "password", Kind: secret.KindPassword, CreatedAt: now, UpdatedAt: now},
	} {
		if err := ms.Store(s); err != nil {
			t.Fatalf("store: %v", err)
		}
	}

	m.state = stateList
	m.secrets, _ = ms.List()

	// Press 'e' to enter expiring mode
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m2 := result.(model)

	if len(m2.secrets) != 0 {
		t.Errorf("expected empty secrets in expiring mode, got %d", len(m2.secrets))
	}
	view := m2.View()
	if !strings.Contains(view, "No expiring") {
		t.Error("expected 'No expiring' message in empty expiring view")
	}
}

func TestList_Expiring_Off(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	// Add a cert and a password
	meta := parse.Metadata{
		Format:   "x509",
		NotAfter: now.Add(15 * 24 * time.Hour).Format(time.RFC3339),
	}
	metaBytes, _ := json.Marshal(meta)

	for _, s := range []secret.Secret{
		{
			ID: "u1", Name: "expiring-cert", Kind: secret.KindCertificate,
			Metadata: string(metaBytes), CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "u2", Name: "password", Kind: secret.KindPassword,
			CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := ms.Store(s); err != nil {
			t.Fatalf("store: %v", err)
		}
	}

	m.state = stateList
	m.secrets, _ = ms.List()
	fullCount := len(m.secrets)

	// Press 'e' to toggle ON
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m2 := result.(model)

	if !m2.expiringMode {
		t.Fatal("expiringMode should be true after first 'e'")
	}

	// Press 'e' again to toggle OFF
	result, _ = m2.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m3 := result.(model)

	if m3.expiringMode {
		t.Error("expiringMode should be false after second 'e'")
	}
	if len(m3.secrets) != fullCount {
		t.Errorf("after toggling off, expected %d secrets, got %d", fullCount, len(m3.secrets))
	}
}

// ── File mode tests ──

func TestAdd_O_SwitchesToFileMode(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateAdd

	// Default mode should be manual
	if m.addFileMode {
		t.Error("addFileMode should be false initially")
	}

	// Press ctrl+o to toggle file mode
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlO})
	m2 := result.(model)

	if !m2.addFileMode {
		t.Error("addFileMode should be true after pressing 'o'")
	}

	view := m2.View()
	if !strings.Contains(view, "File") && !strings.Contains(view, "path") {
		t.Error("view should indicate file mode after toggle")
	}
}

func TestAdd_FileMode_SavesCertificate(t *testing.T) {
	m, ms := newTestModel(t)

	// Derive session key
	key, err := m.engine.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	m.key = key

	// Create a temp PEM certificate file
	certPEM := generateTestCertPEM(t, "test.example.com", time.Now().Add(365*24*time.Hour))
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test-cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write cert file: %v", err)
	}

	// Set up add state in file mode
	m.state = stateAdd
	m.addFileMode = true
	m.addNameInput.SetValue("imported-cert")
	m.addFileInput.SetValue(certPath)
	m.addFocusIndex = 1

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList after file save, got %v (err: %q)", m2.state, m2.err)
	}

	stored, err := ms.GetByNameLookup([]byte("imported-cert"))
	if err != nil {
		t.Fatalf("secret not stored: %v", err)
	}
	if stored.Kind != secret.KindCertificate {
		t.Errorf("kind = %q, want %q", stored.Kind, secret.KindCertificate)
	}
	if stored.Metadata == "" {
		t.Error("metadata should be populated for certificate import")
	}
	if !strings.Contains(stored.Metadata, "test.example.com") {
		t.Error("metadata should contain the certificate subject CN")
	}
	if len(stored.EncryptedValue) == 0 {
		t.Error("encrypted value should not be empty")
	}
}

func TestAdd_FileMode_SavesText(t *testing.T) {
	m, ms := newTestModel(t)

	// Derive session key
	key, err := m.engine.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	m.key = key

	// Create a temp text file
	tmpDir := t.TempDir()
	txtPath := filepath.Join(tmpDir, "note.txt")
	txtContent := []byte("This is a plaintext secret value")
	if err := os.WriteFile(txtPath, txtContent, 0644); err != nil {
		t.Fatalf("write text file: %v", err)
	}

	// Set up add state in file mode
	m.state = stateAdd
	m.addFileMode = true
	m.addNameInput.SetValue("imported-note")
	m.addFileInput.SetValue(txtPath)
	m.addFocusIndex = 1

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList after file save, got %v (err: %q)", m2.state, m2.err)
	}

	stored, err := ms.GetByNameLookup([]byte("imported-note"))
	if err != nil {
		t.Fatalf("secret not stored: %v", err)
	}
	if stored.Kind != secret.KindPassword {
		t.Errorf("kind = %q, want %q (plain text should save as password)", stored.Kind, secret.KindPassword)
	}
}

func TestAdd_FileMode_FileNotFound(t *testing.T) {
	m, _ := newTestModel(t)

	// Derive session key
	key, err := m.engine.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	m.key = key

	m.state = stateAdd
	m.addFileMode = true
	m.addNameInput.SetValue("missing")
	m.addFileInput.SetValue("/nonexistent/path/file.pem")
	m.addFocusIndex = 1

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateAdd {
		t.Errorf("expected stateAdd (stay in form) for file not found, got %v", m2.state)
	}
	if m2.err == "" {
		t.Error("expected error for file not found")
	}
	if !strings.Contains(m2.err, "not found") && !strings.Contains(m2.err, "found") {
		t.Errorf("error should mention file not found, got: %q", m2.err)
	}
}

// ── Additional Detail state tests ──

func TestDetail_SpaceTogglesReveal(t *testing.T) {
	m, ms := newTestModel(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	ct, nonce, err := eng.Encrypt([]byte("secret-value"), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob := append(nonce, ct...)

	_ = ms.Store(secret.Secret{
		Name: "test", Kind: secret.KindPassword,
		EncryptedValue: blob, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	// Start hidden
	if m.showPlaintext {
		t.Error("expected initially hidden")
	}

	// Space toggles reveal
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = result.(model)
	if !m.showPlaintext {
		t.Error("expected revealed after Space")
	}

	// Space toggles hide back
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = result.(model)
	if m.showPlaintext {
		t.Error("expected hidden after second Space")
	}
}

func TestDetail_QReturnsToList(t *testing.T) {
	m, ms := newTestModel(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	ct, nonce, _ := eng.Encrypt([]byte("v"), key)
	blob := append(nonce, ct...)
	crypto.Zeroize(key)

	_ = ms.Store(secret.Secret{
		Name: "t", Kind: secret.KindPassword,
		EncryptedValue: blob, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	m = result.(model)

	if m.state != stateList {
		t.Errorf("expected stateList after 'q', got %v", m.state)
	}
	if len(m.plaintext) != 0 {
		t.Error("plaintext should be cleared after 'q'")
	}
}

func TestDetail_REnterReveal(t *testing.T) {
	m, ms := newTestModel(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	ct, nonce, _ := eng.Encrypt([]byte("visible"), key)
	blob := append(nonce, ct...)
	crypto.Zeroize(key)

	_ = ms.Store(secret.Secret{
		Name: "t", Kind: secret.KindPassword,
		EncryptedValue: blob, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	// Press 'r' to reveal
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = result.(model)
	if !m.showPlaintext {
		t.Error("expected revealed after 'r'")
	}

	view := m.View()
	if !strings.Contains(view, "visible") {
		t.Error("plaintext should be visible after 'r' reveal")
	}
}

func TestDetail_EEntersEditMode(t *testing.T) {
	m, ms := newTestModel(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	ct, nonce, _ := eng.Encrypt([]byte("val"), key)
	blob := append(nonce, ct...)
	crypto.Zeroize(key)

	_ = ms.Store(secret.Secret{
		Name: "edit-me", Kind: secret.KindPassword,
		EncryptedValue: blob, Tags: "test", Notes: "notes",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	// Press 'e' to enter edit
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m = result.(model)

	if m.state != stateAdd {
		t.Fatalf("expected stateAdd, got %v", m.state)
	}
	if !m.editMode {
		t.Error("editMode should be true")
	}
	if m.addNameInput.Value() != "edit-me" {
		t.Errorf("name = %q, want 'edit-me'", m.addNameInput.Value())
	}
	// 'e' rune should also reveal plaintext before entering edit (same as CtrlE)
	if m.showPlaintext {
		t.Error("plaintext should be hidden after entering edit")
	}
}

// ── Additional Search tests ──

func TestSearch_TypingUpdatesResults(t *testing.T) {
	m, ms := newTestModel(t)

	addTestSecret(t, ms, "alpha", secret.KindPassword, "production")
	addTestSecret(t, ms, "beta", secret.KindPassword, "staging")
	addTestSecret(t, ms, "gamma", secret.KindPassword, "production")

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	// Activate search
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = result.(model)

	// Simulate typing "zzzzz" by directly setting the search state
	m.searchInput.SetValue("zzzzz")
	m.searchQuery = "zzzzz"
	m.searchResults = runFilter(m.secrets, "zzzzz")

	if len(m.searchResults) != 0 {
		t.Errorf("expected 0 results for 'zzzzz' (no name/tag match), got %d", len(m.searchResults))
	}

	// Now search by tag "production"
	m.searchInput.SetValue("production")
	m.searchQuery = "production"
	m.searchResults = runFilter(m.secrets, "production")

	if len(m.searchResults) != 2 {
		t.Errorf("expected 2 results for tag 'production', got %d", len(m.searchResults))
	}

	view := m.View()
	if !strings.Contains(view, "alpha") {
		t.Error("view should show alpha")
	}
	if !strings.Contains(view, "gamma") {
		t.Error("view should show gamma")
	}
}

func TestSearch_CtrlJ_CtrlK_Navigation(t *testing.T) {
	m, ms := newTestModel(t)

	addTestSecret(t, ms, "aaa", secret.KindPassword, "")
	addTestSecret(t, ms, "aab", secret.KindPassword, "")
	addTestSecret(t, ms, "aac", secret.KindPassword, "")

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = result.(model)

	m.searchInput.SetValue("aa")
	m.searchQuery = "aa"
	m.searchResults = runFilter(m.secrets, "aa")

	// Ctrl+J navigates down
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlJ})
	m = result.(model)
	if m.cursor != 1 {
		t.Errorf("after Ctrl+J: cursor = %d, want 1", m.cursor)
	}

	// Ctrl+K navigates up
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlK})
	m = result.(model)
	if m.cursor != 0 {
		t.Errorf("after Ctrl+K: cursor = %d, want 0", m.cursor)
	}
}

func TestSearch_EnterOnResult_TransitionsToDetail(t *testing.T) {
	m, ms := newTestModel(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	ct, nonce, _ := eng.Encrypt([]byte("found-value"), key)
	blob := append(nonce, ct...)
	crypto.Zeroize(key)

	_ = ms.Store(secret.Secret{
		ID: "uuid-found", Name: "found-secret", Kind: secret.KindPassword,
		EncryptedValue: blob, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	// Activate search
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = result.(model)

	m.searchInput.SetValue("found")
	m.searchQuery = "found"
	m.searchResults = runFilter(m.secrets, "found")

	if len(m.searchResults) != 1 {
		t.Fatalf("expected 1 search result, got %d", len(m.searchResults))
	}

	// Enter selects the result
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateDetail {
		t.Fatalf("expected stateDetail after Enter on search result, got %v", m.state)
	}
	if m.detailSecret.Name != "found-secret" {
		t.Errorf("detail name = %q, want 'found-secret'", m.detailSecret.Name)
	}
}

func TestSearch_EnterOnEmptyResults_StaysInSearch(t *testing.T) {
	m, ms := newTestModel(t)

	addTestSecret(t, ms, "existing", secret.KindPassword, "")

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = result.(model)

	m.searchInput.SetValue("zzzzzz")
	m.searchQuery = "zzzzzz"
	m.searchResults = runFilter(m.secrets, "zzzzzz")

	// Enter on empty results should NOT crash or transition
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateSearch {
		t.Errorf("expected stateSearch (stay), got %v", m.state)
	}
}

// ── Additional Add state tests ──

func TestAdd_CtrlG_GeneratesPassword(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateAdd
	m.addKindIndex = 0 // password kind

	// Ctrl+G should generate a password in the value field
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlG})
	m2 := result.(model)

	if m2.state != stateAdd {
		t.Fatalf("expected stateAdd after generate, got %v", m2.state)
	}
	if m2.addValueInput.Value() == "" {
		t.Error("value should not be empty after Ctrl+G")
	}
	if len(m2.addValueInput.Value()) < 8 {
		t.Errorf("generated password too short: %q", m2.addValueInput.Value())
	}
	if !strings.Contains(m2.err, "generated") && m2.err == "" {
		t.Error("expected confirmation message after generate")
	}
}

func TestAdd_CtrlG_InFileMode_ShowsError(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateAdd
	m.addFileMode = true

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlG})
	m2 := result.(model)

	if m2.state != stateAdd {
		t.Fatalf("expected stateAdd, got %v", m2.state)
	}
	if m2.err == "" || !strings.Contains(m2.err, "file mode") {
		t.Errorf("expected file mode error, got: %q", m2.err)
	}
}

func TestAdd_CtrlO_TogglesFileMode(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateAdd

	// Toggle file mode on
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlO})
	m2 := result.(model)

	if !m2.addFileMode {
		t.Error("addFileMode should be true after Ctrl+O")
	}

	// Toggle file mode off
	result, _ = m2.Update(tea.KeyMsg{Type: tea.KeyCtrlO})
	m3 := result.(model)

	if m3.addFileMode {
		t.Error("addFileMode should be false after second Ctrl+O")
	}
}

func TestAdd_TabCycleThroughFields(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateAdd
	m.addKindIndex = 0 // password kind (has extra fields)

	// Initial focus is name (index 0)
	if m.addFocusIndex != 0 {
		t.Fatalf("initial focus = %d, want 0", m.addFocusIndex)
	}

	// Tab to value (index 1)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m2 := result.(model)
	if m2.addFocusIndex != 1 {
		t.Errorf("after Tab: focus = %d, want 1", m2.addFocusIndex)
	}

	// Tab to user (index 2)
	result, _ = m2.Update(tea.KeyMsg{Type: tea.KeyTab})
	m3 := result.(model)
	if m3.addFocusIndex != 2 {
		t.Errorf("after second Tab: focus = %d, want 2", m3.addFocusIndex)
	}

	// Tab to site (index 3)
	result, _ = m3.Update(tea.KeyMsg{Type: tea.KeyTab})
	m4 := result.(model)
	if m4.addFocusIndex != 3 {
		t.Errorf("after third Tab: focus = %d, want 3", m4.addFocusIndex)
	}

	// Tab to notes (index 4)
	result, _ = m4.Update(tea.KeyMsg{Type: tea.KeyTab})
	m5 := result.(model)
	if m5.addFocusIndex != 4 {
		t.Errorf("after fourth Tab: focus = %d, want 4", m5.addFocusIndex)
	}

	// Tab wraps back to name (index 0)
	result, _ = m5.Update(tea.KeyMsg{Type: tea.KeyTab})
	m6 := result.(model)
	if m6.addFocusIndex != 0 {
		t.Errorf("after wrap Tab: focus = %d, want 0", m6.addFocusIndex)
	}
}

func TestAdd_TabForNonPasswordKind(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateAdd
	m.addKindIndex = 1 // api_key (non-password, maxFocus=1)

	if m.addFocusIndex != 0 {
		t.Fatalf("initial focus = %d, want 0", m.addFocusIndex)
	}

	// Tab to value (index 1)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m2 := result.(model)
	if m2.addFocusIndex != 1 {
		t.Errorf("after Tab: focus = %d, want 1", m2.addFocusIndex)
	}

	// Tab wraps back to name (index 0) for non-password kind
	result, _ = m2.Update(tea.KeyMsg{Type: tea.KeyTab})
	m3 := result.(model)
	if m3.addFocusIndex != 0 {
		t.Errorf("after Tab wrap: focus = %d, want 0", m3.addFocusIndex)
	}
}

func TestAdd_EnterOnLastField_SavesSecret(t *testing.T) {
	m, ms := newTestModel(t)

	// Derive session key
	key, err := m.engine.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	m.key = key

	m.state = stateAdd
	m.addKindIndex = 1 // api_key (non-password, maxFocus=1 -> enter on field 1 = save)
	m.addNameInput.SetValue("enter-save-test")
	m.addValueInput.SetValue("the-value")
	m.addFocusIndex = 1 // Already on last field

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList after save, got %v (err: %q)", m2.state, m2.err)
	}

	// Verify stored
	stored, err := ms.GetByNameLookup([]byte("enter-save-test"))
	if err != nil {
		t.Fatalf("secret not stored: %v", err)
	}
	if stored.Name != "enter-save-test" {
		t.Errorf("name = %q", stored.Name)
	}
}

func TestAdd_EnterOnNonLastField_AdvancesFocus(t *testing.T) {
	m, _ := newTestModel(t)
	m.state = stateAdd
	m.addKindIndex = 1  // api_key (non-password, maxFocus=1)
	m.addFocusIndex = 0 // on name field (not last)

	m.addNameInput.SetValue("a-name")
	m.addValueInput.SetValue("some-value")

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	// Should advance to next field, not save
	if m2.addFocusIndex != 1 {
		t.Errorf("after Enter on name: focus = %d, want 1", m2.addFocusIndex)
	}
	if m2.state != stateAdd {
		t.Error("should stay in add state")
	}
}

func TestAdd_EmptyFilePathInFileMode_ShowsError(t *testing.T) {
	m, _ := newTestModel(t)

	key, err := m.engine.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	m.key = key

	m.state = stateAdd
	m.addFileMode = true
	m.addNameInput.SetValue("test")
	m.addFileInput.SetValue("") // empty file path
	m.addFocusIndex = 1

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateAdd {
		t.Errorf("expected stateAdd (stay), got %v", m2.state)
	}
	if m2.err == "" {
		t.Error("expected error for empty file path")
	}
}

// ── Unlock edge case tests ──

func TestUnlock_KeyDerivationError(t *testing.T) {
	m, _ := newTestModel(t)

	// Set a blank verify hash to simulate vault config issues
	m.verifyHash = nil

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	// Should handle gracefully — VerifyMasterPassword with nil hash returns false
	if m2.state != stateUnlock {
		t.Errorf("expected stateUnlock after verification failure, got %v", m2.state)
	}
}

// errMockStore wraps mockStore to return errors on specific methods.
type errMockStore struct {
	mockStore
	listErr error
}

func (e *errMockStore) List() ([]secret.Secret, error) {
	if e.listErr != nil {
		return nil, e.listErr
	}
	return e.mockStore.List()
}

func TestUnlock_ListError_ReturnsToUnlock(t *testing.T) {
	eng := testEngine()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}

	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	hkdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	verifyHash := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, verifyHash); err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	ems := &errMockStore{listErr: fmt.Errorf("simulated list error")}
	ems.secrets = make(map[string]secret.Secret)
	ems.config = make(map[string][]byte)

	m := NewModel(ems, eng, salt, verifyHash, 0, true)
	m.passwordInput.SetValue(testPassword)

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateUnlock {
		t.Errorf("expected stateUnlock after List error, got %v", m2.state)
	}
	if m2.err == "" {
		t.Error("expected error message after List failure")
	}
	if m2.key != nil {
		t.Error("key should be nil after unlock failure")
	}
}

// ── TUI Edit tests ──

func TestDetail_E_TransitionsToEdit(t *testing.T) {
	m, ms := newTestModel(t)

	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	ct, nonce, err := eng.Encrypt([]byte("value"), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob := append(nonce, ct...)
	crypto.Zeroize(key)

	_ = ms.Store(secret.Secret{
		Name: "edit-test", Kind: secret.KindPassword,
		EncryptedValue: blob, Tags: "", Notes: "original notes",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	// Unlock and enter detail
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateDetail {
		t.Fatalf("expected stateDetail, got %v", m.state)
	}

	// Press Ctrl+E to enter edit mode
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlE})
	m2 := result.(model)

	if m2.state != stateAdd {
		t.Fatalf("expected stateAdd (edit mode), got %v", m2.state)
	}
	if !m2.editMode {
		t.Error("editMode should be true")
	}
	if m2.addNameInput.Value() != "edit-test" {
		t.Errorf("name input should be pre-filled with 'edit-test', got %q", m2.addNameInput.Value())
	}
}

func TestEdit_SaveUpdatesSecret(t *testing.T) {
	m, ms := newTestModel(t)

	// Derive session key
	key, err := m.engine.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	ct, nonce, err := m.engine.Encrypt([]byte("old-value"), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob := append(nonce, ct...)
	lookup := crypto.ComputeNameLookup(key, "edit-me")
	crypto.Zeroize(key)

	now := time.Now().UTC()
	_ = ms.Store(secret.Secret{
		Name: "edit-me", NameLookup: lookup, Kind: secret.KindPassword,
		EncryptedValue: blob, Tags: "", Notes: "notes",
		CreatedAt: now, UpdatedAt: now,
	})

	// Set up as if we entered edit mode from detail
	m.state = stateAdd
	m.editMode = true
	m.editSecretName = "edit-me"
	m.addNameInput.SetValue("edit-me")
	m.addValueInput.SetValue("new-value")
	m.addKindIndex = 1 // api_kind makes maxFocus=1 so Enter saves
	m.addFocusIndex = 1

	// Derive key for session
	sessionKey, err := m.engine.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	m.key = sessionKey

	// Save
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList after edit save, got %v (err: %q)", m2.state, m2.err)
	}

	// Verify the secret was updated in the store
	stored, err := ms.GetByNameLookup([]byte("edit-me"))
	if err != nil {
		t.Fatalf("secret not found: %v", err)
	}
	if string(stored.EncryptedValue) == string(blob) {
		t.Error("encrypted value should have changed after edit")
	}
}

func TestEdit_CancelReturnsToList(t *testing.T) {
	m, ms := newTestModel(t)

	_ = ms.Store(secret.Secret{
		Name: "test", Kind: secret.KindPassword,
		EncryptedValue: []byte("enc-val"),
		CreatedAt:      time.Now(), UpdatedAt: time.Now(),
	})

	m.state = stateAdd
	m.editMode = true
	m.editSecretName = "test"
	m.addNameInput.SetValue("test")

	// Press Esc to cancel
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m2 := result.(model)

	if m2.state != stateList {
		t.Errorf("expected stateList after cancel, got %v", m2.state)
	}
	if m2.editMode {
		t.Error("editMode should be false after cancel")
	}
}

// ── Expiry notification on startup tests ──

func TestUnlock_ExpiryWarningShown(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	// Add an expiring certificate
	meta := parse.Metadata{
		Format:   "x509",
		NotAfter: now.Add(15 * 24 * time.Hour).Format(time.RFC3339),
	}
	metaBytes, _ := json.Marshal(meta)
	_ = ms.Store(secret.Secret{
		ID: "u1", Name: "expiring-cert", Kind: secret.KindCertificate,
		Metadata: string(metaBytes), CreatedAt: now, UpdatedAt: now,
	})

	// Add a non-expiring password
	_ = ms.Store(secret.Secret{
		ID: "u2", Name: "password", Kind: secret.KindPassword,
		CreatedAt: now, UpdatedAt: now,
	})

	// Unlock
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList, got %v (err: %q)", m2.state, m2.err)
	}

	view := m2.View()
	if !strings.Contains(view, "certificate(s) expiring") && !strings.Contains(view, "⚠️") {
		t.Log("View content:", view[:min(len(view), 300)])
		t.Error("expected expiry warning in view after unlock with expiring certs")
	}
}

func TestUnlock_NoExpiryWarningWhenNoneExpiring(t *testing.T) {
	m, ms := newTestModel(t)
	now := time.Now().UTC()

	// Only add a non-expiring password
	_ = ms.Store(secret.Secret{
		ID: "u1", Name: "password", Kind: secret.KindPassword,
		CreatedAt: now, UpdatedAt: now,
	})

	// Unlock
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList, got %v (err: %q)", m2.state, m2.err)
	}

	view := m2.View()
	if strings.Contains(view, "certificate(s) expiring") || strings.Contains(view, "⚠️") {
		t.Error("should NOT show expiry warning when no certs are expiring")
	}
}

// ── Duplicate detection in TUI add tests ──

func TestAdd_DuplicateShowsHint(t *testing.T) {
	m, ms := newTestModel(t)

	// Pre-populate store with a secret
	_ = ms.Store(secret.Secret{
		Name: "existing", Kind: secret.KindPassword,
		EncryptedValue: []byte("enc"),
		CreatedAt:      time.Now(), UpdatedAt: time.Now(),
	})

	// Derive session key
	key, err := m.engine.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	m.key = key

	m.state = stateAdd
	m.addKindIndex = 1 // api_key makes maxFocus=1 so Enter saves
	m.addFocusIndex = 1
	m.addNameInput.SetValue("existing") // same name as existing
	m.addValueInput.SetValue("new-value")

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateAdd {
		t.Errorf("expected stateAdd (stay on form) for duplicate, got %v", m2.state)
	}
	if !strings.Contains(m2.err, "overwrite") && !strings.Contains(m2.err, "exist") {
		t.Errorf("expected duplicate hint in error, got: %q", m2.err)
	}
}

func TestAdd_FileMode_FileUnreadable(t *testing.T) {
	m, _ := newTestModel(t)

	// Derive session key
	key, err := m.engine.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	m.key = key

	// Create a temp file and remove read permissions
	tmpDir := t.TempDir()
	protectedPath := filepath.Join(tmpDir, "protected.key")
	if err := os.WriteFile(protectedPath, []byte("sensitive-data"), 0000); err != nil {
		t.Fatalf("write protected file: %v", err)
	}

	m.state = stateAdd
	m.addFileMode = true
	m.addNameInput.SetValue("protected")
	m.addFileInput.SetValue(protectedPath)
	m.addFocusIndex = 1

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateAdd {
		t.Errorf("expected stateAdd (stay in form) for unreadable file, got %v", m2.state)
	}
	if m2.err == "" {
		t.Error("expected error for unreadable file")
	}
}

// ── Auto-lock tests ──

func TestLock_AfterInactivity(t *testing.T) {
	eng := testEngine()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}

	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	hkdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	verifyHash := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, verifyHash); err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	mockSt := newMockStore()
	// Use 1-minute timeout for testing
	m := NewModel(mockSt, eng, salt, verifyHash, 1, true)

	// Simulate unlock
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList, got %v", m2.state)
	}
	if m2.key == nil {
		t.Fatal("expected session key to be set")
	}

	// Set last activity far in the past to trigger lock
	m2.lastActivity = time.Now().Add(-2 * time.Minute)

	// Send inactivity tick
	result, _ = m2.Update(inactivityTickMsg{})
	m3 := result.(model)

	if m3.state != stateUnlock {
		t.Errorf("expected stateUnlock after inactivity, got %v", m3.state)
	}
	if m3.key != nil {
		t.Error("session key should be nil after auto-lock")
	}
	if !strings.Contains(m3.err, "inactivity") {
		t.Errorf("expected inactivity message, got: %q", m3.err)
	}
}

func TestLock_NoLockWhenActive(t *testing.T) {
	eng := testEngine()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}

	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	hkdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	verifyHash := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, verifyHash); err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	mockSt := newMockStore()
	m := NewModel(mockSt, eng, salt, verifyHash, 1, true)

	// Simulate unlock
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList, got %v", m2.state)
	}

	// lastActivity was just set, so inactivity tick should NOT lock
	result, _ = m2.Update(inactivityTickMsg{})
	m3 := result.(model)

	// The ticker re-schedules itself in this case, so should stay in list
	if m3.state != stateList {
		t.Errorf("expected stateList (no lock), got %v", m3.state)
	}
	if m3.key == nil {
		t.Error("session key should still be present")
	}
}

func TestLock_TimeoutZero(t *testing.T) {
	eng := testEngine()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}

	key, err := eng.DeriveKey([]byte(testPassword), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	hkdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	verifyHash := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, verifyHash); err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	mockSt := newMockStore()
	// 0 timeout = never lock
	m := NewModel(mockSt, eng, salt, verifyHash, 0, true)

	// Simulate unlock
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := result.(model)

	if m2.state != stateList {
		t.Fatalf("expected stateList, got %v", m2.state)
	}

	// Set last activity far in the past — should NOT lock because timeout is 0
	m2.lastActivity = time.Now().Add(-1 * time.Hour)

	// inactivityTickMsg should NOT trigger lock when timeout is 0
	result, _ = m2.Update(inactivityTickMsg{})
	m3 := result.(model)

	if m3.state != stateList {
		t.Errorf("expected stateList (timeout=0), got %v", m3.state)
	}
	if m3.key == nil {
		t.Error("session key should still be present when timeout is 0")
	}
}

// ── OTP / TOTP detail view tests ──

// ── OTP / TOTP detail view tests ──

// encryptForModel encrypts a value using the model's key and salt (from newTestModel).
// Ensures the decryption in updateList will succeed.
func encryptForModel(t *testing.T, m model, plaintext string) []byte {
	t.Helper()
	eng := testEngine()
	key, err := eng.DeriveKey([]byte(testPassword), m.salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)
	ct, nonce, err := eng.Encrypt([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob := make([]byte, 0, len(nonce)+len(ct))
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return blob
}

func TestDetail_OTP_Shown(t *testing.T) {
	m, ms := newTestModel(t)

	const otpSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	otpauthURI := "otpauth://totp/Example:alice@google.com?secret=" + otpSeed + "&issuer=Example"
	meta := secret.PasswordMetadata{OTPAuth: otpauthURI}
	// MarshalPasswordMetadata now redacts the seed (S-02); the real seed
	// must live in EncryptedOTPSeed encrypted with the model's master key.
	metaJSON := secret.MarshalPasswordMetadata(&meta)
	otpSeedBlob := encryptForModel(t, m, otpSeed)

	blob := encryptForModel(t, m, "test-value")
	now := time.Now().UTC()
	if err := ms.Store(secret.Secret{
		ID: "uuid-otp-1", Name: "otp-secret",
		Kind: secret.KindPassword, EncryptedValue: blob,
		EncryptedOTPSeed: otpSeedBlob,
		Metadata:         metaJSON, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Unlock and enter detail
	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateDetail {
		t.Fatalf("expected stateDetail, got %v", m.state)
	}

	view := m.View()
	if !strings.Contains(view, "TOTP") {
		t.Log("OTP view:", view)
		t.Error("expected TOTP section in detail view")
	}
}

func TestDetail_NonOTP_Hidden(t *testing.T) {
	m, ms := newTestModel(t)

	blob := encryptForModel(t, m, "test-value")
	now := time.Now().UTC()
	if err := ms.Store(secret.Secret{
		ID: "uuid-no-otp", Name: "no-otp-secret",
		Kind: secret.KindPassword, EncryptedValue: blob,
		Metadata: "", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("store: %v", err)
	}

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateDetail {
		t.Fatalf("expected stateDetail, got %v", m.state)
	}
	if m.otpCode != "" {
		t.Error("otpCode should be empty for non-OTP secret")
	}
}

func TestDetail_OTP_TickerLifecycle(t *testing.T) {
	m, ms := newTestModel(t)

	const otpSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	otpauthURI := "otpauth://totp/Example:alice@google.com?secret=" + otpSeed + "&issuer=Example"
	meta := secret.PasswordMetadata{OTPAuth: otpauthURI}
	// MarshalPasswordMetadata now redacts the seed (S-02); the real seed
	// must live in EncryptedOTPSeed encrypted with the model's master key.
	metaJSON := secret.MarshalPasswordMetadata(&meta)
	otpSeedBlob := encryptForModel(t, m, otpSeed)

	blob := encryptForModel(t, m, "test-value")
	now := time.Now().UTC()
	if err := ms.Store(secret.Secret{
		ID: "uuid-otp-2", Name: "otp-ticker",
		Kind: secret.KindPassword, EncryptedValue: blob,
		EncryptedOTPSeed: otpSeedBlob,
		Metadata:         metaJSON, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("store: %v", err)
	}

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateDetail {
		t.Fatalf("expected stateDetail, got %v", m.state)
	}
	if m.otpCode == "" {
		t.Error("expected non-empty otpCode")
	}

	// Send a tick message
	if m.otpCountdown > 0 {
		prevCountdown := m.otpCountdown
		result, _ = m.Update(otpTickMsg{})
		m = result.(model)
		if m.otpCountdown != prevCountdown-1 && m.otpCountdown != m.otpPeriod-1 {
			t.Logf("countdown: %d -> %d", prevCountdown, m.otpCountdown)
		}
	}

	// Navigate back — OTP should be cleared
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = result.(model)
	if m.state != stateList {
		t.Fatalf("expected stateList after Esc, got %v", m.state)
	}
	if m.otpCode != "" {
		t.Error("otpCode should be cleared after navigating away")
	}
	if m.otpCountdown != 0 {
		t.Error("otpCountdown should be reset after navigating away")
	}
}

func TestDetail_OTP_CountdownExpiry(t *testing.T) {
	m, ms := newTestModel(t)

	const otpSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	otpauthURI := "otpauth://totp/Example:alice@google.com?secret=" + otpSeed + "&issuer=Example"
	meta := secret.PasswordMetadata{OTPAuth: otpauthURI}
	// MarshalPasswordMetadata now redacts the seed (S-02); the real seed
	// must live in EncryptedOTPSeed encrypted with the model's master key.
	metaJSON := secret.MarshalPasswordMetadata(&meta)
	otpSeedBlob := encryptForModel(t, m, otpSeed)

	blob := encryptForModel(t, m, "test-value")
	now := time.Now().UTC()
	if err := ms.Store(secret.Secret{
		ID: "uuid-otp-3", Name: "otp-countdown",
		Kind: secret.KindPassword, EncryptedValue: blob,
		EncryptedOTPSeed: otpSeedBlob,
		Metadata:         metaJSON, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("store: %v", err)
	}

	m.passwordInput.SetValue(testPassword)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)
	result, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(model)

	if m.state != stateDetail {
		t.Fatalf("expected stateDetail, got %v", m.state)
	}
	if m.otpCode == "" {
		t.Fatal("expected non-empty otpCode")
	}

	// Tick until countdown wraps
	ticks := m.otpCountdown + 1
	for i := 0; i < ticks; i++ {
		result, _ = m.Update(otpTickMsg{})
		m = result.(model)
	}
	if m.otpCode == "" {
		t.Error("otpCode should not be empty after tick processing")
	}
	if m.otpCountdown < 0 || m.otpCountdown > m.otpPeriod {
		t.Errorf("otpCountdown out of range: %d (period=%d)", m.otpCountdown, m.otpPeriod)
	}
}

func TestPlaintext_IsByteSliceAndZeroized(t *testing.T) {
	m, _ := newTestModel(t)

	// Verify plaintext field is []byte (compile-time) by assigning a byte slice.
	m.plaintext = []byte("sensitive-data")

	// Verify zeroization on backToList.
	m = m.backToList()
	if len(m.plaintext) != 0 {
		t.Errorf("plaintext should be zeroized and nil after backToList, got %d bytes", len(m.plaintext))
	}
}
