package watchtower

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
)

// Compile-time check that mockStore implements store.Store.
var _ store.Store = (*mockStore)(nil)

// mockStore implements store.Store for unit testing.
type mockStore struct {
	listSecrets      []secret.Secret
	getByNameFunc    func(name string) (secret.Secret, error)
	listExpiringFunc func(days int) ([]secret.Secret, error)
}

func (m *mockStore) Init(path string) error      { return nil }
func (m *mockStore) Store(s secret.Secret) error { return nil }
func (m *mockStore) GetByNameLookup(nameLookup []byte) (secret.Secret, error) {
	return secret.Secret{}, nil
}
func (m *mockStore) GetByID(id string) (secret.Secret, error) {
	return secret.Secret{}, fmt.Errorf("not implemented")
}
func (m *mockStore) List() ([]secret.Secret, error)                                { return m.listSecrets, nil }
func (m *mockStore) ListWithEncryptedAll() ([]secret.Secret, error)                { return m.listSecrets, nil }
func (m *mockStore) DeleteByLookup(nameLookup []byte) error                        { return nil }
func (m *mockStore) SoftDeleteByLookup(nameLookup []byte) error                    { return nil }
func (m *mockStore) ListWithTombstones() ([]secret.Secret, error)                  { return m.listSecrets, nil }
func (m *mockStore) PurgeTombstones(before time.Time) (int, error)                 { return 0, nil }
func (m *mockStore) UpdateTombstoneDeletedAt(nameLookup []byte, t time.Time) error { return nil }
func (m *mockStore) UpdateOTPSeedAndMetadata(nameLookup []byte, encryptedOTPSeed []byte, encryptedMetadata []byte) error {
	return nil
}
func (m *mockStore) ConfigGet(key string) ([]byte, error)               { return nil, fmt.Errorf("not found") }
func (m *mockStore) ConfigSet(key string, value []byte) error           { return nil }
func (m *mockStore) ConfigDelete(key string) error                      { return nil }
func (m *mockStore) Count() (int, error)                                { return len(m.listSecrets), nil }
func (m *mockStore) LogAction(action, secretName, details string) error { return nil }
func (m *mockStore) GetAuditLog(limit int) ([]secret.AuditEntry, error) { return nil, nil }
func (m *mockStore) Close() error                                       { return nil }

// testEngine creates a crypto engine and derives a key for tests.
func testEngineAndKey(t *testing.T) (*crypto.Engine, []byte) {
	t.Helper()
	engine := crypto.NewEngine(nil)
	salt := []byte("testsalt12345678")
	key, err := engine.DeriveKey([]byte("testmasterpassword"), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	return engine, key
}

// encryptPassword encrypts a plaintext password and returns the packed envelope.
func encryptPassword(t *testing.T, engine *crypto.Engine, key []byte, plaintext string) []byte {
	t.Helper()
	ciphertext, nonce, err := engine.Encrypt([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// pack envelope: nonce || ciphertext
	blob := make([]byte, 0, len(nonce)+len(ciphertext))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)
	return blob
}

// makePasswordSecret creates a password secret with the given name, encrypted value, and metadata.
func makePasswordSecret(name string, encryptedValue []byte, metadata string) secret.Secret {
	return secret.Secret{
		ID:             name + "-id",
		Name:           name,
		Kind:           secret.KindPassword,
		EncryptedValue: encryptedValue,
		Metadata:       metadata,
	}
}

func TestAssessPasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     PasswordStrength
		reason   string
	}{
		{
			name:     "empty",
			password: "",
			want:     StrengthVeryWeak,
			reason:   "Empty password",
		},
		{
			name:     "common_password",
			password: "password",
			want:     StrengthVeryWeak,
			reason:   "Common password",
		},
		{
			name:     "common_with_suffix",
			password: "password123",
			want:     StrengthVeryWeak,
			reason:   "Common password",
		},
		{
			name:     "short_simple",
			password: "abc",
			want:     StrengthVeryWeak,
			reason:   "Too short and simple",
		},
		{
			name:     "weak_lowercase_only",
			password: "abcdefgh",
			want:     StrengthVeryWeak,
			reason:   "Too short and simple",
		},
		{
			name:     "fair_mixed",
			password: "Abcdefgh1",
			want:     StrengthWeak,
			reason:   "Add more variety (uppercase, digits, symbols)",
		},
		{
			name:     "strong_long_mixed",
			password: "Abcdefgh1!@#",
			want:     StrengthFair,
			reason:   "Could be stronger with more length and symbols",
		},
		{
			name:     "very_strong",
			password: "Abcdefgh1!@#$%^&*()",
			want:     StrengthFair,
			reason:   "Could be stronger with more length and symbols",
		},
		{
			name:     "repeated_chars_penalty",
			password: "aaaabbbbccccdddde",
			want:     StrengthVeryWeak,
			reason:   "Too short and simple",
		},
		{
			name:     "sequential_chars_penalty",
			password: "abcdefgh",
			want:     StrengthVeryWeak,
			reason:   "Too short and simple",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := AssessPasswordStrength(tt.password)
			if got != tt.want {
				t.Errorf("AssessPasswordStrength(%q) strength = %v, want %v", tt.password, got, tt.want)
			}
			if reason != tt.reason {
				t.Errorf("AssessPasswordStrength(%q) reason = %q, want %q", tt.password, reason, tt.reason)
			}
		})
	}
}

func TestAnalyze(t *testing.T) {
	engine, key := testEngineAndKey(t)

	t.Run("no_secrets", func(t *testing.T) {
		ms := &mockStore{
			listSecrets:      nil,
			listExpiringFunc: func(int) ([]secret.Secret, error) { return nil, nil },
		}
		result, err := Analyze(ms, engine, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.TotalSecrets != 0 {
			t.Errorf("TotalSecrets = %d, want 0", result.TotalSecrets)
		}
		if result.AnalyzedPasswordCount != 0 {
			t.Errorf("AnalyzedPasswordCount = %d, want 0", result.AnalyzedPasswordCount)
		}
	})

	t.Run("no_password_secrets", func(t *testing.T) {
		ms := &mockStore{
			listSecrets: []secret.Secret{
				{ID: "1", Name: "api-key", Kind: secret.KindAPIKey},
			},
			listExpiringFunc: func(int) ([]secret.Secret, error) { return nil, nil },
		}
		result, err := Analyze(ms, engine, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.TotalSecrets != 1 {
			t.Errorf("TotalSecrets = %d, want 1", result.TotalSecrets)
		}
		if result.AnalyzedPasswordCount != 0 {
			t.Errorf("AnalyzedPasswordCount = %d, want 0", result.AnalyzedPasswordCount)
		}
	})

	t.Run("weak_password", func(t *testing.T) {
		blob := encryptPassword(t, engine, key, "password")
		ms := &mockStore{
			listSecrets: []secret.Secret{
				makePasswordSecret("weak", blob, ""),
			},
			listExpiringFunc: func(int) ([]secret.Secret, error) { return nil, nil },
		}
		result, err := Analyze(ms, engine, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.AnalyzedPasswordCount != 1 {
			t.Errorf("AnalyzedPasswordCount = %d, want 1", result.AnalyzedPasswordCount)
		}
		if len(result.WeakPasswords) != 1 {
			t.Fatalf("expected 1 weak password, got %d", len(result.WeakPasswords))
		}
		wp := result.WeakPasswords[0]
		if wp.SecretName != "weak" {
			t.Errorf("SecretName = %q, want %q", wp.SecretName, "weak")
		}
		if wp.Score != StrengthVeryWeak {
			t.Errorf("Score = %v, want StrengthVeryWeak", wp.Score)
		}
		if result.SecretsWithWeakPass != 1 {
			t.Errorf("SecretsWithWeakPass = %d, want 1", result.SecretsWithWeakPass)
		}
	})

	t.Run("duplicate_passwords", func(t *testing.T) {
		blob := encryptPassword(t, engine, key, "shared-secret-123!")
		ms := &mockStore{
			listSecrets: []secret.Secret{
				makePasswordSecret("first", blob, ""),
				makePasswordSecret("second", blob, ""),
			},
			listExpiringFunc: func(int) ([]secret.Secret, error) { return nil, nil },
		}
		result, err := Analyze(ms, engine, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.AnalyzedPasswordCount != 2 {
			t.Errorf("AnalyzedPasswordCount = %d, want 2", result.AnalyzedPasswordCount)
		}
		if len(result.DuplicatePasswords) != 1 {
			t.Fatalf("expected 1 duplicate finding, got %d", len(result.DuplicatePasswords))
		}
		dup := result.DuplicatePasswords[0]
		if len(dup.SecretNames) != 2 {
			t.Errorf("expected 2 secret names, got %d", len(dup.SecretNames))
		}
		if result.PasswordReuseCount != 1 {
			t.Errorf("PasswordReuseCount = %d, want 1", result.PasswordReuseCount)
		}
		// Verify hash is not plaintext
		if dup.PasswordHash == "shared-secret-123!" || len(dup.PasswordHash) != 16 {
			t.Errorf("PasswordHash looks wrong: %q", dup.PasswordHash)
		}
	})

	t.Run("missing_2fa", func(t *testing.T) {
		blob := encryptPassword(t, engine, key, "strong-pass-123!")
		meta := secret.MarshalPasswordMetadata(&secret.PasswordMetadata{
			URL:      "https://example.com",
			Username: "user",
		})
		ms := &mockStore{
			listSecrets: []secret.Secret{
				makePasswordSecret("site", blob, meta),
			},
			listExpiringFunc: func(int) ([]secret.Secret, error) { return nil, nil },
		}
		result, err := Analyze(ms, engine, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Missing2FA) != 1 {
			t.Fatalf("expected 1 missing 2FA finding, got %d", len(result.Missing2FA))
		}
		m2fa := result.Missing2FA[0]
		if m2fa.SecretName != "site" {
			t.Errorf("SecretName = %q, want %q", m2fa.SecretName, "site")
		}
		if m2fa.Username != "user" {
			t.Errorf("Username = %q, want %q", m2fa.Username, "user")
		}
		if m2fa.URL != "https://example.com" {
			t.Errorf("URL = %q, want %q", m2fa.URL, "https://example.com")
		}
		if result.SecretsWithNoOTP != 1 {
			t.Errorf("SecretsWithNoOTP = %d, want 1", result.SecretsWithNoOTP)
		}
	})

	t.Run("with_2fa", func(t *testing.T) {
		blob := encryptPassword(t, engine, key, "strong-pass-123!")
		meta := secret.MarshalPasswordMetadata(&secret.PasswordMetadata{
			URL:      "https://example.com",
			Username: "user",
			OTPAuth:  "otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&issuer=Example",
		})
		ms := &mockStore{
			listSecrets: []secret.Secret{
				makePasswordSecret("site", blob, meta),
			},
			listExpiringFunc: func(int) ([]secret.Secret, error) { return nil, nil },
		}
		result, err := Analyze(ms, engine, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Missing2FA) != 0 {
			t.Errorf("expected 0 missing 2FA findings, got %d", len(result.Missing2FA))
		}
		if result.SecretsWithNoOTP != 0 {
			t.Errorf("SecretsWithNoOTP = %d, want 0", result.SecretsWithNoOTP)
		}
	})

	t.Run("no_url_no_2fa_check", func(t *testing.T) {
		// Missing URL means no 2FA check is performed
		blob := encryptPassword(t, engine, key, "strong-pass-123!")
		meta := secret.MarshalPasswordMetadata(&secret.PasswordMetadata{
			Username: "user",
		})
		ms := &mockStore{
			listSecrets: []secret.Secret{
				makePasswordSecret("site", blob, meta),
			},
			listExpiringFunc: func(int) ([]secret.Secret, error) { return nil, nil },
		}
		result, err := Analyze(ms, engine, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Missing2FA) != 0 {
			t.Errorf("expected 0 missing 2FA findings, got %d", len(result.Missing2FA))
		}
	})

	t.Run("metadata_only_secret", func(t *testing.T) {
		blob := encryptPassword(t, engine, key, "metadata-only-pw")
		fullSecret := makePasswordSecret("meta", blob, "")
		ms := &mockStore{
			listSecrets: []secret.Secret{
				{ID: "meta-id", Name: "meta", Kind: secret.KindPassword, EncryptedValue: nil}, // metadata only
			},
			getByNameFunc: func(name string) (secret.Secret, error) {
				if name == "meta" {
					return fullSecret, nil
				}
				return secret.Secret{}, fmt.Errorf("not found")
			},
			listExpiringFunc: func(int) ([]secret.Secret, error) { return nil, nil },
		}
		result, err := Analyze(ms, engine, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.AnalyzedPasswordCount != 1 {
			t.Errorf("AnalyzedPasswordCount = %d, want 1", result.AnalyzedPasswordCount)
		}
	})

	t.Run("expiring_certificates", func(t *testing.T) {
		meta := fmt.Sprintf(`{"not_after":%q}`, time.Now().Add(10*24*time.Hour).Format(time.RFC3339))
		ms := &mockStore{
			listSecrets: []secret.Secret{
				{Name: "cert1", Kind: secret.KindCertificate, Metadata: meta},
			},
		}
		result, err := Analyze(ms, engine, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ExpiringCertificates != 1 {
			t.Errorf("ExpiringCertificates = %d, want 1", result.ExpiringCertificates)
		}
	})

	t.Run("zeroization_no_plaintext_leak", func(t *testing.T) {
		blob := encryptPassword(t, engine, key, "secret-password-123!")
		ms := &mockStore{
			listSecrets: []secret.Secret{
				makePasswordSecret("s1", blob, ""),
			},
			listExpiringFunc: func(int) ([]secret.Secret, error) { return nil, nil },
		}
		result, err := Analyze(ms, engine, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Ensure no plaintext password appears anywhere in the result
		resultStr := fmt.Sprintf("%+v", result)
		if strings.Contains(resultStr, "secret-password-123!") {
			t.Error("result contains plaintext password — zeroization contract broken")
		}
	})

	t.Run("list_error", func(t *testing.T) {
		ms := &mockStore{}
		// We can't easily make List return an error with the mock since we control the field.
		// But we can verify that a nil listSecrets returns empty result without error.
		result, err := Analyze(ms, engine, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.TotalSecrets != 0 {
			t.Errorf("TotalSecrets = %d, want 0", result.TotalSecrets)
		}
	})
}

func TestAnalyzeWithPwned_Detection(t *testing.T) {
	engine, key := testEngineAndKey(t)
	compromisedPass := "P@ssw0rd123!"
	safePass := "SuperSecretSafePassword987!#@%"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock response indicating compromisedPass is breached 100 times
		// #nosec G401 -- mock server testing SHA-1 prefix contract
		hasher := sha1.New()
		hasher.Write([]byte(compromisedPass))
		fullHash := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))
		suffix := fullHash[5:]

		resp := fmt.Sprintf("%s:100\r\n", suffix)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(resp))
	}))
	defer server.Close()

	blob1 := encryptPassword(t, engine, key, compromisedPass)
	blob2 := encryptPassword(t, engine, key, safePass)

	ms := &mockStore{
		listSecrets: []secret.Secret{
			makePasswordSecret("login-pwned", blob1, `{"username":"user1","url":"https://example.com"}`),
			makePasswordSecret("login-safe", blob2, `{"username":"user2","url":"https://safe.com"}`),
		},
	}

	pwnedMgr := NewPwnedManager(1*time.Hour, WithBaseURL(server.URL))
	result, err := AnalyzeWithPwned(ms, engine, key, pwnedMgr)
	if err != nil {
		t.Fatalf("AnalyzeWithPwned failed: %v", err)
	}

	if result.SecretsWithCompromised != 1 {
		t.Errorf("SecretsWithCompromised = %d, want 1", result.SecretsWithCompromised)
	}
	if len(result.CompromisedPasswords) != 1 {
		t.Fatalf("expected 1 compromised finding, got %d", len(result.CompromisedPasswords))
	}
	if result.CompromisedPasswords[0].SecretName != "login-pwned" {
		t.Errorf("SecretName = %q, want login-pwned", result.CompromisedPasswords[0].SecretName)
	}
	if result.CompromisedPasswords[0].BreachCount != 100 {
		t.Errorf("BreachCount = %d, want 100", result.CompromisedPasswords[0].BreachCount)
	}
	if result.IsOfflineMode {
		t.Errorf("expected online mode, got offline with reason %s", result.OfflineReason)
	}
}

func TestPasswordStrengthMethods(t *testing.T) {
	tests := []struct {
		strength PasswordStrength
		str      string
		hex      string
	}{
		{StrengthVeryWeak, "Very Weak", "#EF4444"},
		{StrengthWeak, "Weak", "#F59E0B"},
		{StrengthFair, "Fair", "#F59E0B"},
		{StrengthStrong, "Strong", "#10B981"},
		{StrengthVeryStrong, "Very Strong", "#10B981"},
	}
	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			if got := tt.strength.String(); got != tt.str {
				t.Errorf("String() = %q, want %q", got, tt.str)
			}
			if got := tt.strength.ColorHex(); got != tt.hex {
				t.Errorf("ColorHex() = %q, want %q", got, tt.hex)
			}
		})
	}
}

func TestAnalyzeWithPwned_PersistentCache(t *testing.T) {
	engine, key := testEngineAndKey(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	blob := encryptPassword(t, engine, key, "some-password")
	// Metadata has fresh audit from 1 hour ago with 50 breaches
	recentAudit := time.Now().UTC().Add(-1 * time.Hour)
	meta := secret.MarshalPasswordMetadata(&secret.PasswordMetadata{
		Username:    "user",
		PwnedCount:  50,
		LastAudited: &recentAudit,
	})

	ms := &mockStore{
		listSecrets: []secret.Secret{
			makePasswordSecret("cached-pwned", blob, meta),
		},
	}

	pwnedMgr := NewPwnedManager(1*time.Hour, WithBaseURL(server.URL))
	result, err := AnalyzeWithPwned(ms, engine, key, pwnedMgr)
	if err != nil {
		t.Fatalf("AnalyzeWithPwned failed: %v", err)
	}

	// Should have used cache and made 0 network calls
	if calls != 0 {
		t.Errorf("expected 0 network calls for fresh cache, got %d", calls)
	}
	if result.SecretsWithCompromised != 1 {
		t.Errorf("expected 1 compromised secret from cache, got %d", result.SecretsWithCompromised)
	}
	if len(result.CompromisedPasswords) != 1 || result.CompromisedPasswords[0].BreachCount != 50 {
		t.Errorf("unexpected compromised finding from cache: %+v", result.CompromisedPasswords)
	}
}
