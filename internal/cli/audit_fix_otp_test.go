package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/secret"
)

// TestAuditFixOTPLeak_MigratesPlaintextSeed simulates a pre-S-02 vault where the
// OTP seed sits in the plaintext metadata column, then verifies `audit
// fix-otp-leak` moves it into the encrypted_otp_seed column and scrubs metadata.
func TestAuditFixOTPLeak_MigratesPlaintextSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	const seedB32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	const otpauthURI = "otpauth://totp/Example:alice@google.com?secret=" + seedB32 + "&issuer=Example"

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)

	eng := crypto.NewEngine(nil)
	key, err := eng.DeriveKey([]byte(testMasterPassword), getSalt(t, s))
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	ct, nonce, err := eng.Encrypt([]byte("the-password"), key)
	if err != nil {
		t.Fatalf("encrypt value: %v", err)
	}

	// Build LEGACY metadata: json.Marshal does NOT redact (only
	// MarshalPasswordMetadata does), so this reproduces the plaintext leak that
	// older binaries wrote before the S-02 fix existed.
	legacyMeta, err := json.Marshal(&secret.PasswordMetadata{OTPAuth: otpauthURI})
	if err != nil {
		t.Fatalf("marshal legacy meta: %v", err)
	}
	if !strings.Contains(string(legacyMeta), seedB32) {
		t.Fatalf("test setup wrong: legacy metadata should contain the plaintext seed")
	}

	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "legacy-otp",
		Kind:           secret.KindPassword,
		EncryptedValue: packEnvelope(nonce, ct),
		Metadata:       string(legacyMeta),
		// EncryptedOTPSeed intentionally empty — that is the bug state.
	})
	crypto.Zeroize(key)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	if err := executeCmd("audit", "fix-otp-leak", "--vault-path", vaultPath); err != nil {
		t.Fatalf("fix-otp-leak failed: %v", err)
	}

	s2, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s2.Close() }()

	key2, _ := eng.DeriveKey([]byte(testMasterPassword), getSalt(t, s2))
	defer crypto.Zeroize(key2)
	sec, err := getByName(s2, key2, "legacy-otp")
	if err != nil {
		t.Fatalf("get legacy-otp: %v", err)
	}

	// (a) seed gone from plaintext metadata
	if strings.Contains(sec.Metadata, seedB32) {
		t.Fatalf("seed still in plaintext metadata after migration: %s", sec.Metadata)
	}
	// (b) seed now encrypted and recoverable
	if len(sec.EncryptedOTPSeed) == 0 {
		t.Fatal("encrypted_otp_seed empty after migration")
	}
	n2, c2, err := unpackEnvelope(sec.EncryptedOTPSeed)
	if err != nil {
		t.Fatalf("unpack seed: %v", err)
	}
	got, err := eng.Decrypt(c2, key2, n2)
	if err != nil {
		t.Fatalf("decrypt seed: %v", err)
	}
	if string(got) != seedB32 {
		t.Fatalf("decrypted seed: got %q, want %q", string(got), seedB32)
	}
	// (c) the encrypted password value is untouched by the migration
	valNonce, valCT, err := unpackEnvelope(sec.EncryptedValue)
	if err != nil {
		t.Fatalf("unpack value: %v", err)
	}
	pw, err := eng.Decrypt(valCT, key2, valNonce)
	if err != nil {
		t.Fatalf("password value corrupted by migration: %v", err)
	}
	if string(pw) != "the-password" {
		t.Fatalf("password value: got %q, want %q", string(pw), "the-password")
	}
}

// TestAuditFixOTPLeak_DryRunDoesNotModify verifies --dry-run leaves the vault
// untouched.
func TestAuditFixOTPLeak_DryRunDoesNotModify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	const otpauthURI = "otpauth://totp/Acme:bob?secret=JBSWY3DPEHPK3PXP&issuer=Acme"

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	s := initVault(t, vaultPath, testMasterPassword)

	legacyMeta, _ := json.Marshal(&secret.PasswordMetadata{OTPAuth: otpauthURI})
	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), getSalt(t, s))
	ct, nonce, _ := eng.Encrypt([]byte("pw"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "dry",
		Kind:           secret.KindPassword,
		EncryptedValue: packEnvelope(nonce, ct),
		Metadata:       string(legacyMeta),
	})
	crypto.Zeroize(key)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	if err := executeCmd("audit", "fix-otp-leak", "--dry-run", "--vault-path", vaultPath); err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}

	s2, _ := openStore(vaultPath)
	defer func() { _ = s2.Close() }()
	key2, _ := eng.DeriveKey([]byte(testMasterPassword), getSalt(t, s2))
	defer crypto.Zeroize(key2)
	sec, _ := getByName(s2, key2, "dry")
	if len(sec.EncryptedOTPSeed) != 0 {
		t.Fatal("dry-run must not populate encrypted_otp_seed")
	}
	if sec.Metadata != string(legacyMeta) {
		t.Fatal("dry-run must not modify metadata")
	}
}
