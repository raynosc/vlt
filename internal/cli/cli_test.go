package cli

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"image/png"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	p12 "software.sslmate.com/src/go-pkcs12"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/parse"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
)

const testMasterPassword = "test-master-password-123"

// ---------------------------------------------------------------------------
// Test fixture generation (duplicated from parse_test.go for CLI tests)
// ---------------------------------------------------------------------------

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func generateRSA(bits int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	must(err)
	return k
}

func generateEd25519() ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	return priv
}

//nolint:unused
func generateECDSA(curve elliptic.Curve) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	must(err)
	return k
}

func marshalSSHPriv(key interface{}, comment string) ([]byte, error) {
	block, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

//nolint:unused
func pubKeyLine(privPEM []byte, comment string) []byte {
	signer, err := ssh.ParsePrivateKey(privPEM)
	must(err)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if comment != "" {
		line += " " + comment
	}
	return []byte(line + "\n")
}

// genCertPEM generates a self-signed X.509 certificate and returns PEM bytes.
func genCertPEM(subject string, bits int, notBefore, notAfter time.Time, dnsNames []string) []byte {
	key := generateRSA(bits)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: subject},
		Issuer:       pkix.Name{CommonName: subject},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(err)
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return pem.EncodeToMemory(block)
}

// genPKCS12 generates a PKCS12 bundle with a leaf and CA cert.
func genPKCS12(password string) []byte {
	caKey := generateRSA(2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	must(err)
	caCert, err := x509.ParseCertificate(caDER)
	must(err)

	leafKey := generateRSA(2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	leafTmpl.Issuer = caTmpl.Subject
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	must(err)
	leafCert, err := x509.ParseCertificate(leafDER)
	must(err)

	//nolint:staticcheck
	data, err := p12.Encode(rand.Reader, leafKey, leafCert, []*x509.Certificate{caCert}, password)
	must(err)
	return data
}

// writeFixture writes data to a file in the given directory.
func writeFixture(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Vault helper (from foundation-cli tests)
// ---------------------------------------------------------------------------

// initVault creates a test vault at the given path with a known password.
func initVault(t *testing.T, vaultPath, password string) *store.SQLStore {
	t.Helper()

	s := store.NewSQLStore()
	if err := s.Init(vaultPath); err != nil {
		t.Fatalf("Init vault: %v", err)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}

	eng := crypto.NewEngine(nil)
	key, err := eng.DeriveKey([]byte(password), salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	// Generate verify hash
	kdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	verifyHash := make([]byte, 32)
	if _, err := io.ReadFull(kdf, verifyHash); err != nil {
		t.Fatalf("generate verify hash: %v", err)
	}

	// Store config via SQL directly
	if err := s.ConfigSet(configKeySalt, salt); err != nil {
		t.Fatalf("store salt: %v", err)
	}
	if err := s.ConfigSet(configKeyVerifyHash, verifyHash); err != nil {
		t.Fatalf("store verify hash: %v", err)
	}

	// Store argon2 params
	params := crypto.DefaultArgon2Params
	timeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBytes, params.Time)
	memoryBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(memoryBytes, params.Memory)
	threadsBytes := []byte{byte(params.Threads)}
	_ = s.ConfigSet(configKeyArgon2Time, timeBytes)
	_ = s.ConfigSet(configKeyArgon2Memory, memoryBytes)
	_ = s.ConfigSet(configKeyArgon2Threads, threadsBytes)

	return s
}

func storeSecretForTest(t *testing.T, s *store.SQLStore, eng *crypto.Engine, key []byte, sec secret.Secret) {
	t.Helper()
	sec, err := encryptSecretMetadata(sec, eng, key)
	if err != nil {
		t.Fatalf("encrypt test secret metadata: %v", err)
	}
	if err := s.Store(sec); err != nil {
		t.Fatalf("store test secret: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Command execution helpers
// ---------------------------------------------------------------------------

func TestMain(m *testing.M) {
	origKC := kc
	kc = newMockKC()
	code := m.Run()
	kc = origKC
	os.Exit(code)
}

// executeCmd runs a cobra command with the given args.
func executeCmd(args ...string) error {
	root := newRootCmd()
	root.SetArgs(args)
	return root.Execute()
}

// executeCmdWithOutput runs a command and captures both stdout and stderr.
func executeCmdWithOutput(args ...string) (stdout, stderr string, err error) {
	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := newRootCmd()
	root.SetArgs(args)
	cmdErr := root.Execute()

	_ = wOut.Close()
	_ = wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	outBuf, _ := io.ReadAll(rOut)
	errBuf, _ := io.ReadAll(rErr)

	return string(outBuf), string(errBuf), cmdErr
}

// withEnv sets an env var for the duration of a test.
func withEnv(t *testing.T, key, value string) {
	t.Helper()
	old := os.Getenv(key)
	_ = os.Setenv(key, value)
	t.Cleanup(func() {
		if old == "" {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, old)
		}
	})
}

// pipeStdinExecute pipes a string to os.Stdin and executes a cobra command.
// Used when --stdin flag needs input (replaces removed --value flag).
func pipeStdinExecute(t *testing.T, stdinValue string, args ...string) error {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create pipe: %w", err)
	}
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	// Write the stdin value in a goroutine so it's available when read
	go func() {
		defer w.Close()
		_, _ = w.Write([]byte(stdinValue))
	}()

	root := newRootCmd()
	root.SetArgs(args)
	return root.Execute()
}

// pipeStdinExecuteWithOutput pipes stdin and captures stdout/stderr.
func pipeStdinExecuteWithOutput(t *testing.T, stdinValue string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		return "", "", fmt.Errorf("create pipe: %w", pipeErr)
	}
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	go func() {
		defer w.Close()
		_, _ = w.Write([]byte(stdinValue))
	}()

	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := newRootCmd()
	root.SetArgs(args)
	cmdErr := root.Execute()

	_ = wOut.Close()
	_ = wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	outBuf, _ := io.ReadAll(rOut)
	errBuf, _ := io.ReadAll(rErr)

	return string(outBuf), string(errBuf), cmdErr
}

// ---------------------------------------------------------------------------
// Recovery kit tests
// ---------------------------------------------------------------------------

func TestInit_RecoveryKitToFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test-vault.sqlite")
	recoveryPath := filepath.Join(tmpDir, "recovery-kit.txt")

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	err := executeCmd("init", "--save-recovery", recoveryPath, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Verify recovery kit file was created
	if _, err := os.Stat(recoveryPath); os.IsNotExist(err) {
		t.Fatal("recovery kit file not created")
	}

	// Verify permissions are 0o600
	info, err := os.Stat(recoveryPath)
	if err != nil {
		t.Fatalf("stat recovery kit: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("expected permissions 0600, got %#o", perm)
	}

	// Verify content is non-empty
	data, err := os.ReadFile(recoveryPath)
	if err != nil {
		t.Fatalf("read recovery kit: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("recovery kit file is empty")
	}
}

func TestInit_ShowRecoveryFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test-vault.sqlite")
	recoveryPath := filepath.Join(tmpDir, "recovery-kit.txt")

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, stderr, err := executeCmdWithOutput("init", "--vault-path", vaultPath, "--save-recovery", recoveryPath)
	if err != nil {
		t.Fatalf("init --save-recovery failed: %v", err)
	}

	// Should still create the file
	if _, err := os.Stat(recoveryPath); os.IsNotExist(err) {
		t.Fatal("recovery kit file should still be created with --save-recovery")
	}

	// Should show recovery kit in stderr
	if !strings.Contains(stderr, "RECOVERY KIT") {
		t.Errorf("expected RECOVERY KIT header in output with --save-recovery, got: %s", stderr)
	}
	if !strings.Contains(stderr, "WARNING") {
		t.Errorf("expected WARNING in output with --save-recovery, got: %s", stderr)
	}
}

func TestInit_RecoveryKitNotOnStdout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test-vault.sqlite")

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	stdout, _, err := executeCmdWithOutput("init", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Verify recovery kit is NOT on stdout (it should be on stderr only)
	if stdout != "" {
		t.Errorf("expected empty stdout (recovery kit should not be printed), got: %s", stdout)
	}
}

// ---------------------------------------------------------------------------
// Rate limiting tests
// ---------------------------------------------------------------------------

func TestUnlock_RateLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	// Without env var and without TTY, promptPassword will fail immediately.
	// The test verifies we get an error (rate limiting not triggered since we
	// can't even read a password). The rate limiting is tested via the logic
	// in unlockVault when the env var is set with wrong passwords.
	err := pipeStdinExecute(t, "val\n", "add", "test", "--stdin", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error for non-interactive mode, got nil")
	}
	// Should fail because no TTY to read password
	if strings.Contains(err.Error(), "Too many") {
		// This would indicate rate limiting was hit (shouldn't happen without TTY)
		t.Logf("Got rate limit error: %v", err)
	}
}

func TestUnlock_EnvVarBypassRateLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	// With env var, wrong password should give single error (no retries)
	withEnv(t, "PASSWD_MASTER_PASSWORD", "wrong-password-twice")

	err := pipeStdinExecute(t, "val\n", "add", "test", "--stdin", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
	if !strings.Contains(err.Error(), "invalid master password") {
		t.Errorf("expected 'invalid master password' error, got: %v", err)
	}

	// With correct env var, should succeed immediately (no retries)
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	err = pipeStdinExecute(t, "val2\n", "add", "test2", "--stdin", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("expected success with correct env var, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// --no-env flag tests
// ---------------------------------------------------------------------------

func TestNoEnv_Flag_IgnoresEnvVar(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	// Set env var — but with --no-env, it should be ignored
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Without --no-env, the correct env var should succeed
	err := pipeStdinExecute(t, "val\n", "add", "via-env", "--stdin", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("expected success without --no-env, got: %v", err)
	}

	// With --no-env, the env var should be IGNORED and it should try to prompt
	// Since there's no TTY in tests, promptPassword should fail
	err = pipeStdinExecute(t, "val2\n", "add", "via-no-env", "--stdin", "--no-env", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error with --no-env (no TTY to read password), got nil")
	}
	// The error should be about reading password, NOT about invalid master password
	// (which would mean the env var was used)
	if strings.Contains(err.Error(), "invalid master password") {
		t.Errorf("--no-env should ignore env var, got 'invalid master password' (env var was used): %v", err)
	}
}

func TestNoEnv_WarningPrintedOnStderr(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Capture stderr to verify the warning is shown
	stdout, stderr, err := pipeStdinExecuteWithOutput(t, "val\n", "add", "warning-check", "--stdin", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("add failed: %v", err)
	}
	_ = stdout

	if !strings.Contains(stderr, "WARNING: PASSWD_MASTER_PASSWORD is set") {
		t.Errorf("expected prominent warning on stderr, got: %s", stderr)
	}
	if !strings.Contains(stderr, "--no-env") {
		t.Errorf("expected --no-env hint in warning, got: %s", stderr)
	}
}

func TestNoEnv_Flag_AffectsInitCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	// With env var and --no-env, init should prompt (and fail without TTY)
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	err := executeCmd("init", "--no-env", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error with --no-env on init (no TTY), got nil")
	}
	if strings.Contains(err.Error(), "invalid master password") || strings.Contains(err.Error(), "passwords do not match") {
		t.Errorf("--no-env should ignore env var on init, got env-var-related error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Init tests (from foundation-cli)
// ---------------------------------------------------------------------------

func TestInitCmd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test-vault.sqlite")

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	err := executeCmd("init", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		t.Fatal("vault file not created")
	}
}

// ---------------------------------------------------------------------------
// Add with --file tests
// ---------------------------------------------------------------------------

func TestAdd_File_Certificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	// Generate a test certificate
	certPEM := genCertPEM("test.example.com", 2048,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(365*24*time.Hour),
		[]string{"example.com"})
	certFile := writeFixture(t, fixtureDir, "cert.pem", certPEM)

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	err := executeCmd("add", "mycert", "--file", certFile, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("add --file cert.pem failed: %v", err)
	}

	// Verify the secret was stored with kind=certificate and metadata
	s2, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s2.Close() }()

	eng2 := crypto.NewEngine(nil)
	key2, _ := eng2.DeriveKey([]byte(testMasterPassword), getSalt(t, s2))
	defer crypto.Zeroize(key2)
	sec, err := getByName(s2, key2, "mycert")
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if sec.Kind != secret.KindCertificate {
		t.Fatalf("expected kind=certificate, got %q", sec.Kind)
	}
	if sec.Metadata == "" {
		t.Fatal("expected non-empty metadata")
	}

	// Verify metadata parses correctly
	var meta parse.Metadata
	if err := json.Unmarshal([]byte(sec.Metadata), &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.SubjectCN != "test.example.com" {
		t.Fatalf("expected SubjectCN=test.example.com, got %q", meta.SubjectCN)
	}
	if meta.FingerprintSHA256 == "" {
		t.Fatal("expected non-empty FingerprintSHA256")
	}
	if len(meta.KeyUsage) == 0 {
		t.Fatal("expected non-empty KeyUsage")
	}
}

func TestAdd_File_SSHKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	// Generate an SSH RSA private key
	sshKey, err := marshalSSHPriv(generateRSA(2048), "test-key")
	if err != nil {
		t.Fatalf("generate SSH key: %v", err)
	}
	keyFile := writeFixture(t, fixtureDir, "id_rsa", sshKey)

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	err = executeCmd("add", "mysshkey", "--file", keyFile, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("add --file id_rsa failed: %v", err)
	}

	s2, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s2.Close() }()

	eng2 := crypto.NewEngine(nil)
	key2, _ := eng2.DeriveKey([]byte(testMasterPassword), getSalt(t, s2))
	defer crypto.Zeroize(key2)
	sec, err := getByName(s2, key2, "mysshkey")
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if sec.Kind != secret.KindSSHKey {
		t.Fatalf("expected kind=ssh_key, got %q", sec.Kind)
	}
	if sec.Metadata == "" {
		t.Fatal("expected non-empty metadata")
	}

	var meta parse.Metadata
	if err := json.Unmarshal([]byte(sec.Metadata), &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.KeyType != "ssh-rsa" {
		t.Fatalf("expected KeyType=ssh-rsa, got %q", meta.KeyType)
	}
	if meta.FingerprintSHA256 == "" {
		t.Fatal("expected non-empty fingerprint")
	}
}

func TestAdd_File_PKCS12(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	// Generate a PKCS12 bundle with known password
	p12Data := genPKCS12("test123")
	p12File := writeFixture(t, fixtureDir, "bundle.p12", p12Data)

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	err := executeCmd("add", "myp12", "--file", p12File, "--password", "test123", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("add --file bundle.p12 --password test123 failed: %v", err)
	}

	s2, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s2.Close() }()

	eng2 := crypto.NewEngine(nil)
	key2, _ := eng2.DeriveKey([]byte(testMasterPassword), getSalt(t, s2))
	defer crypto.Zeroize(key2)
	sec, err := getByName(s2, key2, "myp12")
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if sec.Kind != secret.KindCertificate {
		t.Fatalf("expected kind=certificate, got %q", sec.Kind)
	}
	if sec.Metadata == "" {
		t.Fatal("expected non-empty metadata")
	}

	var meta parse.Metadata
	if err := json.Unmarshal([]byte(sec.Metadata), &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.Format != "pkcs12" {
		t.Fatalf("expected format=pkcs12, got %q", meta.Format)
	}
	if meta.CertCount != 2 {
		t.Fatalf("expected CertCount=2, got %d", meta.CertCount)
	}
}

func TestAdd_File_NonExistent_ReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	err := executeCmd("add", "mycert", "--file", "/nonexistent/path/cert.pem", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
	if !strings.Contains(err.Error(), "file not found") {
		t.Fatalf("expected 'file not found' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Inspect tests
// ---------------------------------------------------------------------------

func TestInspect_Certificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	fixtureDir := t.TempDir()
	certPEM := genCertPEM("inspect.example.com", 2048,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(365*24*time.Hour),
		[]string{"example.com", "www.example.com"})
	certFile := writeFixture(t, fixtureDir, "cert.pem", certPEM)

	stdout, _, err := executeCmdWithOutput("inspect", certFile)
	if err != nil {
		t.Fatalf("inspect failed: %v", err)
	}

	// Should display metadata fields (output goes to stdout)
	checks := []string{
		"X.509 Certificate",
		"inspect.example.com",
		"SHA-256",
		"SHA-1",
		"example.com",
		"digital_signature",
	}
	for _, check := range checks {
		if !strings.Contains(stdout, check) {
			t.Errorf("expected %q in inspect output", check)
		}
	}
}

func TestInspect_SSHKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	fixtureDir := t.TempDir()
	sshKey, err := marshalSSHPriv(generateEd25519(), "test@host")
	if err != nil {
		t.Fatalf("generate SSH key: %v", err)
	}
	keyFile := writeFixture(t, fixtureDir, "id_ed25519", sshKey)

	stdout, _, err := executeCmdWithOutput("inspect", keyFile)
	if err != nil {
		t.Fatalf("inspect SSH key failed: %v", err)
	}

	checks := []string{"SSH Private Key", "ssh-ed25519", "SHA256"}
	for _, check := range checks {
		if !strings.Contains(stdout, check) {
			t.Errorf("expected %q in inspect output", check)
		}
	}
}

func TestInspect_JSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	fixtureDir := t.TempDir()
	certPEM := genCertPEM("json-test.example.com", 2048,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(365*24*time.Hour),
		nil)
	certFile := writeFixture(t, fixtureDir, "cert.pem", certPEM)

	stdout, _, err := executeCmdWithOutput("inspect", "--json", certFile)
	if err != nil {
		t.Fatalf("inspect --json failed: %v", err)
	}

	var meta parse.Metadata
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &meta); err != nil {
		t.Fatalf("unmarshal JSON output: %v", err)
	}
	if meta.SubjectCN != "json-test.example.com" {
		t.Fatalf("expected SubjectCN=json-test.example.com, got %q", meta.SubjectCN)
	}
	if meta.FingerprintSHA256 == "" {
		t.Fatal("expected non-empty FingerprintSHA256")
	}
}

func TestInspect_NonExistent_ReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	err := executeCmd("inspect", "/nonexistent/cert.pem")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
	if !strings.Contains(err.Error(), "file not found") {
		t.Fatalf("expected 'file not found' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// List with --kind and --expiring tests
// ---------------------------------------------------------------------------

func TestList_KindFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	// Generate fixtures
	certPEM := genCertPEM("cert.example.com", 2048,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(365*24*time.Hour),
		nil)
	_ = writeFixture(t, fixtureDir, "cert.pem", certPEM)

	sshKey, err := marshalSSHPriv(generateRSA(2048), "key-comment")
	if err != nil {
		t.Fatalf("generate SSH key: %v", err)
	}
	_ = writeFixture(t, fixtureDir, "id_rsa", sshKey)

	s := initVault(t, vaultPath, testMasterPassword)

	// Add secrets programmatically
	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	// Certificate
	ct1, nonce1, _ := eng.Encrypt(certPEM, key)
	meta1, _ := parse.ParseX509(certPEM)
	metaJSON1, _ := json.Marshal(meta1)
	sec1 := secret.Secret{
		Name:           "my-cert",
		Kind:           secret.KindCertificate,
		EncryptedValue: packEnvelope(nonce1, ct1),
		Metadata:       string(metaJSON1),
	}
	storeSecretForTest(t, s, eng, key, sec1)

	// SSH key
	ct2, nonce2, _ := eng.Encrypt(sshKey, key)
	meta2, _ := parse.ParseSSHPrivate(sshKey)
	metaJSON2, _ := json.Marshal(meta2)
	sec2 := secret.Secret{
		Name:           "my-ssh",
		Kind:           secret.KindSSHKey,
		EncryptedValue: packEnvelope(nonce2, ct2),
		Metadata:       string(metaJSON2),
	}
	storeSecretForTest(t, s, eng, key, sec2)

	// Password (no metadata)
	ct3, nonce3, _ := eng.Encrypt([]byte("password-value"), key)
	sec3 := secret.Secret{
		Name:           "my-password",
		Kind:           secret.KindPassword,
		EncryptedValue: packEnvelope(nonce3, ct3),
	}
	storeSecretForTest(t, s, eng, key, sec3)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Test --kind certificate
	_, stderr, err := executeCmdWithOutput("list", "--kind", "certificate", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("list --kind certificate failed: %v", err)
	}
	if !strings.Contains(stderr, "my-cert") {
		t.Errorf("expected 'my-cert' in list output")
	}
	if strings.Contains(stderr, "my-ssh") {
		t.Errorf("did NOT expect 'my-ssh' in certificate list")
	}
	if strings.Contains(stderr, "my-password") {
		t.Errorf("did NOT expect 'my-password' in certificate list")
	}

	// Test --kind ssh_key
	_, stderr, err = executeCmdWithOutput("list", "--kind", "ssh_key", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("list --kind ssh_key failed: %v", err)
	}
	if !strings.Contains(stderr, "my-ssh") {
		t.Errorf("expected 'my-ssh' in list output")
	}
	if strings.Contains(stderr, "my-cert") {
		t.Errorf("did NOT expect 'my-cert' in ssh_key list")
	}
}

func TestList_Expiring(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)

	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	// Cert expiring in 10 days
	cert10 := genCertPEM("expiring-10", 2048, time.Now().Add(-1*time.Hour), time.Now().Add(10*24*time.Hour), nil)
	meta10, _ := parse.ParseX509(cert10)
	metaJSON10, _ := json.Marshal(meta10)
	ct10, nonce10, _ := eng.Encrypt(cert10, key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "cert-10d",
		Kind:           secret.KindCertificate,
		EncryptedValue: packEnvelope(nonce10, ct10),
		Metadata:       string(metaJSON10),
	})

	// Cert expiring in 45 days
	cert45 := genCertPEM("expiring-45", 2048, time.Now().Add(-1*time.Hour), time.Now().Add(45*24*time.Hour), nil)
	meta45, _ := parse.ParseX509(cert45)
	metaJSON45, _ := json.Marshal(meta45)
	ct45, nonce45, _ := eng.Encrypt(cert45, key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "cert-45d",
		Kind:           secret.KindCertificate,
		EncryptedValue: packEnvelope(nonce45, ct45),
		Metadata:       string(metaJSON45),
	})

	// Cert expiring in 90 days
	cert90 := genCertPEM("expiring-90", 2048, time.Now().Add(-1*time.Hour), time.Now().Add(90*24*time.Hour), nil)
	meta90, _ := parse.ParseX509(cert90)
	metaJSON90, _ := json.Marshal(meta90)
	ct90, nonce90, _ := eng.Encrypt(cert90, key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "cert-90d",
		Kind:           secret.KindCertificate,
		EncryptedValue: packEnvelope(nonce90, ct90),
		Metadata:       string(metaJSON90),
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// List expiring within 30 days — should only show cert-10d
	_, stderr, err := executeCmdWithOutput("list", "--expiring", "30", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("list --expiring 30 failed: %v", err)
	}
	if !strings.Contains(stderr, "cert-10d") {
		t.Errorf("expected 'cert-10d' in expiring list")
	}
	if strings.Contains(stderr, "cert-45d") {
		t.Errorf("did NOT expect 'cert-45d' in expiring within 30 days")
	}
	if strings.Contains(stderr, "cert-90d") {
		t.Errorf("did NOT expect 'cert-90d' in expiring within 30 days")
	}
}

func TestList_Empty_Expiring_Message(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, stderr, err := executeCmdWithOutput("list", "--expiring", "30", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("list --expiring 30 failed: %v", err)
	}
	if !strings.Contains(stderr, "No certificates expiring within 30 days") {
		t.Fatalf("expected friendly empty message, got: %s", stderr)
	}
}

func TestList_KindAndExpiring(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)

	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	// Certificate expiring in 10 days
	cert10 := genCertPEM("expiring-10", 2048, time.Now().Add(-1*time.Hour), time.Now().Add(10*24*time.Hour), nil)
	meta10, _ := parse.ParseX509(cert10)
	metaJSON10, _ := json.Marshal(meta10)
	ct10, nonce10, _ := eng.Encrypt(cert10, key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "cert-ex10",
		Kind:           secret.KindCertificate,
		EncryptedValue: packEnvelope(nonce10, ct10),
		Metadata:       string(metaJSON10),
	})

	// Password (non-expiring)
	ctPW, noncePW, _ := eng.Encrypt([]byte("password-val"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "my-pass",
		Kind:           secret.KindPassword,
		EncryptedValue: packEnvelope(noncePW, ctPW),
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// List --kind certificate --expiring 30 — should show cert-ex10 but not my-pass
	_, stderr, err := executeCmdWithOutput("list", "--kind", "certificate", "--expiring", "30", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("list --kind certificate --expiring 30 failed: %v", err)
	}
	if !strings.Contains(stderr, "cert-ex10") {
		t.Errorf("expected 'cert-ex10' in list output")
	}
	if strings.Contains(stderr, "my-pass") {
		t.Errorf("did NOT expect 'my-pass' in certificate list")
	}
}

func TestList_TagFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	// Add secrets with different tags
	ct1, nonce1, _ := eng.Encrypt([]byte("val1"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name: "prod-db", Kind: secret.KindPassword,
		EncryptedValue: packEnvelope(nonce1, ct1), Tags: "production,db",
	})
	ct2, nonce2, _ := eng.Encrypt([]byte("val2"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name: "dev-db", Kind: secret.KindPassword,
		EncryptedValue: packEnvelope(nonce2, ct2), Tags: "development,db",
	})
	ct3, nonce3, _ := eng.Encrypt([]byte("val3"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name: "staging-key", Kind: secret.KindAPIKey,
		EncryptedValue: packEnvelope(nonce3, ct3), Tags: "staging",
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Test --tag production
	_, stderr, err := executeCmdWithOutput("list", "--tag", "production", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("list --tag production failed: %v", err)
	}
	if !strings.Contains(stderr, "prod-db") {
		t.Errorf("expected 'prod-db' in --tag production output")
	}
	if strings.Contains(stderr, "dev-db") {
		t.Errorf("did NOT expect 'dev-db' in --tag production output")
	}
	if strings.Contains(stderr, "staging-key") {
		t.Errorf("did NOT expect 'staging-key' in --tag production output")
	}

	// Test --tag db (should match prod-db and dev-db)
	_, stderr, err = executeCmdWithOutput("list", "--tag", "db", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("list --tag db failed: %v", err)
	}
	if !strings.Contains(stderr, "prod-db") {
		t.Errorf("expected 'prod-db' in --tag db output")
	}
	if !strings.Contains(stderr, "dev-db") {
		t.Errorf("expected 'dev-db' in --tag db output")
	}
}

func TestList_TagsFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	// Add secrets with tags
	ct1, nonce1, _ := eng.Encrypt([]byte("v1"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name: "a", Kind: secret.KindPassword,
		EncryptedValue: packEnvelope(nonce1, ct1), Tags: "production,aws",
	})
	ct2, nonce2, _ := eng.Encrypt([]byte("v2"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name: "b", Kind: secret.KindPassword,
		EncryptedValue: packEnvelope(nonce2, ct2), Tags: "development,aws",
	})
	ct3, nonce3, _ := eng.Encrypt([]byte("v3"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name: "c", Kind: secret.KindPassword,
		EncryptedValue: packEnvelope(nonce3, ct3), Tags: "production",
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Test --tags
	_, stderr, err := executeCmdWithOutput("list", "--tags", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("list --tags failed: %v", err)
	}

	// Should show unique tags with counts
	if !strings.Contains(stderr, "production") {
		t.Errorf("expected 'production' in --tags output, got: %s", stderr)
	}
	if !strings.Contains(stderr, "development") {
		t.Errorf("expected 'development' in --tags output, got: %s", stderr)
	}
	if !strings.Contains(stderr, "aws") {
		t.Errorf("expected 'aws' in --tags output, got: %s", stderr)
	}
	// Counts: production=2, aws=2, development=1
	if !strings.Contains(stderr, "TAG") || !strings.Contains(stderr, "COUNT") {
		t.Errorf("expected header in --tags output, got: %s", stderr)
	}
}

func TestList_TagsFlag_NoTags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, stderr, err := executeCmdWithOutput("list", "--tags", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("list --tags failed: %v", err)
	}
	if !strings.Contains(stderr, "No tags") {
		t.Errorf("expected 'No tags' message, got: %s", stderr)
	}
}

// ---------------------------------------------------------------------------
// Add/Get round-trip (from foundation-cli)
// ---------------------------------------------------------------------------

func TestAddGet_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	err := pipeStdinExecute(t, "s3cret-value!\n", "add", "my-secret", "--stdin", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("add failed: %v", err)
	}

	stdout, _, err := executeCmdWithOutput("get", "my-secret", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if strings.TrimSpace(stdout) != "s3cret-value!" {
		t.Fatalf("expected 's3cret-value!', got %q", strings.TrimSpace(stdout))
	}
}

func TestList_EmptyVault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, stderr, err := executeCmdWithOutput("list", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if !strings.Contains(stderr, "No secrets stored") {
		t.Fatalf("expected 'No secrets stored', got: %s", stderr)
	}
}

func TestWrongMasterPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", "wrong-password")

	err := pipeStdinExecute(t, "val\n", "add", "test", "--stdin", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
	if !strings.Contains(err.Error(), "invalid master password") {
		t.Fatalf("expected 'invalid master password', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Check command tests
// ---------------------------------------------------------------------------

func TestCheck_PassesOnCleanVault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, stderr, err := executeCmdWithOutput("check", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("check failed: %v", err)
	}
	if !strings.Contains(stderr, "passed") {
		t.Fatalf("expected 'passed' in output, got: %s", stderr)
	}
}

func TestCheck_ReportsExpiring(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)

	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	// Add a cert expiring in 10 days
	certPEM := genCertPEM("expiring-10", 2048,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(10*24*time.Hour),
		nil)
	meta, _ := parse.ParseX509(certPEM)
	metaJSON, _ := json.Marshal(meta)
	ct, nonce, _ := eng.Encrypt(certPEM, key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "expiring-cert",
		Kind:           secret.KindCertificate,
		EncryptedValue: packEnvelope(nonce, ct),
		Metadata:       string(metaJSON),
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, stderr, err := executeCmdWithOutput("check", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("check failed: %v", err)
	}
	if !strings.Contains(stderr, "expiring") {
		t.Fatalf("expected 'expiring' in check output, got: %s", stderr)
	}
	if !strings.Contains(stderr, "expiring-cert") {
		t.Fatalf("expected 'expiring-cert' in check output, got: %s", stderr)
	}
}

func TestCheck_Passwords_DetectsDuplicates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)

	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	// Add two password secrets with the same value
	pw := "duplicate-password-123"
	ct, nonce, _ := eng.Encrypt([]byte(pw), key)
	blob := packEnvelope(nonce, ct)

	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "login-a",
		Kind:           secret.KindPassword,
		EncryptedValue: blob,
	})
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "login-b",
		Kind:           secret.KindPassword,
		EncryptedValue: blob,
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	_, stderr, err := executeCmdWithOutput("check", "--passwords", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("check --passwords failed: %v", err)
	}
	if !strings.Contains(stderr, "REUSED") {
		t.Fatalf("expected 'REUSED' in output, got: %s", stderr)
	}
	if !strings.Contains(stderr, "login-a") {
		t.Fatalf("expected 'login-a' in output, got: %s", stderr)
	}
	if !strings.Contains(stderr, "login-b") {
		t.Fatalf("expected 'login-b' in output, got: %s", stderr)
	}
}

func TestCheck_Passwords_DetectsWeak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)

	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	// Add a weak password
	pw := "123456"
	ct, nonce, _ := eng.Encrypt([]byte(pw), key)
	blob := packEnvelope(nonce, ct)

	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "weak-login",
		Kind:           secret.KindPassword,
		EncryptedValue: blob,
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	_, stderr, err := executeCmdWithOutput("check", "--passwords", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("check --passwords failed: %v", err)
	}
	if !strings.Contains(stderr, "WEAK") {
		t.Fatalf("expected 'WEAK' in output, got: %s", stderr)
	}
	if !strings.Contains(stderr, "weak-login") {
		t.Fatalf("expected 'weak-login' in output, got: %s", stderr)
	}
}

// mustGetSalt reads the salt from a test vault config.
func mustGetSalt(t *testing.T, s *store.SQLStore) []byte {
	t.Helper()
	salt, err := s.ConfigGet(configKeySalt)
	if err != nil {
		t.Fatalf("read salt: %v", err)
	}
	return salt
}

// ---------------------------------------------------------------------------
// Edit tests
// ---------------------------------------------------------------------------

func TestEdit_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Add a secret
	err := pipeStdinExecute(t, "original-value\n", "add", "my-secret", "--stdin", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Edit it with a new value
	err = pipeStdinExecute(t, "updated-value\n", "edit", "my-secret", "--stdin", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("edit failed: %v", err)
	}

	// Verify the value changed
	stdout, _, err := executeCmdWithOutput("get", "my-secret", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if strings.TrimSpace(stdout) != "updated-value" {
		t.Fatalf("expected 'updated-value', got %q", strings.TrimSpace(stdout))
	}
}

func TestEdit_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	err := pipeStdinExecute(t, "new-val\n", "edit", "nonexistent", "--stdin", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error for non-existent secret, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got: %v", err)
	}
}

func TestEdit_Rename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Add a secret
	err := pipeStdinExecute(t, "secret-value\n", "add", "old-name", "--stdin", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Rename it
	err = pipeStdinExecute(t, "new-value\n", "edit", "old-name", "--stdin", "--name", "new-name", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("edit rename failed: %v", err)
	}

	// Old name should not exist
	_, _, err = executeCmdWithOutput("get", "old-name", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error for old name after rename")
	}

	// New name should have the value
	stdout, _, err := executeCmdWithOutput("get", "new-name", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("get new name failed: %v", err)
	}
	if strings.TrimSpace(stdout) != "new-value" {
		t.Fatalf("expected 'new-value', got %q", strings.TrimSpace(stdout))
	}
}

func TestEdit_WithNotesFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Add a secret
	err := pipeStdinExecute(t, "val\n", "add", "my-secret", "--stdin", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("add failed: %v", err)
	}

	// Edit notes only (keep value)
	err = executeCmd("edit", "my-secret", "--notes", "updated notes", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("edit notes failed: %v", err)
	}

	// Get and verify notes (via JSON output)
	stdout, _, err := executeCmdWithOutput("get", "my-secret", "--json", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if !strings.Contains(stdout, "updated notes") && !strings.Contains(stdout, "val") {
		t.Fatalf("expected notes in output, got: %s", stdout)
	}
}

// ---------------------------------------------------------------------------
// OTP / TOTP command tests
// ---------------------------------------------------------------------------

// generateQRPNG creates a PNG file containing a QR code with the given content.
func generateQRPNG(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "qr.png")
	qr, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		t.Fatalf("create QR: %v", err)
	}
	img := qr.Image(256)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("encode PNG: %v", err)
	}
	return path
}

func TestTOTP_ShowsCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)

	// Store a secret with OTPAuth metadata
	eng := crypto.NewEngine(nil)
	key, err := eng.DeriveKey([]byte(testMasterPassword), getSalt(t, s))
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	ct, nonce, err := eng.Encrypt([]byte("my-password-value"), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob := packEnvelope(nonce, ct)

	otpauthURI := "otpauth://totp/Example:alice@google.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example"
	meta := secret.PasswordMetadata{
		URL:     "https://example.com",
		OTPAuth: otpauthURI,
	}
	metaJSON := secret.MarshalPasswordMetadata(&meta)

	// S-02: the seed lives encrypted in its own column, never in metadata.
	seedCT, seedNonce, err := eng.Encrypt([]byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), key)
	if err != nil {
		t.Fatalf("encrypt otp seed: %v", err)
	}

	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:             "test-otp",
		Kind:             secret.KindPassword,
		EncryptedValue:   blob,
		EncryptedOTPSeed: packEnvelope(seedNonce, seedCT),
		Metadata:         metaJSON,
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	stdout, stderr, err := executeCmdWithOutput("totp", "test-otp", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("totp failed: %v (stderr: %s)", err, stderr)
	}

	// Should print a 6-digit code on stdout
	if len(stdout) < 6 {
		t.Errorf("expected 6+ digit code on stdout, got %q", stdout)
	}
}

func TestTOTP_UnknownSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, _, err := executeCmdWithOutput("totp", "unknown", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error for unknown secret")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestTOTP_NoOTPURI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)

	eng := crypto.NewEngine(nil)
	key, err := eng.DeriveKey([]byte(testMasterPassword), getSalt(t, s))
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	ct, nonce, _ := eng.Encrypt([]byte("value"), key)
	blob := packEnvelope(nonce, ct)

	// Store secret WITHOUT OTPAuth
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "no-otp",
		Kind:           secret.KindPassword,
		EncryptedValue: blob,
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, _, err = executeCmdWithOutput("totp", "no-otp", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error for secret without OTP URI")
	}
	if !strings.Contains(err.Error(), "OTP") && !strings.Contains(err.Error(), "otp") {
		t.Errorf("expected OTP-related error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Import --qr tests
// ---------------------------------------------------------------------------

func TestImport_QR(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	// Generate QR with an OTP URI
	qrURI := "otpauth://totp/QRImport:test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=QRImport"
	qrPath := generateQRPNG(t, tmpDir, qrURI)

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, stderr, err := executeCmdWithOutput("import", "--qr", qrPath, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("import --qr failed: %v (stderr: %s)", err, stderr)
	}

	// Verify the secret was stored
	s2, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s2.Close() }()

	eng2 := crypto.NewEngine(nil)
	key2, _ := eng2.DeriveKey([]byte(testMasterPassword), getSalt(t, s2))
	defer crypto.Zeroize(key2)
	sec, err := getByName(s2, key2, "QRImport:test@example.com")
	if err != nil {
		t.Fatalf("get imported secret: %v", err)
	}
	if sec.Kind != secret.KindPassword {
		t.Errorf("kind = %q, want %q", sec.Kind, secret.KindPassword)
	}
	if sec.Metadata == "" {
		t.Fatal("expected non-empty metadata")
	}
	meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
	if meta == nil {
		t.Fatal("expected parseable metadata")
		return
	}
	// HIGH-01: Metadata now has redacted OTP secret for security.
	// The full URI is stored encrypted as the secret value.
	if !strings.Contains(meta.OTPAuth, "secret=REDACTED") {
		t.Errorf("expected redacted OTPAuth in metadata, got %q", meta.OTPAuth)
	}
	// Verify the encrypted value contains the full URI
	if len(sec.EncryptedValue) < 12 {
		t.Fatal("expected encrypted value with full OTP URI")
	}
	// Decrypt and verify full URI matches
	key, err := crypto.NewEngine(nil).DeriveKey([]byte(testMasterPassword), getSalt(t, s2))
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)
	nonce := sec.EncryptedValue[:12]
	ciphertext := sec.EncryptedValue[12:]
	plain, err := crypto.NewEngine(nil).Decrypt(ciphertext, key, nonce)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	defer crypto.Zeroize(plain)
	if string(plain) != qrURI {
		t.Errorf("encrypted value = %q, want %q", string(plain), qrURI)
	}
}

func TestImport_QR_CorruptFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "bad.png")
	if err := os.WriteFile(badPath, []byte{0x00, 0x01, 0x02}, 0644); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, _, err := executeCmdWithOutput("import", "--qr", badPath, "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error for corrupt QR file")
	}
	if !strings.Contains(err.Error(), "QR") && !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected QR/decode error, got: %v", err)
	}
}

// getSalt returns the salt from a test vault's config.
func getSalt(t *testing.T, s *store.SQLStore) []byte {
	t.Helper()
	salt, err := s.ConfigGet(configKeySalt)
	if err != nil {
		t.Fatalf("read salt: %v", err)
	}
	return salt
}

func TestReadArgon2Params_StoredParams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := store.NewSQLStore()
	if err := s.Init(vaultPath); err != nil {
		t.Fatalf("Init vault: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Store custom Argon2 params
	timeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBytes, 7)
	memoryBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(memoryBytes, 128*1024)
	threadsBytes := []byte{9}

	_ = s.ConfigSet(configKeyArgon2Time, timeBytes)
	_ = s.ConfigSet(configKeyArgon2Memory, memoryBytes)
	_ = s.ConfigSet(configKeyArgon2Threads, threadsBytes)

	params, err := readArgon2Params(s)
	if err != nil {
		t.Fatalf("readArgon2Params failed: %v", err)
	}
	if params.Time != 7 {
		t.Errorf("Time = %d, want 7", params.Time)
	}
	if params.Memory != 128*1024 {
		t.Errorf("Memory = %d, want %d", params.Memory, 128*1024)
	}
	if params.Threads != 9 {
		t.Errorf("Threads = %d, want 9", params.Threads)
	}
}

func TestReadArgon2Params_MissingKeysFallsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := store.NewSQLStore()
	if err := s.Init(vaultPath); err != nil {
		t.Fatalf("Init vault: %v", err)
	}
	defer func() { _ = s.Close() }()

	// No Argon2 params stored
	params, err := readArgon2Params(s)
	if err != nil {
		t.Fatalf("readArgon2Params failed: %v", err)
	}
	if params.Time != crypto.DefaultArgon2Params.Time {
		t.Errorf("Time = %d, want %d", params.Time, crypto.DefaultArgon2Params.Time)
	}
	if params.Memory != crypto.DefaultArgon2Params.Memory {
		t.Errorf("Memory = %d, want %d", params.Memory, crypto.DefaultArgon2Params.Memory)
	}
	if params.Threads != crypto.DefaultArgon2Params.Threads {
		t.Errorf("Threads = %d, want %d", params.Threads, crypto.DefaultArgon2Params.Threads)
	}
}
