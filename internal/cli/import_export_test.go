package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/secret"
)

// ---------------------------------------------------------------------------
// Import Tests
// ---------------------------------------------------------------------------

func TestImport_CSV_Password(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	// Write a sample export CSV file
	csvContent := []byte("Title;Url;Username;Password;OTPAuth;Favorite;Archived;Tags;Notes\n" +
		"Movie.com;https://movie.example.com;user@example.com;s3cret!;otpauth123;;;movies,fun;My movie notes\n" +
		"Bank;https://bank.example.com;john;bankpass;;FALSE;FALSE;finance;Bank account\n")
	csvFile := filepath.Join(fixtureDir, "export.csv")
	if err := os.WriteFile(csvFile, csvContent, 0o600); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	err := executeCmd("import", csvFile, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	// Verify secrets were stored
	s2, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s2.Close() }()

	// Check Movie.com
	eng2 := crypto.NewEngine(nil)
	key2, _ := eng2.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s2))
	defer crypto.Zeroize(key2)
	movie, err := getByName(s2, key2, "Movie.com")
	if err != nil {
		t.Fatalf("get Movie.com: %v", err)
	}
	if movie.Kind != secret.KindPassword {
		t.Fatalf("expected kind=password, got %q", movie.Kind)
	}
	if movie.Tags != "movies,fun" {
		t.Errorf("expected tags 'movies,fun', got %q", movie.Tags)
	}
	if movie.Notes != "My movie notes" {
		t.Errorf("expected notes 'My movie notes', got %q", movie.Notes)
	}

	// Decrypt and verify password value
	eng := crypto.NewEngine(nil)
	salt := mustGetSalt(t, s2)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), salt)
	nonce, ct, _ := unpackEnvelope(movie.EncryptedValue)
	plaintext, err := eng.Decrypt(ct, key, nonce)
	if err != nil {
		t.Fatalf("decrypt Movie.com: %v", err)
	}
	if string(plaintext) != "s3cret!" {
		t.Errorf("expected password 's3cret!', got %q", string(plaintext))
	}

	// Verify metadata
	meta := secret.UnmarshalPasswordMetadata(movie.Metadata)
	if meta == nil {
		t.Fatal("expected non-nil password metadata")
		return
	}
	if meta.URL != "https://movie.example.com" {
		t.Errorf("expected url 'https://movie.example.com', got %q", meta.URL)
	}
	if meta.Username != "user@example.com" {
		t.Errorf("expected username 'user@example.com', got %q", meta.Username)
	}
	if meta.OTPAuth != "otpauth123" {
		t.Errorf("expected otpauth 'otpauth123', got %q", meta.OTPAuth)
	}

	// Check Bank
	bank, err := getByName(s2, key2, "Bank")
	if err != nil {
		t.Fatalf("get Bank: %v", err)
	}
	if bank.Tags != "finance" {
		t.Errorf("expected tags 'finance', got %q", bank.Tags)
	}
	if bank.Notes != "Bank account" {
		t.Errorf("expected notes 'Bank account', got %q", bank.Notes)
	}
	meta2 := secret.UnmarshalPasswordMetadata(bank.Metadata)
	if meta2 == nil {
		t.Fatal("expected non-nil password metadata for Bank")
		return
	}
	if meta2.URL != "https://bank.example.com" {
		t.Errorf("expected url 'https://bank.example.com', got %q", meta2.URL)
	}
	if meta2.Username != "john" {
		t.Errorf("expected username 'john', got %q", meta2.Username)
	}
}

func TestImport_CSV_CommaStandard(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	csvContent := []byte("Title,URL,Username,Password,Notes,OTPAuth\n" +
		"ABITAB,https://abitab.com.uy/,this is not a login form,zcf2KMC1bqe@uzw1rpx,,\n" +
		"Abitab.com,https://abitab.com.uy/,63721782,aqntjste-Q1,,\n" +
		"AC Atlassian,https://id.atlassian.com/,,tax.ftc8ACJ.bvd-btj,,\n")
	csvFile := filepath.Join(fixtureDir, "passwords.csv")
	if err := os.WriteFile(csvFile, csvContent, 0o600); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	err := executeCmd("import", csvFile, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("import comma csv failed: %v", err)
	}

	s2, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s2.Close() }()

	eng2 := crypto.NewEngine(nil)
	key2, _ := eng2.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s2))
	defer crypto.Zeroize(key2)

	sec, err := getByName(s2, key2, "ABITAB")
	if err != nil {
		t.Fatalf("get ABITAB: %v", err)
	}
	if sec.Name != "ABITAB" {
		t.Errorf("expected name 'ABITAB', got %q", sec.Name)
	}
}

func TestImport_JSON_Password(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	// Write a JSON import file
	jsonContent := []byte(`[
		{"Title":"Site1","Url":"https://site1.com","Username":"user1","Password":"pass1","OTPAuth":"","Tags":"tag1","Notes":"note1"},
		{"Title":"Site2","Url":"https://site2.com","Username":"user2","Password":"pass2","OTPAuth":"otp2","Tags":"tag2a,tag2b","Notes":"note2"}
	]`)
	jsonFile := filepath.Join(fixtureDir, "passwords.json")
	if err := os.WriteFile(jsonFile, jsonContent, 0o600); err != nil {
		t.Fatalf("write json: %v", err)
	}

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	err := executeCmd("import", jsonFile, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("import json failed: %v", err)
	}

	// Verify
	s2, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s2.Close() }()

	eng := crypto.NewEngine(nil)
	salt := mustGetSalt(t, s2)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), salt)

	for _, tc := range []struct {
		name     string
		expected string
		url      string
		username string
		otpauth  string
		tags     string
		notes    string
	}{
		{"Site1", "pass1", "https://site1.com", "user1", "", "tag1", "note1"},
		{"Site2", "pass2", "https://site2.com", "user2", "otp2", "tag2a,tag2b", "note2"},
	} {
		sec, err := getByName(s2, key, tc.name)
		if err != nil {
			t.Fatalf("get %q: %v", tc.name, err)
		}
		nonce, ct, _ := unpackEnvelope(sec.EncryptedValue)
		plaintext, err := eng.Decrypt(ct, key, nonce)
		if err != nil {
			t.Fatalf("decrypt %q: %v", tc.name, err)
		}
		if string(plaintext) != tc.expected {
			t.Errorf("%q password: got %q, want %q", tc.name, string(plaintext), tc.expected)
		}
		meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
		if meta == nil {
			t.Fatalf("%q: expected metadata", tc.name)
			continue
		}
		if meta.URL != tc.url {
			t.Errorf("%q url: got %q, want %q", tc.name, meta.URL, tc.url)
		}
		if meta.Username != tc.username {
			t.Errorf("%q username: got %q, want %q", tc.name, meta.Username, tc.username)
		}
		if meta.OTPAuth != tc.otpauth {
			t.Errorf("%q otpauth: got %q, want %q", tc.name, meta.OTPAuth, tc.otpauth)
		}
		if sec.Tags != tc.tags {
			t.Errorf("%q tags: got %q, want %q", tc.name, sec.Tags, tc.tags)
		}
		if sec.Notes != tc.notes {
			t.Errorf("%q notes: got %q, want %q", tc.name, sec.Notes, tc.notes)
		}
	}
}

// TestImport_JSON_OTP_EncryptsSeed is a regression guard for S-02: when a
// record carries a real otpauth:// URI, the import path must (a) redact the
// secret in the plaintext metadata column and (b) store the base32 seed
// encrypted in the dedicated encrypted_otp_seed column. Before the fix the
// seed was simply redacted and lost, leaving CLI-imported OTP secrets unable
// to generate codes.
func TestImport_JSON_OTP_EncryptsSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	const seedB32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	const otpauthURI = "otpauth://totp/Example:alice@google.com?secret=" + seedB32 + "&issuer=Example"

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	jsonContent := []byte(`[
		{"Title":"OTPSite","Url":"https://otp.example.com","Username":"alice","Password":"pw","OTPAuth":"` + otpauthURI + `","Tags":"","Notes":""}
	]`)
	jsonFile := filepath.Join(fixtureDir, "otp.json")
	if err := os.WriteFile(jsonFile, jsonContent, 0o600); err != nil {
		t.Fatalf("write json: %v", err)
	}

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	if err := executeCmd("import", jsonFile, "--vault-path", vaultPath); err != nil {
		t.Fatalf("import json failed: %v", err)
	}

	s2, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s2.Close() }()

	eng2 := crypto.NewEngine(nil)
	key2, _ := eng2.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s2))
	defer crypto.Zeroize(key2)
	sec, err := getByName(s2, key2, "OTPSite")
	if err != nil {
		t.Fatalf("get OTPSite: %v", err)
	}

	// (a) The seed must NOT survive in plaintext metadata.
	if strings.Contains(sec.Metadata, seedB32) {
		t.Fatalf("seed leaked in plaintext metadata: %s", sec.Metadata)
	}

	// (b) The encrypted_otp_seed column must be populated and decrypt to the seed.
	if len(sec.EncryptedOTPSeed) == 0 {
		t.Fatal("encrypted_otp_seed is empty; CLI import did not persist the OTP seed")
	}
	eng := crypto.NewEngine(nil)
	salt := mustGetSalt(t, s2)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), salt)
	defer crypto.Zeroize(key)
	nonce, ct, err := unpackEnvelope(sec.EncryptedOTPSeed)
	if err != nil {
		t.Fatalf("unpack otp seed: %v", err)
	}
	gotSeed, err := eng.Decrypt(ct, key, nonce)
	if err != nil {
		t.Fatalf("decrypt otp seed: %v", err)
	}
	if string(gotSeed) != seedB32 {
		t.Fatalf("decrypted seed: got %q, want %q", string(gotSeed), seedB32)
	}
}

func TestImport_DryRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	csvContent := []byte("Title;Url;Username;Password;OTPAuth;Favorite;Archived;Tags;Notes\n" +
		"DryRunTest;https://example.com;user;pass;;;test;\n")
	csvFile := filepath.Join(fixtureDir, "test.csv")
	if err := os.WriteFile(csvFile, csvContent, 0o600); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	_, stderr, err := executeCmdWithOutput("import", csvFile, "--vault-path", vaultPath, "--dry-run")
	if err != nil {
		t.Fatalf("import --dry-run failed: %v", err)
	}
	if !strings.Contains(stderr, "Dry run") && !strings.Contains(stderr, "dry") {
		t.Errorf("expected dry run message in stderr, got: %s", stderr)
	}

	// Verify no secrets were stored
	s2, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s2.Close() }()

	eng2 := crypto.NewEngine(nil)
	key2, _ := eng2.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s2))
	defer crypto.Zeroize(key2)
	_, err = getByName(s2, key2, "DryRunTest")
	if err == nil {
		t.Fatal("expected secret not to be stored after dry run")
	}
}

func TestImport_Duplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	// First import
	csvContent := []byte("Title;Url;Username;Password;OTPAuth;Favorite;Archived;Tags;Notes\n" +
		"UniqueOne;https://a.com;user1;pass1;;;\n")
	csvFile := filepath.Join(fixtureDir, "test.csv")
	if err := os.WriteFile(csvFile, csvContent, 0o600); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// First import
	err := executeCmd("import", csvFile, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("first import failed: %v", err)
	}

	// Second import — should skip duplicate
	_, stderr, err := executeCmdWithOutput("import", csvFile, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("second import failed: %v", err)
	}
	if !strings.Contains(stderr, "skipped") && !strings.Contains(stderr, "duplicate") {
		t.Errorf("expected duplicate/skipped message, got: %s", stderr)
	}

	// With --overwrite, should succeed
	_, _, err = executeCmdWithOutput("import", csvFile, "--vault-path", vaultPath, "--overwrite")
	if err != nil {
		t.Fatalf("import with --overwrite failed: %v", err)
	}
}

func TestImport_EmptyFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	// Empty CSV
	emptyCSV := filepath.Join(fixtureDir, "empty.csv")
	if err := os.WriteFile(emptyCSV, []byte{}, 0o600); err != nil {
		t.Fatalf("write empty csv: %v", err)
	}

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	err := executeCmd("import", emptyCSV, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("import empty csv should not error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Export Tests
// ---------------------------------------------------------------------------

func TestExport_CSV(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)

	// Add a password secret with metadata
	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	ct1, nonce1, _ := eng.Encrypt([]byte("mypass1"), key)
	meta1 := secret.MarshalPasswordMetadata(&secret.PasswordMetadata{
		URL:      "https://example.com",
		Username: "alice",
		OTPAuth:  "otp123",
	})
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "Example",
		Kind:           secret.KindPassword,
		EncryptedValue: packEnvelope(nonce1, ct1),
		Tags:           "web,important",
		Notes:          "My example login",
		Metadata:       meta1,
	})

	ct2, nonce2, _ := eng.Encrypt([]byte("bankpass"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "Bank",
		Kind:           secret.KindPassword,
		EncryptedValue: packEnvelope(nonce2, ct2),
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	outputDir := t.TempDir()
	_, stderr, err := executeCmdWithOutput("export", "--vault-path", vaultPath, "--output", outputDir, "--force")
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	// Read exported CSV file
	data, err := os.ReadFile(filepath.Join(outputDir, "vlt-export.csv"))
	if err != nil {
		t.Fatalf("read export file: %v", err)
	}
	stdout := string(data)

	// Check header
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 1 {
		t.Fatal("expected at least header line")
	}
	header := lines[0]
	expectedHeader := "Title;Url;Username;Password;OTPAuth;Tags;Notes"
	if header != expectedHeader {
		t.Errorf("header: got %q, want %q", header, expectedHeader)
	}

	// Check data lines
	foundExample := false
	foundBank := false
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "Example;") {
			foundExample = true
			fields := strings.Split(line, ";")
			if len(fields) != 7 {
				t.Fatalf("expected 7 fields, got %d: %v", len(fields), fields)
			}
			if fields[0] != "Example" {
				t.Errorf("title: got %q", fields[0])
			}
			if fields[1] != "https://example.com" {
				t.Errorf("url: got %q, want https://example.com", fields[1])
			}
			if fields[2] != "alice" {
				t.Errorf("username: got %q, want alice", fields[2])
			}
			if fields[3] != "mypass1" {
				t.Errorf("password: got %q, want mypass1", fields[3])
			}
			if fields[4] != "otp123" {
				t.Errorf("otpauth: got %q, want otp123", fields[4])
			}
			if fields[5] != "web,important" {
				t.Errorf("tags: got %q, want web,important", fields[5])
			}
			if fields[6] != "My example login" {
				t.Errorf("notes: got %q, want My example login", fields[6])
			}
		}
		if strings.HasPrefix(line, "Bank;") {
			foundBank = true
		}
	}
	if !foundExample {
		t.Error("Example not found in CSV output")
	}
	if !foundBank {
		t.Error("Bank not found in CSV output")
	}

	// Check stderr has output info
	if !strings.Contains(stderr, "exported") {
		t.Logf("stderr: %s", stderr)
	}
}

func TestExport_JSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)

	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	ct, nonce, _ := eng.Encrypt([]byte("jsonpass"), key)
	meta := secret.MarshalPasswordMetadata(&secret.PasswordMetadata{
		URL:      "https://json.test",
		Username: "jsonuser",
	})
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "JSONTest",
		Kind:           secret.KindPassword,
		EncryptedValue: packEnvelope(nonce, ct),
		Tags:           "json",
		Notes:          "json note",
		Metadata:       meta,
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	_, _, err := executeCmdWithOutput("export", "--format", "json", "--vault-path", vaultPath, "--output", tmpDir, "--force")
	if err != nil {
		t.Fatalf("export json failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(tmpDir, "vlt-export.json"))
	if err != nil {
		t.Fatalf("read export json: %v", err)
	}
	stdout := string(data)

	var exported []map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &exported); err != nil {
		t.Fatalf("unmarshal json output: %v", err)
	}
	if len(exported) == 0 {
		t.Fatal("expected at least 1 exported secret")
	}

	found := false
	for _, item := range exported {
		if item["Title"] == "JSONTest" {
			found = true
			if item["Url"] != "https://json.test" {
				t.Errorf("url: got %q", item["Url"])
			}
			if item["Username"] != "jsonuser" {
				t.Errorf("username: got %q", item["Username"])
			}
			if item["Password"] != "jsonpass" {
				t.Errorf("password: got %q", item["Password"])
			}
			if item["Tags"] != "json" {
				t.Errorf("tags: got %q", item["Tags"])
			}
			if item["Notes"] != "json note" {
				t.Errorf("notes: got %q", item["Notes"])
			}
		}
	}
	if !found {
		t.Error("JSONTest not found in JSON export")
	}
}

func TestExport_File(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	outputDir := t.TempDir()

	s := initVault(t, vaultPath, testMasterPassword)

	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	// Add a certificate and an SSH key
	certPEM := genCertPEM("export.test", 2048,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(365*24*time.Hour),
		[]string{"export.test"})
	ctC, nonceC, _ := eng.Encrypt(certPEM, key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "my-cert",
		Kind:           secret.KindCertificate,
		EncryptedValue: packEnvelope(nonceC, ctC),
	})

	// Also add a password (should not get exported as file)
	ctP, nonceP, _ := eng.Encrypt([]byte("should-not-export"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "my-password",
		Kind:           secret.KindPassword,
		EncryptedValue: packEnvelope(nonceP, ctP),
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	_, stderr, err := executeCmdWithOutput("export", "--kind", "certificate", "--output", outputDir, "--vault-path", vaultPath, "--force")
	if err != nil {
		t.Fatalf("export certificate failed: %v", err)
	}

	// Check the file was created
	certFile := filepath.Join(outputDir, "my-cert.pem")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Fatalf("expected cert file at %s, not found", certFile)
	}
	written, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read exported cert: %v", err)
	}
	if string(written) != string(certPEM) {
		t.Errorf("exported PEM content mismatch")
	}

	// Check warning in stderr
	if !strings.Contains(stderr, "WARNING") {
		t.Errorf("expected WARNING in stderr, got: %s", stderr)
	}

	// Verify password was NOT exported as file
	passFile := filepath.Join(outputDir, "my-password.txt")
	if _, err := os.Stat(passFile); err == nil {
		t.Error("password should not have been exported as file when --kind certificate is used")
	}
}

func TestExport_File_SSHKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	outputDir := t.TempDir()

	s := initVault(t, vaultPath, testMasterPassword)

	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))

	sshKey, err := marshalSSHPriv(generateRSA(2048), "export-test-key")
	if err != nil {
		t.Fatalf("generate SSH key: %v", err)
	}
	ct, nonce, _ := eng.Encrypt(sshKey, key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "my-ssh-key",
		Kind:           secret.KindSSHKey,
		EncryptedValue: packEnvelope(nonce, ct),
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	_, stderr, err := executeCmdWithOutput("export", "--kind", "ssh_key", "--output", outputDir, "--vault-path", vaultPath, "--force")
	if err != nil {
		t.Fatalf("export ssh_key failed: %v", err)
	}

	keyFile := filepath.Join(outputDir, "my-ssh-key.key")
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		// Try .pem fallback
		keyFile = filepath.Join(outputDir, "my-ssh-key.pem")
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			t.Fatal("exported SSH key file not found")
		}
	}
	written, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read exported key: %v", err)
	}
	if string(written) != string(sshKey) {
		t.Errorf("exported SSH key content mismatch")
	}

	if !strings.Contains(stderr, "WARNING") {
		t.Errorf("expected WARNING in stderr, got: %s", stderr)
	}
}

func TestExport_FormatFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))
	ct, nonce, _ := eng.Encrypt([]byte("fmtpass"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "FormatTest",
		Kind:           secret.KindPassword,
		EncryptedValue: packEnvelope(nonce, ct),
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Test --kind password --format json
	_, _, err := executeCmdWithOutput("export", "--kind", "password", "--format", "json", "--vault-path", vaultPath, "--output", tmpDir, "--force")
	if err != nil {
		t.Fatalf("export --kind password --format json failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(tmpDir, "vlt-export.json"))
	if err != nil {
		t.Fatalf("read export json: %v", err)
	}
	stdout := string(data)
	var items []map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &items); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if len(items) == 0 {
		t.Error("expected items in json output")
	}
}

// ---------------------------------------------------------------------------
// Round-trip: import → export → compare
// ---------------------------------------------------------------------------

func TestImportExport_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	// Create import JSON
	importData := []byte(`[
		{"Title":"RoundTrip1","Url":"https://rt1.com","Username":"rtuser1","Password":"rtpass1","OTPAuth":"rtotp1","Tags":"rt1","Notes":"rt note 1"},
		{"Title":"RoundTrip2","Url":"https://rt2.com","Username":"rtuser2","Password":"rtpass2","OTPAuth":"","Tags":"rt2a,rt2b","Notes":"rt note 2"}
	]`)
	importFile := filepath.Join(fixtureDir, "import.json")
	if err := os.WriteFile(importFile, importData, 0o600); err != nil {
		t.Fatalf("write import json: %v", err)
	}

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Import
	err := executeCmd("import", importFile, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	// Export to JSON
	_, _, err = executeCmdWithOutput("export", "--format", "json", "--vault-path", vaultPath, "--output", tmpDir, "--force")
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(tmpDir, "vlt-export.json"))
	if err != nil {
		t.Fatalf("read export json: %v", err)
	}
	stdout := string(data)

	var exported []map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &exported); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}

	// Verify exported data matches imported (except OTPAuth empty vs missing)
	for _, exp := range exported {
		title, _ := exp["Title"].(string)
		switch title {
		case "RoundTrip1":
			if exp["Url"] != "https://rt1.com" {
				t.Errorf("RoundTrip1 url: got %v", exp["Url"])
			}
			if exp["Username"] != "rtuser1" {
				t.Errorf("RoundTrip1 username: got %v", exp["Username"])
			}
			if exp["Password"] != "rtpass1" {
				t.Errorf("RoundTrip1 password: got %v", exp["Password"])
			}
			if exp["OTPAuth"] != "rtotp1" {
				t.Errorf("RoundTrip1 otpauth: got %v", exp["OTPAuth"])
			}
		case "RoundTrip2":
			if exp["Url"] != "https://rt2.com" {
				t.Errorf("RoundTrip2 url: got %v", exp["Url"])
			}
			if exp["Username"] != "rtuser2" {
				t.Errorf("RoundTrip2 username: got %v", exp["Username"])
			}
			if exp["Password"] != "rtpass2" {
				t.Errorf("RoundTrip2 password: got %v", exp["Password"])
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Export confirmation tests
// ---------------------------------------------------------------------------

func TestExport_ConfirmForceFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	eng := crypto.NewEngine(nil)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), mustGetSalt(t, s))
	ct, nonce, _ := eng.Encrypt([]byte("testpass"), key)
	storeSecretForTest(t, s, eng, key, secret.Secret{
		Name:           "TestSecret",
		Kind:           secret.KindPassword,
		EncryptedValue: packEnvelope(nonce, ct),
	})
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Without --force in non-interactive mode (stdin is not a terminal in tests),
	// export should fail because it requires confirmation.
	outputDir := t.TempDir()
	err := executeCmd("export", "--vault-path", vaultPath, "--output", outputDir)
	if err == nil {
		t.Fatal("expected error without --force in non-interactive mode, got nil")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("expected error mentioning --force, got: %v", err)
	}

	// With --force, should succeed
	outputDir2 := t.TempDir()
	err = executeCmd("export", "--vault-path", vaultPath, "--output", outputDir2, "--force")
	if err != nil {
		t.Fatalf("export with --force failed: %v", err)
	}
}

func TestExport_ForceFlagSkipsConfirm(t *testing.T) {
	// Test the confirmExport function directly
	err := confirmExport(5, true) // force=true
	if err != nil {
		t.Errorf("expected nil with force=true, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Missing required fields
// ---------------------------------------------------------------------------

func TestImport_MissingFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")
	fixtureDir := t.TempDir()

	// CSV with empty title and empty password
	csvContent := []byte("Title;Url;Username;Password;OTPAuth;Favorite;Archived;Tags;Notes\n" +
		";https://x.com;user;;;FALSE;FALSE;;\n") // empty title and password
	csvFile := filepath.Join(fixtureDir, "bad.csv")
	if err := os.WriteFile(csvFile, csvContent, 0o600); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	_, stderr, err := executeCmdWithOutput("import", csvFile, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("import with bad data: %v", err)
	}
	// Should report errors
	if !strings.Contains(stderr, "error") && !strings.Contains(stderr, "Error") &&
		!strings.Contains(stderr, "skipped") && !strings.Contains(stderr, "0 imported") {
		t.Logf("stderr for bad data: %s", stderr)
	}
}

// ---------------------------------------------------------------------------
// Import sample real export CSV if present
// ---------------------------------------------------------------------------

func TestImport_RealExportCSV(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	// Use the actual file in project root if present
	csvFile := "../../test_export.csv"
	if _, err := os.Stat(csvFile); os.IsNotExist(err) {
		t.Skip("test_export.csv not found, skipping")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	err := executeCmd("import", csvFile, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("import real csv failed: %v", err)
	}

	// Verify the secret was imported correctly
	s2, err := openStore(vaultPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s2.Close() }()

	eng := crypto.NewEngine(nil)
	salt := mustGetSalt(t, s2)
	key, _ := eng.DeriveKey([]byte(testMasterPassword), salt)
	defer crypto.Zeroize(key)
	sec, err := getByName(s2, key, "Movie.com")
	if err != nil {
		t.Fatalf("get Movie.com: %v", err)
	}
	if sec.Kind != secret.KindPassword {
		t.Errorf("expected kind=password, got %q", sec.Kind)
	}

	// Decrypt and check password
	nonce, ct, _ := unpackEnvelope(sec.EncryptedValue)
	plaintext, err := eng.Decrypt(ct, key, nonce)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plaintext) != "SXTfSNfmkaX7r8K" {
		t.Errorf("password mismatch: got %q", string(plaintext))
	}
}
