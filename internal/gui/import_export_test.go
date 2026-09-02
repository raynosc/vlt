package gui

import (
	"testing"

	"github.com/raynosc/vlt/internal/store"
)

// setupUnlockedApp creates an unlocked App for testing.
func setupUnlockedApp(t *testing.T) (*App, func()) {
	t.Helper()
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

	return app, func() { app.Close() }
}

func TestApp_ImportPasswords_CSV(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	csvData := []byte("Title;Url;Username;Password;OTPAuth;Tags;Notes\n" +
		"github;https://github.com;alice;secret123;;dev;work account\n" +
		"gmail;https://gmail.com;bob;pass456;;personal;email\n")

	result, err := app.ImportPasswords(csvData, ".csv", false)
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	if result.Imported != 2 {
		t.Errorf("expected 2 imported, got %d", result.Imported)
	}
	if result.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", result.Errors)
	}
	if result.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", result.Skipped)
	}

	// Verify secrets were stored
	secrets, err := app.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(secrets) != 2 {
		t.Errorf("expected 2 secrets in vault, got %d", len(secrets))
	}
}

func TestApp_ImportPasswords_CommaCSV(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	csvData := []byte("Title,URL,Username,Password,Notes,OTPAuth\n" +
		"ABITAB,https://abitab.com.uy/,this is not a login form,zcf2KMC1bqe@uzw1rpx,,\n" +
		"Abitab.com,https://abitab.com.uy/,63721782,aqntjste-Q1,,\n" +
		"AC Atlassian,https://id.atlassian.com/,,tax.ftc8ACJ.bvd-btj,,\n")

	result, err := app.ImportPasswords(csvData, ".csv", false)
	if err != nil {
		t.Fatalf("import standard comma csv: %v", err)
	}

	if result.Imported != 3 {
		t.Errorf("expected 3 imported, got %d", result.Imported)
	}
	if result.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", result.Errors)
	}
}

func TestApp_ImportPasswords_BitwardenCSV(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	csvData := []byte("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
		"Personal,,login,Google,Primary email,,0,https://accounts.google.com,user@gmail.com,mySecretPassword123,\n")

	result, err := app.ImportPasswords(csvData, ".csv", false)
	if err != nil {
		t.Fatalf("import bitwarden csv: %v", err)
	}

	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
}

func TestApp_ImportPasswords_JSON(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	jsonData := []byte(`[
		{"Title":"github","Url":"https://github.com","Username":"alice","Password":"secret123","OTPAuth":"","Tags":"dev","Notes":"work"},
		{"Title":"gmail","Url":"https://gmail.com","Username":"bob","Password":"pass456","Tags":"personal","Notes":"email"}
	]`)

	result, err := app.ImportPasswords(jsonData, ".json", false)
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	if result.Imported != 2 {
		t.Errorf("expected 2 imported, got %d", result.Imported)
	}
	if result.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", result.Errors)
	}
}

func TestApp_ImportPasswords_SkipsDuplicates(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	// Inject existing secret
	injectSecretWithMeta(t, app.store, app.engine, app.key, "github", "existing-pass", "password", "alice", "https://github.com", "")

	csvData := []byte("Title;Url;Username;Password;Tags;Notes\ngithub;https://github.com;alice;newpass;;new\n")

	result, err := app.ImportPasswords(csvData, ".csv", false)
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	if result.Imported != 0 {
		t.Errorf("expected 0 imported (duplicate), got %d", result.Imported)
	}
	if result.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", result.Skipped)
	}
}

func TestApp_ImportPasswords_Overwrite(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	injectSecretWithMeta(t, app.store, app.engine, app.key, "github", "old-pass", "password", "alice", "https://github.com", "")

	csvData := []byte("Title;Url;Username;Password;Tags;Notes\ngithub;https://github.com;alice;newpass;;new\n")

	result, err := app.ImportPasswords(csvData, ".csv", true)
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	if result.Imported != 1 {
		t.Errorf("expected 1 imported (overwrite), got %d", result.Imported)
	}
	if result.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", result.Skipped)
	}

	// Verify value was updated
	sec, val, err := app.GetSecret("github")
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if val != "newpass" {
		t.Errorf("expected password 'newpass', got %q", val)
	}
	if sec.Notes != "new" {
		t.Errorf("expected notes 'new', got %q", sec.Notes)
	}
}

func TestApp_ImportPasswords_LockedVault(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	app.Lock()

	_, err := app.ImportPasswords([]byte("x"), ".csv", false)
	if err == nil {
		t.Fatal("expected error for locked vault")
	}
	if err.Error() != "vault is locked" {
		t.Errorf("expected 'vault is locked', got: %v", err)
	}
}

func TestApp_ImportPasswords_InvalidFormat(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	_, err := app.ImportPasswords([]byte("x"), ".txt", false)
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestApp_ExportPasswords_CSV(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	injectSecretWithMeta(t, app.store, app.engine, app.key, "github", "secret123", "password", "alice", "https://github.com", "")
	injectSecretWithMeta(t, app.store, app.engine, app.key, "gmail", "pass456", "password", "bob", "https://gmail.com", "")

	data, count, err := app.ExportPasswords("csv")
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	if count != 2 {
		t.Errorf("expected 2 exported, got %d", count)
	}

	csvStr := string(data)
	if !contains(csvStr, "github") {
		t.Error("expected CSV to contain 'github'")
	}
	if !contains(csvStr, "secret123") {
		t.Error("expected CSV to contain plaintext password")
	}
	if !contains(csvStr, "alice") {
		t.Error("expected CSV to contain username")
	}
}

func TestApp_ExportPasswords_JSON(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	injectSecretWithMeta(t, app.store, app.engine, app.key, "github", "secret123", "password", "alice", "https://github.com", "")

	data, count, err := app.ExportPasswords("json")
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 exported, got %d", count)
	}

	jsonStr := string(data)
	if !contains(jsonStr, "github") {
		t.Error("expected JSON to contain 'github'")
	}
	if !contains(jsonStr, "secret123") {
		t.Error("expected JSON to contain plaintext password")
	}
}

func TestApp_ExportPasswords_LockedVault(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	app.Lock()

	_, _, err := app.ExportPasswords("csv")
	if err == nil {
		t.Fatal("expected error for locked vault")
	}
	if err.Error() != "vault is locked" {
		t.Errorf("expected 'vault is locked', got: %v", err)
	}
}

func TestApp_ExportPasswords_NonPasswordSecrets(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	// Inject a non-password secret
	injectSecret(t, app.store, app.engine, app.key, "ssh-key", "ssh-rsa AAAA...", "ssh_key", "", "")

	data, count, err := app.ExportPasswords("csv")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 exported, got %d", count)
	}
	csvStr := string(data)
	if !contains(csvStr, "ssh-key") {
		t.Error("expected CSV to contain 'ssh-key'")
	}
	if !contains(csvStr, "ssh-rsa AAAA...") {
		t.Error("expected CSV to contain SSH key plaintext")
	}
}

func TestApp_ExportPasswords_IncludesAllKinds(t *testing.T) {
	app, cleanup := setupUnlockedApp(t)
	defer cleanup()

	injectSecretWithMeta(t, app.store, app.engine, app.key, "github", "secret123", "password", "alice", "https://github.com", "")
	injectSecret(t, app.store, app.engine, app.key, "cert", "CERTDATA", "certificate", "", "")
	injectSecret(t, app.store, app.engine, app.key, "ssh", "SSHDATA", "ssh_key", "", "")

	_, count, err := app.ExportPasswords("csv")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 secrets exported (all kinds), got %d", count)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSub(s, substr))
}

func containsSub(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
