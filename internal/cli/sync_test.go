package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncStatus_NotConfigured(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	root := newRootCmd()
	var buf strings.Builder
	root.SetOut(&buf)
	root.SetArgs([]string{
		"sync", "status",
		"--vault-path", vaultPath,
		"--no-keychain",
		"--no-env",
	})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for unconfigured sync, got nil")
	}
	if !strings.Contains(err.Error(), "sync not configured") {
		t.Errorf("expected 'sync not configured' error, got: %v", err)
	}
}

func TestSyncPush_NoSecrets(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := initVault(t, vaultPath, testMasterPassword)

	// Configure sync (won't actually connect). Legacy plaintext seeding here
	// also exercises the lazy migration path added for S-01.
	_ = s.ConfigSet("sync_server_url", []byte("http://localhost:19999"))
	_ = s.ConfigSet("vault_uuid", []byte("test-vault"))
	_ = s.ConfigSet("api_key", []byte("test-api-key"))
	_ = s.ConfigSet("sync_encryption_key", make([]byte, 32))
	_ = s.ConfigSet("last_sync_seq", []byte("0"))
	_ = s.Close()

	// S-01: sync push now requires the vault to be unlocked.
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	root := newRootCmd()
	root.SetArgs([]string{
		"sync", "push",
		"--vault-path", vaultPath,
		"--no-keychain",
		"--insecure",
	})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for empty vault push, got nil")
	}
	// Should fail because vault is empty — no secrets to push
}

func TestSyncPull_Unauthenticated(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := initVault(t, vaultPath, testMasterPassword)

	// Configure sync pointing to a server that will reject us.
	// Legacy plaintext exercises the S-01 lazy-migration path.
	_ = s.ConfigSet("sync_server_url", []byte("http://localhost:19999"))
	_ = s.ConfigSet("vault_uuid", []byte("test-vault"))
	_ = s.ConfigSet("api_key", []byte("invalid-key"))
	_ = s.ConfigSet("sync_encryption_key", make([]byte, 32))
	_ = s.ConfigSet("last_sync_seq", []byte("0"))
	_ = s.Close()

	// S-01: sync pull now requires the vault to be unlocked.
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	root := newRootCmd()
	root.SetArgs([]string{
		"sync", "pull",
		"--vault-path", vaultPath,
		"--no-keychain",
		"--insecure",
	})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for failing pull, got nil")
	}
}

func TestSyncInit_MasksAPIKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Create vault first
	_, stderr, err := executeCmdWithOutput("init", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("init failed: %v (stderr: %s)", err, stderr)
	}

	// Run sync init and capture output
	_, stderr, err = executeCmdWithOutput("sync", "init", "--server", "https://example.com", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("sync init failed: %v (stderr: %s)", err, stderr)
	}

	if !strings.Contains(stderr, "API Key:") {
		t.Fatalf("expected API Key in output, got: %s", stderr)
	}
	// Check that only last 4 chars are visible
	lines := strings.Split(stderr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "API Key:") {
			// Should contain **** and last 4 chars
			if !strings.Contains(line, "****") {
				t.Errorf("expected masked API key with ****, got: %s", line)
			}
			break
		}
	}
}

func TestSyncShowKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	_, _, err := executeCmdWithOutput("init", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	_, _, err = executeCmdWithOutput("sync", "init", "--server", "https://example.com", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("sync init failed: %v", err)
	}

	stdout, _, err := executeCmdWithOutput("sync", "show-key", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("sync show-key failed: %v", err)
	}

	if !strings.Contains(stdout, "API Key:") {
		t.Errorf("expected API Key in output, got: %s", stdout)
	}
}

func TestSyncPush_WithoutInsecure_RejectsHTTP(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.sqlite")
	s := initVault(t, vaultPath, testMasterPassword)

	// Legacy plaintext seeding exercises the S-01 lazy-migration path
	// inside NewClient.
	_ = s.ConfigSet("sync_server_url", []byte("http://localhost:19999"))
	_ = s.ConfigSet("vault_uuid", []byte("test-vault"))
	_ = s.ConfigSet("api_key", []byte("test-api-key"))
	_ = s.ConfigSet("sync_encryption_key", make([]byte, 32))
	_ = s.ConfigSet("last_sync_seq", []byte("0"))
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	root := newRootCmd()
	root.SetArgs([]string{
		"sync", "push",
		"--vault-path", vaultPath,
		"--no-keychain",
	})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for HTTP URL without --insecure, got nil")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("expected HTTPS error, got: %v", err)
	}
}
