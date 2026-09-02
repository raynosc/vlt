package cli

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/raynosc/vlt/internal/config"
)

// helper to set up isolated XDG config for vault tests
func withTempXDG(t *testing.T, tmpDir string) {
	t.Helper()
	withEnv(t, "XDG_CONFIG_HOME", tmpDir)
}

func TestVault_List(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	withTempXDG(t, tmpDir)
	vaultPath, _ := config.DefaultVaultPath()

	// Create a default vault
	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)
	_, stderr, err := executeCmdWithOutput("vault", "list", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("vault list failed: %v", err)
	}
	if !strings.Contains(stderr, "vault") {
		t.Errorf("expected 'vault' in output, got: %s", stderr)
	}
}

func TestVault_Create(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	withTempXDG(t, tmpDir)
	vaultPath, _ := config.DefaultVaultPath()
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	// Create a default vault first (needed for config)
	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	// Use a unique vault name to avoid collisions with real user vaults
	vaultName := "testvault-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	// Create named vault
	_, stderr, err := executeCmdWithOutput("vault", "create", vaultName, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("vault create failed: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stderr, "Vault created") && !strings.Contains(stderr, "RECOVERY KIT") {
		t.Logf("stderr: %s", stderr)
	}

	// Verify vault file exists
	workPath, _ := config.VaultPathForName(vaultName)
	if _, err := os.Stat(workPath); os.IsNotExist(err) {
		t.Fatalf("expected vault to exist at %s", workPath)
	}

	// Cleanup
	_ = os.Remove(workPath)
	_ = os.Remove(workPath + "-wal")
	_ = os.Remove(workPath + "-shm")
}

func TestVault_Create_Duplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	withTempXDG(t, tmpDir)
	vaultPath, _ := config.DefaultVaultPath()
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	vaultName := "testdup-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	// First create
	_, _, _ = executeCmdWithOutput("vault", "create", vaultName, "--vault-path", vaultPath)
	p, _ := config.VaultPathForName(vaultName)
	defer os.Remove(p)
	defer os.Remove(p + "-wal")
	defer os.Remove(p + "-shm")

	// Second create should fail
	_, _, err := executeCmdWithOutput("vault", "create", vaultName, "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error creating duplicate vault")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}
}

func TestVault_Switch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	withTempXDG(t, tmpDir)
	vaultPath, _ := config.DefaultVaultPath()
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	vaultName := "testswitch-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	// Create named vault
	_, _, _ = executeCmdWithOutput("vault", "create", vaultName, "--vault-path", vaultPath)
	p, _ := config.VaultPathForName(vaultName)
	defer os.Remove(p)
	defer os.Remove(p + "-wal")
	defer os.Remove(p + "-shm")

	// Switch to named vault
	_, stderr, err := executeCmdWithOutput("vault", "switch", vaultName, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("vault switch failed: %v", err)
	}
	if !strings.Contains(stderr, "Switched to vault") {
		t.Errorf("expected 'Switched to vault' in stderr, got: %s", stderr)
	}

	// Verify config
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.ActiveVault != vaultName {
		t.Errorf("expected active vault %q, got %q", vaultName, cfg.ActiveVault)
	}
}

func TestVault_Switch_Nonexistent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	withTempXDG(t, tmpDir)
	vaultPath, _ := config.DefaultVaultPath()
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	_, _, err := executeCmdWithOutput("vault", "switch", "nonexistent", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error switching to nonexistent vault")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected 'does not exist' error, got: %v", err)
	}
}

func TestVault_Remove(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	withTempXDG(t, tmpDir)
	vaultPath, _ := config.DefaultVaultPath()
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	vaultName := "testremove-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	// Create named vault
	_, _, _ = executeCmdWithOutput("vault", "create", vaultName, "--vault-path", vaultPath)
	p, _ := config.VaultPathForName(vaultName)

	// Switch away from it so we can remove it
	_, _, _ = executeCmdWithOutput("vault", "switch", "vault", "--vault-path", vaultPath)

	// Remove with --force
	_, stderr, err := executeCmdWithOutput("vault", "remove", vaultName, "--force", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("vault remove failed: %v", err)
	}
	if !strings.Contains(stderr, "removed") {
		t.Errorf("expected 'removed' in stderr, got: %s", stderr)
	}

	// Verify file is gone
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("expected vault file to be deleted")
	}
}

func TestVault_Remove_ActiveVault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	withTempXDG(t, tmpDir)
	vaultPath, _ := config.DefaultVaultPath()
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	vaultName := "testactive-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	// Create and switch to named vault
	_, _, _ = executeCmdWithOutput("vault", "create", vaultName, "--vault-path", vaultPath)
	p, _ := config.VaultPathForName(vaultName)
	defer os.Remove(p)
	defer os.Remove(p + "-wal")
	defer os.Remove(p + "-shm")
	_, _, _ = executeCmdWithOutput("vault", "switch", vaultName, "--vault-path", vaultPath)

	// Try to remove active vault
	_, _, err := executeCmdWithOutput("vault", "remove", vaultName, "--force", "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error removing active vault")
	}
	if !strings.Contains(err.Error(), "active vault") {
		t.Errorf("expected 'active vault' error, got: %v", err)
	}
}

func TestVault_EnableDisable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	withTempXDG(t, tmpDir)
	vaultPath, _ := config.DefaultVaultPath()
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	vaultName := "testdis-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	_, _, err := executeCmdWithOutput("vault", "create", vaultName, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("vault create: %v", err)
	}

	// Disable vault
	_, stderr, err := executeCmdWithOutput("vault", "disable", vaultName, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("vault disable: %v", err)
	}
	if !strings.Contains(stderr, "disabled") {
		t.Errorf("expected 'disabled' in stderr, got: %s", stderr)
	}

	// Verify in config
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config load: %v", err)
	}
	if !cfg.IsVaultDisabled(vaultName) {
		t.Errorf("expected vault %q to be disabled in config", vaultName)
	}

	// Listing should show disabled status
	_, listStderr, err := executeCmdWithOutput("vault", "list", "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("vault list: %v", err)
	}
	if !strings.Contains(listStderr, "disabled") {
		t.Errorf("expected 'disabled' status in list output, got:\n%s", listStderr)
	}

	// Switching to a disabled vault should fail
	_, _, err = executeCmdWithOutput("vault", "switch", vaultName, "--vault-path", vaultPath)
	if err == nil {
		t.Fatal("expected error when switching to disabled vault")
	}

	// Enable vault
	_, stderr, err = executeCmdWithOutput("vault", "enable", vaultName, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("vault enable: %v", err)
	}
	if !strings.Contains(stderr, "enabled") {
		t.Errorf("expected 'enabled' in stderr, got: %s", stderr)
	}

	// Default / switch should now succeed
	_, stderr, err = executeCmdWithOutput("vault", "default", vaultName, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("vault default: %v", err)
	}
	if !strings.Contains(stderr, "Switched to vault") {
		t.Errorf("expected 'Switched to vault' in stderr, got: %s", stderr)
	}
}

func TestVault_Rename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI integration test in short mode")
	}

	tmpDir := t.TempDir()
	withTempXDG(t, tmpDir)
	vaultPath, _ := config.DefaultVaultPath()
	withEnv(t, "PASSWD_MASTER_PASSWORD", testMasterPassword)

	s := initVault(t, vaultPath, testMasterPassword)
	_ = s.Close()

	oldName := "testren-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	newName := oldName + "-renamed"

	_, _, err := executeCmdWithOutput("vault", "create", oldName, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("vault create: %v", err)
	}

	_, stderr, err := executeCmdWithOutput("vault", "rename", oldName, newName, "--vault-path", vaultPath)
	if err != nil {
		t.Fatalf("vault rename: %v", err)
	}
	if !strings.Contains(stderr, "renamed to") {
		t.Errorf("expected 'renamed to' in stderr, got: %s", stderr)
	}

	// Verify old file gone and new file exists
	oldP, _ := config.VaultPathForName(oldName)
	newP, _ := config.VaultPathForName(newName)
	if _, err := os.Stat(oldP); !os.IsNotExist(err) {
		t.Errorf("expected old vault file to be gone")
	}
	if _, err := os.Stat(newP); err != nil {
		t.Errorf("expected new vault file to exist: %v", err)
	}
}
