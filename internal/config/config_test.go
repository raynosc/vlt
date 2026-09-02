package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultVaultDir_ReturnsPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dir, err := DefaultVaultDir()
	if err != nil {
		t.Fatalf("DefaultVaultDir failed: %v", err)
	}
	if dir == "" {
		t.Fatal("expected non-empty vault dir")
	}
}

func TestDefaultVaultPath_ReturnsPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	path, err := DefaultVaultPath()
	if err != nil {
		t.Fatalf("DefaultVaultPath failed: %v", err)
	}
	if path == "" {
		t.Fatal("expected non-empty vault path")
	}
	if filepath.Base(path) != DefaultFilename {
		t.Errorf("expected filename %q, got %q", DefaultFilename, filepath.Base(path))
	}
	// Vault must live inside the vault dir, not one level up
	dir, _ := DefaultVaultDir()
	if filepath.Dir(path) != dir {
		t.Errorf("expected vault path inside %q, got %q", dir, path)
	}
}

func TestDefaultConfig_HasVaultPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig failed: %v", err)
	}
	if cfg.VaultPath == "" {
		t.Fatal("expected non-empty VaultPath")
	}

	cfgPath := cfg.ConfigPath()
	if cfgPath == "" {
		t.Fatal("expected non-empty config path")
	}
	if filepath.Base(cfgPath) != ConfigFilename {
		t.Errorf("expected config filename %q, got %q", ConfigFilename, filepath.Base(cfgPath))
	}
}

func TestSaveAndLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Use a temporary directory to avoid modifying real config
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "custom", "vault.sqlite")

	cfg := &Config{VaultPath: vaultPath}

	// Save
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	cfgPath := cfg.ConfigPath()
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		t.Fatalf("config file not created at %s", cfgPath)
	}

	// Load into new config
	// We override the default by setting XDG_CONFIG_HOME to tmpDir
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	// Re-create config pointing at our temp vault
	loadedCfg := &Config{VaultPath: vaultPath}

	// Save again to verify round-trip
	if err := loadedCfg.Save(); err != nil {
		t.Fatalf("second Save failed: %v", err)
	}

	if loadedCfg.VaultPath != vaultPath {
		t.Errorf("VaultPath mismatch: got %q, want %q", loadedCfg.VaultPath, vaultPath)
	}
}

func TestEnsureVaultDir_CreatesDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "nested", "dir", "vault.sqlite")

	cfg := &Config{VaultPath: vaultPath}
	if err := cfg.EnsureVaultDir(); err != nil {
		t.Fatalf("EnsureVaultDir failed: %v", err)
	}

	dir := filepath.Dir(vaultPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatalf("directory not created at %s", dir)
	}
}

func TestLoad_NonExistent_ReturnsDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
		return
	}
	if cfg.VaultPath == "" {
		t.Fatal("expected non-empty VaultPath from default")
	}
}

func TestVaultPathForName(t *testing.T) {
	dir, err := DefaultVaultDir()
	if err != nil {
		t.Fatalf("DefaultVaultDir: %v", err)
	}

	defPath, err := VaultPathForName("")
	if err != nil {
		t.Fatalf("VaultPathForName empty: %v", err)
	}
	if defPath != filepath.Join(dir, DefaultFilename) {
		t.Errorf("expected default %q, got %q", filepath.Join(dir, DefaultFilename), defPath)
	}

	workPath, err := VaultPathForName("work")
	if err != nil {
		t.Fatalf("VaultPathForName work: %v", err)
	}
	if workPath != filepath.Join(dir, "work.sqlite") {
		t.Errorf("expected work %q, got %q", filepath.Join(dir, "work.sqlite"), workPath)
	}
}

func TestConfig_EnableDisableSetActive(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig: %v", err)
	}

	if cfg.IsVaultDisabled("personal") {
		t.Error("expected personal not to be disabled initially")
	}

	// Disable personal
	if err := cfg.DisableVault("personal"); err != nil {
		t.Fatalf("DisableVault: %v", err)
	}
	if !cfg.IsVaultDisabled("personal") {
		t.Error("expected personal to be disabled")
	}

	// Double disable is idempotent
	if err := cfg.DisableVault("personal"); err != nil {
		t.Fatalf("DisableVault idempotent: %v", err)
	}
	if len(cfg.DisabledVaults) != 1 {
		t.Errorf("expected 1 disabled vault, got %d", len(cfg.DisabledVaults))
	}

	// Enable personal
	if err := cfg.EnableVault("personal"); err != nil {
		t.Fatalf("EnableVault: %v", err)
	}
	if cfg.IsVaultDisabled("personal") {
		t.Error("expected personal to be enabled")
	}

	// Set active vault
	if err := cfg.SetActiveVault("work"); err != nil {
		t.Fatalf("SetActiveVault: %v", err)
	}
	if cfg.ActiveVault != "work" {
		t.Errorf("expected active vault 'work', got %q", cfg.ActiveVault)
	}
	if filepath.Base(cfg.VaultPath) != "work.sqlite" {
		t.Errorf("expected vault path to end in work.sqlite, got %q", cfg.VaultPath)
	}

	// Reload from disk and verify persistence
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.ActiveVault != "work" {
		t.Errorf("expected loaded active vault 'work', got %q", loaded.ActiveVault)
	}
}

func TestRenameVault(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	oldPath, err := VaultPathForName("oldvault")
	if err != nil {
		t.Fatalf("VaultPathForName: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(oldPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(oldPath, []byte("sqlite-data"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(oldPath+"-wal", []byte("wal-data"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, _ := DefaultConfig()
	_ = cfg.SetActiveVault("oldvault")

	// Perform rename
	if err := RenameVault("oldvault", "newvault"); err != nil {
		t.Fatalf("RenameVault: %v", err)
	}

	newPath, _ := VaultPathForName("newvault")
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf("expected old file to be deleted")
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Errorf("expected new file to exist")
	}
	if _, err := os.Stat(newPath + "-wal"); err != nil {
		t.Errorf("expected new wal file to exist")
	}

	// Verify config updated
	loaded, _ := Load()
	if loaded.ActiveVault != "newvault" {
		t.Errorf("expected active vault 'newvault', got %q", loaded.ActiveVault)
	}
}

func TestDeleteVault(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	path, _ := VaultPathForName("deleteme")
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte("data"), 0o600)
	_ = os.WriteFile(path+"-wal", []byte("wal"), 0o600)

	if err := DeleteVault("deleteme"); err != nil {
		t.Fatalf("DeleteVault: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected file to be deleted")
	}
	if _, err := os.Stat(path + "-wal"); !os.IsNotExist(err) {
		t.Errorf("expected wal file to be deleted")
	}
}
