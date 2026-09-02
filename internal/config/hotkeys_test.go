package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHotkeysConfig_Defaults(t *testing.T) {
	cfg := &Config{}
	hk := cfg.GetHotkeys()

	if hk.QuickAccess != DefaultHotkeyQuickAccess {
		t.Errorf("expected default QuickAccess %q, got %q", DefaultHotkeyQuickAccess, hk.QuickAccess)
	}
	if hk.MainWindow != DefaultHotkeyMainWindow {
		t.Errorf("expected default MainWindow %q, got %q", DefaultHotkeyMainWindow, hk.MainWindow)
	}
}

func TestHotkeysConfig_CustomValuesAndPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	vaultPath := filepath.Join(tmpDir, "vault.sqlite")

	cfg := &Config{
		VaultPath: vaultPath,
		Hotkeys: HotkeysConfig{
			QuickAccess: "ctrl+shift+k",
			MainWindow:  "ctrl+shift+m",
		},
	}

	if err := cfg.Save(); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	// Read raw config and verify
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to parse config from %s: %v", cfgPath, err)
	}

	hk := loaded.GetHotkeys()
	if hk.QuickAccess != "ctrl+shift+k" {
		t.Errorf("expected custom QuickAccess ctrl+shift+k, got %q", hk.QuickAccess)
	}
	if hk.MainWindow != "ctrl+shift+m" {
		t.Errorf("expected custom MainWindow ctrl+shift+m, got %q", hk.MainWindow)
	}
}
