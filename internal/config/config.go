// Package config provides vault path resolution and configuration management.
//
// Vault path follows XDG Base Directory Specification:
//   - Linux:   ~/.config/passwd/vault.sqlite
//   - macOS:   ~/Library/Application Support/passwd/vault.sqlite
//   - Other:   XDG_CONFIG_HOME/passwd/vault.sqlite or ~/.config/passwd/vault.sqlite
//
// Named vaults are stored as <name>.sqlite in the same directory.
// Config is stored as JSON in the vault directory.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultFilename is the default SQLite vault database filename.
const DefaultFilename = "vault.sqlite"

// ConfigFilename is the config file name stored alongside the vault.
const ConfigFilename = "config.json"

// VaultInfo describes a discovered vault for the vault list command.
type VaultInfo struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Created  time.Time `json:"created"`
	Disabled bool      `json:"disabled"`
	IsActive bool      `json:"is_active"`
}

// Config holds passwd configuration.
type Config struct {
	// VaultPath is the full path to the SQLite vault database file.
	VaultPath string `json:"vault_path"`

	// ActiveVault is the name of the currently active vault.
	// Empty means the default vault (vault.sqlite).
	ActiveVault string `json:"active_vault,omitempty"`

	// DisabledVaults lists vaults that are disabled/hidden from standard discovery.
	DisabledVaults []string `json:"disabled_vaults,omitempty"`

	// AutoLockMinutes is the inactivity timeout in minutes before locking the vault.
	// 0 means auto-lock is disabled. Defaults to 15 minutes if unconfigured (-1 for explicitly disabled).
	AutoLockMinutes int `json:"auto_lock_minutes,omitempty"`

	// QuickAccessStyle defines the visual theme of Quick Access ("modern" or "classic").
	// Defaults to "modern".
	QuickAccessStyle string `json:"quick_access_style,omitempty"`

	// Hotkeys holds global shortcut combinations for launching views.
	Hotkeys HotkeysConfig `json:"hotkeys,omitempty"`
}

// HotkeysConfig defines configurable key combinations for quick access and main GUI.
type HotkeysConfig struct {
	// QuickAccess shortcut combination (e.g. "shift+cmd+space" or "shift+ctrl+space").
	QuickAccess string `json:"quick_access,omitempty"`
	// MainWindow shortcut combination (e.g. "shift+cmd+v" or "shift+ctrl+v").
	MainWindow string `json:"main_window,omitempty"`
}

const (
	// DefaultHotkeyQuickAccess is the default hotkey for the Quick Access popup.
	DefaultHotkeyQuickAccess = "shift+cmd+space"
	// DefaultHotkeyMainWindow is the default hotkey for the Main Window.
	DefaultHotkeyMainWindow = "shift+cmd+v"
)

// GetHotkeys returns the active hotkeys configuration, filling missing fields with defaults.
func (c *Config) GetHotkeys() HotkeysConfig {
	hk := c.Hotkeys
	if strings.TrimSpace(hk.QuickAccess) == "" {
		hk.QuickAccess = DefaultHotkeyQuickAccess
	}
	if strings.TrimSpace(hk.MainWindow) == "" {
		hk.MainWindow = DefaultHotkeyMainWindow
	}
	return hk
}

// IsVaultDisabled checks if a given vault name is marked disabled in this config.
func (c *Config) IsVaultDisabled(name string) bool {
	for _, v := range c.DisabledVaults {
		if strings.EqualFold(v, name) {
			return true
		}
	}
	return false
}

// EnableVault removes a vault from DisabledVaults and saves the configuration.
func (c *Config) EnableVault(name string) error {
	var updated []string
	for _, v := range c.DisabledVaults {
		if !strings.EqualFold(v, name) {
			updated = append(updated, v)
		}
	}
	c.DisabledVaults = updated
	return c.Save()
}

// DisableVault adds a vault to DisabledVaults and saves the configuration.
func (c *Config) DisableVault(name string) error {
	if !c.IsVaultDisabled(name) {
		c.DisabledVaults = append(c.DisabledVaults, name)
	}
	return c.Save()
}

// SetActiveVault updates the active vault name, vault path, and saves the configuration.
func (c *Config) SetActiveVault(name string) error {
	p, err := VaultPathForName(name)
	if err != nil {
		return err
	}
	c.ActiveVault = name
	c.VaultPath = p
	return c.Save()
}

// DefaultVaultDir returns the vault directory path.
// Prefers XDG_CONFIG_HOME/passwd if set (for tests and advanced users),
// otherwise uses ~/.config/passwd consistently on all platforms
// (macOS, Linux, etc.).
func DefaultVaultDir() (string, error) {
	if xdgHome := os.Getenv("XDG_CONFIG_HOME"); xdgHome != "" {
		return filepath.Join(xdgHome, "passwd"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home dir: %w", err)
	}
	return filepath.Join(home, ".config", "passwd"), nil
}

// DefaultVaultPath returns the default path to the SQLite vault database file.
func DefaultVaultPath() (string, error) {
	dir, err := DefaultVaultDir()
	if err != nil {
		return "", fmt.Errorf("default vault dir: %w", err)
	}
	return filepath.Join(dir, DefaultFilename), nil
}

// DefaultSocketPath returns the default Unix socket path for the daemon.
// The socket lives in the vault config directory (owner-only permissions).
func DefaultSocketPath() (string, error) {
	dir, err := DefaultVaultDir()
	if err != nil {
		return "", fmt.Errorf("default socket dir: %w", err)
	}
	return filepath.Join(dir, "daemon.sock"), nil
}

// VaultPathForName returns the vault path for a named vault or the default.
// If name is empty, returns the default vault path.
// If name is non-empty, returns <dir>/<name>.sqlite.
func VaultPathForName(name string) (string, error) {
	dir, err := DefaultVaultDir()
	if err != nil {
		return "", fmt.Errorf("default vault dir: %w", err)
	}

	if name == "" {
		return filepath.Join(dir, DefaultFilename), nil
	}
	return filepath.Join(dir, name+".sqlite"), nil
}

// DefaultConfig returns a Config with default XDG-based vault path.
func DefaultConfig() (*Config, error) {
	vaultPath, err := DefaultVaultPath()
	if err != nil {
		return nil, err
	}
	return &Config{VaultPath: vaultPath}, nil
}

// ConfigPath returns the path to the config.json file alongside the vault.
func (c *Config) ConfigPath() string {
	return filepath.Join(filepath.Dir(c.VaultPath), ConfigFilename)
}

// VaultsDir returns the directory where all vault files are stored.
func VaultsDir() (string, error) {
	cfg, err := DefaultConfig()
	if err != nil {
		return "", err
	}
	return filepath.Dir(cfg.VaultPath), nil
}

// rawListVaults scans the vault directory without loading full config (used internally to avoid recursion).
func rawListVaults() ([]VaultInfo, error) {
	dir, err := VaultsDir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read vault dir: %w", err)
	}

	var vaults []VaultInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sqlite") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".sqlite")
		if name == "" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}

		vaults = append(vaults, VaultInfo{
			Name:    name,
			Path:    filepath.Join(dir, e.Name()),
			Created: info.ModTime(),
		})
	}

	sort.Slice(vaults, func(i, j int) bool {
		if vaults[i].Name == "vault" {
			return true
		}
		if vaults[j].Name == "vault" {
			return false
		}
		return vaults[i].Name < vaults[j].Name
	})

	return vaults, nil
}

// ListVaults scans the vault directory and returns all discovered vaults with status annotations.
// Returns the default vault first (if it exists), then named vaults sorted by name.
func ListVaults() ([]VaultInfo, error) {
	vaults, err := rawListVaults()
	if err != nil {
		return nil, err
	}

	cfg, _ := loadRaw()
	for i := range vaults {
		name := vaults[i].Name
		if cfg != nil {
			vaults[i].Disabled = cfg.IsVaultDisabled(name)
			if (cfg.ActiveVault == "" && name == "vault") || cfg.ActiveVault == name {
				vaults[i].IsActive = true
			}
		}
	}

	return vaults, nil
}

// ListEnabledVaults returns only enabled vaults discovered in the vault directory.
func ListEnabledVaults() ([]VaultInfo, error) {
	all, err := ListVaults()
	if err != nil {
		return nil, err
	}
	var enabled []VaultInfo
	for _, v := range all {
		if !v.Disabled {
			enabled = append(enabled, v)
		}
	}
	return enabled, nil
}

// VaultDir returns the vault directory path.
func VaultDir() (string, error) {
	return VaultsDir()
}

// loadRaw reads config without performing recovery or calling ListVaults.
func loadRaw() (*Config, error) {
	def, err := DefaultConfig()
	if err != nil {
		return nil, err
	}

	cfgPath := def.ConfigPath()
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return def, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.VaultPath == "" {
		cfg.VaultPath = def.VaultPath
	}

	return &cfg, nil
}

// Load reads config from the default config path with fallback recovery.
func Load() (*Config, error) {
	cfg, err := loadRaw()
	if err != nil {
		return nil, err
	}

	def, err := DefaultConfig()
	if err != nil {
		return nil, err
	}

	// Graceful fallback: if the configured active vault no longer exists on disk,
	// recover by switching to the default vault (vault.sqlite) or the first discovered enabled vault.
	if _, statErr := os.Stat(cfg.VaultPath); os.IsNotExist(statErr) {
		if _, defErr := os.Stat(def.VaultPath); defErr == nil && !cfg.IsVaultDisabled("vault") {
			cfg.VaultPath = def.VaultPath
			cfg.ActiveVault = "vault"
			_ = cfg.Save()
		} else if vaults, listErr := rawListVaults(); listErr == nil && len(vaults) > 0 {
			var target *VaultInfo
			for _, v := range vaults {
				if !cfg.IsVaultDisabled(v.Name) {
					target = &v
					break
				}
			}
			if target == nil {
				target = &vaults[0]
			}
			cfg.VaultPath = target.Path
			cfg.ActiveVault = target.Name
			_ = cfg.Save()
		}
	}

	return cfg, nil
}

// Save writes the config to disk at its config path.
// Creates the directory if it does not exist.
func (c *Config) Save() error {
	path := c.ConfigPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// EnsureVaultDir creates the vault directory if it does not exist.
func (c *Config) EnsureVaultDir() error {
	dir := filepath.Dir(c.VaultPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}
	return nil
}

// VaultNameFromPath extracts the vault name from a vault path.
// e.g. /path/to/work.sqlite -> "work", /path/to/vault.sqlite -> "vault".
func VaultNameFromPath(vaultPath string) string {
	base := filepath.Base(vaultPath)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// RenameVault renames a vault file and any associated WAL/SHM journal files, and updates configuration.
func RenameVault(oldName, newName string) error {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == "" || newName == "" {
		return fmt.Errorf("vault name cannot be empty")
	}
	if strings.ContainsAny(newName, `/\:*?"<>|`) {
		return fmt.Errorf("vault name contains invalid characters")
	}
	if strings.EqualFold(oldName, newName) {
		return nil
	}

	oldPath, err := VaultPathForName(oldName)
	if err != nil {
		return fmt.Errorf("resolve old vault path: %w", err)
	}
	if _, err := os.Stat(oldPath); err != nil {
		return fmt.Errorf("vault %q does not exist", oldName)
	}

	newPath, err := VaultPathForName(newName)
	if err != nil {
		return fmt.Errorf("resolve new vault path: %w", err)
	}
	if _, err := os.Stat(newPath); err == nil {
		return fmt.Errorf("vault %q already exists", newName)
	}

	// Rename main sqlite file
	if err := os.Rename(oldPath, newPath); err != nil {
		return fmt.Errorf("rename vault file: %w", err)
	}

	// Rename WAL/SHM if present
	for _, suffix := range []string{"-wal", "-shm"} {
		oldJournal := oldPath + suffix
		newJournal := newPath + suffix
		if _, err := os.Stat(oldJournal); err == nil {
			_ = os.Rename(oldJournal, newJournal)
		}
	}

	// Update config
	cfg, err := Load()
	if err == nil && cfg != nil {
		changed := false
		if (cfg.ActiveVault == "" && oldName == "vault") || cfg.ActiveVault == oldName {
			cfg.ActiveVault = newName
			cfg.VaultPath = newPath
			changed = true
		}
		for i, d := range cfg.DisabledVaults {
			if strings.EqualFold(d, oldName) {
				cfg.DisabledVaults[i] = newName
				changed = true
			}
		}
		if changed {
			_ = cfg.Save()
		}
	}

	return nil
}

// DeleteVault deletes a vault file and any associated WAL/SHM files, and updates configuration.
func DeleteVault(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("vault name cannot be empty")
	}

	vaultPath, err := VaultPathForName(name)
	if err != nil {
		return fmt.Errorf("resolve vault path: %w", err)
	}
	if _, err := os.Stat(vaultPath); err != nil {
		return fmt.Errorf("vault %q does not exist", name)
	}

	// Remove main sqlite file
	if err := os.Remove(vaultPath); err != nil {
		return fmt.Errorf("delete vault file: %w", err)
	}

	// Remove WAL/SHM if present
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(vaultPath + suffix)
	}

	// Update config
	cfg, err := Load()
	if err == nil && cfg != nil {
		_ = cfg.EnableVault(name)
		if (cfg.ActiveVault == "" && name == "vault") || cfg.ActiveVault == name {
			// Find another vault
			vaults, _ := rawListVaults()
			var fallbackName string
			for _, v := range vaults {
				if v.Name != name && !cfg.IsVaultDisabled(v.Name) {
					fallbackName = v.Name
					break
				}
			}
			if fallbackName != "" {
				_ = cfg.SetActiveVault(fallbackName)
			} else {
				cfg.ActiveVault = ""
				cfg.VaultPath = ""
				_ = cfg.Save()
			}
		}
	}

	return nil
}
