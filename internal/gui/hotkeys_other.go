//go:build !darwin

package gui

import (
	"sync"

	"github.com/raynosc/vlt/internal/config"
)

// GlobalHotkeyManager manages OS-level global hotkeys registration and event dispatching.
// On non-macOS platforms, global hotkeys can be extended with native platform hooks.
type GlobalHotkeyManager struct {
	mu           sync.Mutex
	onQuickPress func()
	onMainPress  func()
}

// NewGlobalHotkeyManager creates a new hotkey manager.
func NewGlobalHotkeyManager(onQuickPress, onMainPress func()) *GlobalHotkeyManager {
	return &GlobalHotkeyManager{
		onQuickPress: onQuickPress,
		onMainPress:  onMainPress,
	}
}

// Start registers and listens for hotkeys according to the provided configuration.
func (m *GlobalHotkeyManager) Start(cfg config.HotkeysConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return nil
}

// Stop unregisters all active global hotkeys.
func (m *GlobalHotkeyManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
}
