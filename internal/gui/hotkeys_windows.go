//go:build windows

package gui

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/raynosc/vlt/internal/config"
)

var (
	user32                 = syscall.NewLazyDLL("user32.dll")
	procRegisterHotKey     = user32.NewProc("RegisterHotKey")
	procUnregisterHotKey   = user32.NewProc("UnregisterHotKey")
	procGetMessageW        = user32.NewProc("GetMessageW")
	procPostThreadMessageW = user32.NewProc("PostThreadMessageW")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procGetCurrentThreadId = kernel32.NewProc("GetCurrentThreadId")
)

// Windows Virtual Key codes and modifiers
const (
	modAlt      = 0x0001
	modControl  = 0x0002
	modShift    = 0x0004
	modWin      = 0x0008
	modNoRepeat = 0x4000

	wmHotkey = 0x0312
	wmQuit   = 0x0012

	hotkeyIDQuick = 1
	hotkeyIDMain  = 2
)

type point struct {
	x, y int32
}

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

// GlobalHotkeyManager manages OS-level global hotkeys on Windows via RegisterHotKey.
type GlobalHotkeyManager struct {
	mu           sync.Mutex
	onQuickPress func()
	onMainPress  func()

	threadID   uint32
	readyChan  chan struct{}
	stopChan   chan struct{}
	workerDone chan struct{}

	regQuick bool
	regMain  bool
}

// NewGlobalHotkeyManager creates a new Windows hotkey manager.
func NewGlobalHotkeyManager(onQuickPress, onMainPress func()) *GlobalHotkeyManager {
	return &GlobalHotkeyManager{
		onQuickPress: onQuickPress,
		onMainPress:  onMainPress,
	}
}

// Start registers and listens for Windows hotkeys according to the provided configuration.
func (m *GlobalHotkeyManager) Start(cfg config.HotkeysConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop any existing listener loop
	m.stopInternal()

	quickVK, quickMods, errQuick := parseWindowsHotkey(cfg.QuickAccess)
	mainVK, mainMods, errMain := parseWindowsHotkey(cfg.MainWindow)

	if errQuick != nil && errMain != nil {
		return fmt.Errorf("no valid hotkeys to register: quick err=%v, main err=%v", errQuick, errMain)
	}

	m.readyChan = make(chan struct{})
	m.stopChan = make(chan struct{})
	m.workerDone = make(chan struct{})

	go m.eventLoop(quickVK, quickMods, errQuick == nil, mainVK, mainMods, errMain == nil, cfg)

	// Wait until the Windows message queue is initialized on the dedicated thread
	<-m.readyChan
	return nil
}

// Stop unregisters all active global hotkeys and stops the background message loop.
func (m *GlobalHotkeyManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopInternal()
}

func (m *GlobalHotkeyManager) stopInternal() {
	if m.workerDone == nil {
		return
	}

	// Signal stop and post WM_QUIT to thread message queue
	close(m.stopChan)
	if m.threadID != 0 {
		_, _, _ = procPostThreadMessageW.Call(uintptr(m.threadID), wmQuit, 0, 0)
	}

	<-m.workerDone
	m.workerDone = nil
	m.threadID = 0
}

func (m *GlobalHotkeyManager) eventLoop(quickVK, quickMods uint32, hasQuick bool, mainVK, mainMods uint32, hasMain bool, cfg config.HotkeysConfig) {
	// Lock OS thread because Windows message queues and RegisterHotKey are thread-bound
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(m.workerDone)

	tid, _, _ := procGetCurrentThreadId.Call()
	m.threadID = uint32(tid)

	// Register hotkeys on this thread
	if hasQuick {
		r, _, err := procRegisterHotKey.Call(0, hotkeyIDQuick, uintptr(quickMods|modNoRepeat), uintptr(quickVK))
		if r != 0 {
			m.regQuick = true
			fmt.Printf("[Hotkeys] Registered QuickAccess (%s)\n", cfg.QuickAccess)
		} else {
			// Retry without MOD_NOREPEAT for older Windows versions compatibility
			r2, _, _ := procRegisterHotKey.Call(0, hotkeyIDQuick, uintptr(quickMods), uintptr(quickVK))
			if r2 != 0 {
				m.regQuick = true
				fmt.Printf("[Hotkeys] Registered QuickAccess (%s)\n", cfg.QuickAccess)
			} else {
				fmt.Printf("[Hotkeys] Failed to register QuickAccess (%s): %v\n", cfg.QuickAccess, err)
			}
		}
	}

	if hasMain {
		r, _, err := procRegisterHotKey.Call(0, hotkeyIDMain, uintptr(mainMods|modNoRepeat), uintptr(mainVK))
		if r != 0 {
			m.regMain = true
			fmt.Printf("[Hotkeys] Registered MainWindow (%s)\n", cfg.MainWindow)
		} else {
			r2, _, _ := procRegisterHotKey.Call(0, hotkeyIDMain, uintptr(mainMods), uintptr(mainVK))
			if r2 != 0 {
				m.regMain = true
				fmt.Printf("[Hotkeys] Registered MainWindow (%s)\n", cfg.MainWindow)
			} else {
				fmt.Printf("[Hotkeys] Failed to register MainWindow (%s): %v\n", cfg.MainWindow, err)
			}
		}
	}

	defer func() {
		if m.regQuick {
			_, _, _ = procUnregisterHotKey.Call(0, hotkeyIDQuick)
			m.regQuick = false
		}
		if m.regMain {
			_, _, _ = procUnregisterHotKey.Call(0, hotkeyIDMain)
			m.regMain = false
		}
	}()

	close(m.readyChan)

	var message msg
	for {
		// GetMessage blocks until a message is received or WM_QUIT
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(ret) <= 0 { // 0 = WM_QUIT, -1 = error
			return
		}

		if message.message == wmHotkey {
			switch message.wParam {
			case hotkeyIDQuick:
				if m.onQuickPress != nil {
					m.onQuickPress()
				}
			case hotkeyIDMain:
				if m.onMainPress != nil {
					m.onMainPress()
				}
			}
		}
	}
}

// parseWindowsHotkey parses shortcut strings like "shift+ctrl+space" or "shift+cmd+space"
// (mapping cmd/super/win to Ctrl by default on Windows for seamless cross-platform defaults).
func parseWindowsHotkey(s string) (uint32, uint32, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, 0, errors.New("empty hotkey string")
	}

	parts := strings.Split(s, "+")
	var mods uint32
	var vk uint32
	var keyFound bool

	for _, p := range parts {
		p = strings.TrimSpace(p)
		switch p {
		case "shift":
			mods |= modShift
		case "ctrl", "control":
			mods |= modControl
		case "alt", "option", "opt":
			mods |= modAlt
		case "win", "windows", "super":
			// Windows key modifier
			mods |= modWin
		case "cmd", "command":
			// For cross-platform default consistency, "cmd" on Windows defaults to Control
			mods |= modControl
		default:
			code, err := parseWindowsVirtualKey(p)
			if err != nil {
				return 0, 0, err
			}
			vk = code
			keyFound = true
		}
	}

	if !keyFound {
		return 0, 0, fmt.Errorf("no primary key found in %q", s)
	}

	return vk, mods, nil
}

func parseWindowsVirtualKey(name string) (uint32, error) {
	switch strings.ToLower(name) {
	case "space":
		return 0x20, nil // VK_SPACE
	case "return", "enter":
		return 0x0D, nil // VK_RETURN
	case "esc", "escape":
		return 0x1B, nil // VK_ESCAPE
	case "tab":
		return 0x09, nil // VK_TAB
	case "backspace":
		return 0x08, nil // VK_BACK
	case "a":
		return 0x41, nil
	case "b":
		return 0x42, nil
	case "c":
		return 0x43, nil
	case "d":
		return 0x44, nil
	case "e":
		return 0x45, nil
	case "f":
		return 0x46, nil
	case "g":
		return 0x47, nil
	case "h":
		return 0x48, nil
	case "i":
		return 0x49, nil
	case "j":
		return 0x4A, nil
	case "k":
		return 0x4B, nil
	case "l":
		return 0x4C, nil
	case "m":
		return 0x4D, nil
	case "n":
		return 0x4E, nil
	case "o":
		return 0x4F, nil
	case "p":
		return 0x50, nil
	case "q":
		return 0x51, nil
	case "r":
		return 0x52, nil
	case "s":
		return 0x53, nil
	case "t":
		return 0x54, nil
	case "u":
		return 0x55, nil
	case "v":
		return 0x56, nil
	case "w":
		return 0x57, nil
	case "x":
		return 0x58, nil
	case "y":
		return 0x59, nil
	case "z":
		return 0x5A, nil
	case "0":
		return 0x30, nil
	case "1":
		return 0x31, nil
	case "2":
		return 0x32, nil
	case "3":
		return 0x33, nil
	case "4":
		return 0x34, nil
	case "5":
		return 0x35, nil
	case "6":
		return 0x36, nil
	case "7":
		return 0x37, nil
	case "8":
		return 0x38, nil
	case "9":
		return 0x39, nil
	default:
		return 0, fmt.Errorf("unsupported windows key: %s", name)
	}
}
