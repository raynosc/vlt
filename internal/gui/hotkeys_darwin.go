//go:build darwin

package gui

/*
#cgo darwin LDFLAGS: -framework Carbon
#include <Carbon/Carbon.h>

extern void onDarwinHotKeyTriggered(uint32_t id);

static OSStatus darwinHotKeyHandler(EventHandlerCallRef nextHandler, EventRef theEvent, void *userData) {
    EventHotKeyID hkID;
    GetEventParameter(theEvent, kEventParamDirectObject, typeEventHotKeyID, NULL, sizeof(hkID), NULL, &hkID);
    onDarwinHotKeyTriggered(hkID.id);
    return noErr;
}

static void installDarwinHandler() {
    static int installed = 0;
    if (!installed) {
        EventTypeSpec eventType;
        eventType.eventClass = kEventClassKeyboard;
        eventType.eventKind = kEventHotKeyPressed;
        InstallApplicationEventHandler(&darwinHotKeyHandler, 1, &eventType, NULL, NULL);
        installed = 1;
    }
}

static EventHotKeyRef registerDarwinCarbonHotKey(uint32_t id, uint32_t keyCode, uint32_t modifiers) {
    installDarwinHandler();
    EventHotKeyID hkID;
    hkID.signature = 'VLTH';
    hkID.id = id;
    EventHotKeyRef ref = NULL;
    OSStatus err = RegisterEventHotKey(keyCode, modifiers, hkID, GetApplicationEventTarget(), 0, &ref);
    if (err != noErr) {
        return NULL;
    }
    return ref;
}

static void unregisterDarwinCarbonHotKey(EventHotKeyRef ref) {
    if (ref != NULL) {
        UnregisterEventHotKey(ref);
    }
}
*/
import "C"
import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/raynosc/vlt/internal/config"
)

var (
	darwinHotkeyMu sync.Mutex
	darwinQuickCb  func()
	darwinMainCb   func()
)

//export onDarwinHotKeyTriggered
func onDarwinHotKeyTriggered(id C.uint32_t) {
	darwinHotkeyMu.Lock()
	qCb := darwinQuickCb
	mCb := darwinMainCb
	darwinHotkeyMu.Unlock()

	switch uint32(id) {
	case 1:
		if qCb != nil {
			qCb()
		}
	case 2:
		if mCb != nil {
			mCb()
		}
	}
}

// GlobalHotkeyManager manages OS-level global hotkeys registration and event dispatching.
type GlobalHotkeyManager struct {
	mu           sync.Mutex
	quickRef     unsafe.Pointer
	mainRef      unsafe.Pointer
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

	darwinHotkeyMu.Lock()
	darwinQuickCb = m.onQuickPress
	darwinMainCb = m.onMainPress
	darwinHotkeyMu.Unlock()

	m.stopInternal()

	// Register Quick Access (ID 1)
	quickKey, quickMods, err := parseCarbonHotkey(cfg.QuickAccess)
	if err == nil {
		ref := C.registerDarwinCarbonHotKey(1, C.uint32_t(quickKey), C.uint32_t(quickMods))
		if ref != nil {
			m.quickRef = unsafe.Pointer(ref)
			fmt.Printf("[Hotkeys] Registered QuickAccess (%s)\n", cfg.QuickAccess)
		} else {
			fmt.Printf("[Hotkeys] Failed to register QuickAccess (%s)\n", cfg.QuickAccess)
		}
	}

	// Register Main Window (ID 2)
	mainKey, mainMods, err := parseCarbonHotkey(cfg.MainWindow)
	if err == nil {
		ref := C.registerDarwinCarbonHotKey(2, C.uint32_t(mainKey), C.uint32_t(mainMods))
		if ref != nil {
			m.mainRef = unsafe.Pointer(ref)
			fmt.Printf("[Hotkeys] Registered MainWindow (%s)\n", cfg.MainWindow)
		} else {
			fmt.Printf("[Hotkeys] Failed to register MainWindow (%s)\n", cfg.MainWindow)
		}
	}

	return nil
}

func (m *GlobalHotkeyManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopInternal()
}

func (m *GlobalHotkeyManager) stopInternal() {
	if m.quickRef != nil {
		C.unregisterDarwinCarbonHotKey(C.EventHotKeyRef(m.quickRef))
		m.quickRef = nil
	}
	if m.mainRef != nil {
		C.unregisterDarwinCarbonHotKey(C.EventHotKeyRef(m.mainRef))
		m.mainRef = nil
	}
}

// Carbon keycodes and modifiers
const (
	carbonCmdKey     = 0x0100 // cmdKey
	carbonShiftKey   = 0x0200 // shiftKey
	carbonOptionKey  = 0x0800 // optionKey
	carbonControlKey = 0x1000 // controlKey
)

func parseCarbonHotkey(s string) (uint32, uint32, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, 0, errors.New("empty hotkey string")
	}

	parts := strings.Split(s, "+")
	var mods uint32
	var keyCode uint32
	var keyFound bool

	for _, p := range parts {
		p = strings.TrimSpace(p)
		switch p {
		case "shift":
			mods |= carbonShiftKey
		case "cmd", "command", "super", "win":
			mods |= carbonCmdKey
		case "ctrl", "control":
			mods |= carbonControlKey
		case "alt", "option", "opt":
			mods |= carbonOptionKey
		default:
			code, err := parseCarbonKeyCode(p)
			if err != nil {
				return 0, 0, err
			}
			keyCode = code
			keyFound = true
		}
	}

	if !keyFound {
		return 0, 0, fmt.Errorf("no primary key found in %q", s)
	}

	return keyCode, mods, nil
}

func parseCarbonKeyCode(name string) (uint32, error) {
	switch strings.ToLower(name) {
	case "space":
		return 49, nil // kVK_Space
	case "a":
		return 0, nil
	case "s":
		return 1, nil
	case "d":
		return 2, nil
	case "f":
		return 3, nil
	case "h":
		return 4, nil
	case "g":
		return 5, nil
	case "z":
		return 6, nil
	case "x":
		return 7, nil
	case "c":
		return 8, nil
	case "v":
		return 9, nil
	case "b":
		return 11, nil
	case "q":
		return 12, nil
	case "w":
		return 13, nil
	case "e":
		return 14, nil
	case "r":
		return 15, nil
	case "y":
		return 16, nil
	case "t":
		return 17, nil
	case "1":
		return 18, nil
	case "2":
		return 19, nil
	case "3":
		return 20, nil
	case "4":
		return 21, nil
	case "6":
		return 22, nil
	case "5":
		return 23, nil
	case "9":
		return 25, nil
	case "7":
		return 26, nil
	case "8":
		return 28, nil
	case "0":
		return 29, nil
	case "o":
		return 31, nil
	case "u":
		return 32, nil
	case "i":
		return 34, nil
	case "p":
		return 35, nil
	case "l":
		return 37, nil
	case "j":
		return 38, nil
	case "k":
		return 40, nil
	case "n":
		return 45, nil
	case "m":
		return 46, nil
	case "return", "enter":
		return 36, nil // kVK_Return
	case "esc", "escape":
		return 53, nil // kVK_Escape
	default:
		return 0, fmt.Errorf("unsupported carbon key: %s", name)
	}
}
