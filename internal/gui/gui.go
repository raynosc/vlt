// Package gui provides the Fyne-based native GUI for vlt.
//
// It implements all screens: unlock, list, detail, add, edit, and settings,
// plus a system tray menu for background operation.
package gui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"

	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/secret"
	themepkg "github.com/raynosc/vlt/internal/theme"
)

// ── Theme ──

// vltTheme implements fyne.Theme with a glassmorphism dark aesthetic.
type vltTheme struct{}

var _ fyne.Theme = (*vltTheme)(nil)

func (vltTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return themepkg.Purple
	case theme.ColorNameFocus:
		return themepkg.PurpleFocus
	case theme.ColorNamePressed:
		return themepkg.PurplePressed
	case theme.ColorNameSelection:
		return themepkg.PurpleDim
	case theme.ColorNameInputBackground:
		return themepkg.InputBg
	case theme.ColorNameBackground:
		return themepkg.Background
	case theme.ColorNameButton:
		return themepkg.Purple
	case theme.ColorNameDisabledButton:
		return themepkg.DisabledBtn
	case theme.ColorNameHeaderBackground:
		return themepkg.HeaderBg
	case theme.ColorNameMenuBackground:
		return themepkg.MenuBg
	case theme.ColorNameOverlayBackground:
		return themepkg.OverlayBg
	case theme.ColorNameScrollBar:
		return themepkg.PurpleScroll
	case theme.ColorNameSeparator:
		return themepkg.Separator
	case theme.ColorNameShadow:
		return themepkg.Shadow
	case theme.ColorNameSuccess:
		return themepkg.Success
	case theme.ColorNameError:
		return themepkg.Error
	case theme.ColorNameForeground:
		return themepkg.Foreground
	case theme.ColorNamePlaceHolder:
		return themepkg.Muted
	case theme.ColorNameDisabled:
		return themepkg.Muted
	case theme.ColorNameHover:
		return themepkg.GlassBgHover
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (vltTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (vltTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (v vltTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return sizePadding
	case theme.SizeNameInnerPadding:
		return sizeInnerPadding
	case theme.SizeNameScrollBar:
		return sizeScrollBar
	case theme.SizeNameSeparatorThickness:
		return sizeSeparatorThickness
	case theme.SizeNameInputBorder:
		return sizeInputBorder
	case theme.SizeNameInputRadius:
		return sizeInputRadius
	case theme.SizeNameSelectionRadius:
		return sizeCardRadius
	default:
		return theme.DefaultTheme().Size(name)
	}
}

// quickTheme is a tighter variant of vltTheme used exclusively by the
// standalone Quick Access window. It inherits all colors/fonts/icons from
// vltTheme and only shrinks the spacing-related sizes so the popup packs more
// rows with minimal whitespace (compact quick-access look).
//
// It is applied per-process in RunQuick, so it never affects the main GUI.
type quickTheme struct{ vltTheme }

func (quickTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6 // was 14 — outer breathing room
	case theme.SizeNameInnerPadding:
		return 4 // was 10 — inner spacing (drives list row height)
	case theme.SizeNameScrollBar:
		return 6
	case theme.SizeNameSeparatorThickness:
		return sizeSeparatorThickness
	case theme.SizeNameInputBorder:
		return sizeInputBorder
	case theme.SizeNameInputRadius:
		return sizeInputRadius
	case theme.SizeNameSelectionRadius:
		return sizeCardRadius
	default:
		return theme.DefaultTheme().Size(name)
	}
}

// newQuickWindow returns a borderless (frameless) window for the Quick Access
// popup when the underlying driver supports it (desktop). A splash window has
// no title bar / traffic-light buttons, reclaiming that vertical space — and
// matching the chromeless launcher style. On non-desktop drivers (e.g. the
// test driver) it falls back to a normal titled window.
func newQuickWindow(a fyne.App) fyne.Window {
	if drv, ok := a.Driver().(desktop.Driver); ok {
		return drv.CreateSplashWindow()
	}
	return a.NewWindow("Quick Access")
}

// ── GUI App ──

// GUI manages the Fyne application lifecycle and all screens.
type GUI struct {
	fyneApp fyne.App
	window  fyne.Window
	backend *App

	// Screen management
	content *fyne.Container

	// State
	currentScreen      string
	selectedName       string
	activeCategoryID   string
	activeCategoryKind secret.Kind
	selectedNames      map[string]bool

	// Cached secret list
	cachedSecrets []secret.Secret

	// TOTP goroutine lifecycle
	totpCancel context.CancelFunc

	// Quick Access Single-Instance Window
	quickWindow fyne.Window

	// Global OS Hotkeys
	hotkeysManager *GlobalHotkeyManager

	// Single Instance IPC
	ipcSocketPath string
	ipcListener   net.Listener

	// Inactivity Auto-Lock
	activityMu       sync.Mutex
	lastActivity     time.Time
	autoLockMinutes  int
	autoLockStopChan chan struct{}
}

type guiIPCMessage struct {
	Cmd string `json:"cmd"`
}

func defaultGUISocketPath() string {
	dir, err := config.DefaultVaultDir()
	if err != nil {
		vaultDir, _ := config.VaultDir()
		return filepath.Join(vaultDir, "vlt-gui.sock")
	}
	return filepath.Join(dir, "vlt-gui.sock")
}

func ipcNetworkAndAddr(socketPath string) (string, string) {
	if runtime.GOOS == "windows" {
		return "tcp", "127.0.0.1:41882"
	}
	return "unix", socketPath
}

func sendIPCCommand(socketPath, cmd string) bool {
	network, addr := ipcNetworkAndAddr(socketPath)
	conn, err := net.DialTimeout(network, addr, 150*time.Millisecond)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	data, _ := json.Marshal(guiIPCMessage{Cmd: cmd})
	_, err = conn.Write(append(data, '\n'))
	return err == nil
}

func (g *GUI) startIPCServer(socketPath string) {
	network, addr := ipcNetworkAndAddr(socketPath)
	if network == "unix" {
		_ = os.Remove(socketPath)
	}

	l, err := net.Listen(network, addr)
	if err != nil {
		return
	}
	g.ipcListener = l

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go g.handleIPCConnection(conn)
		}
	}()
}

func (g *GUI) handleIPCConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		var msg guiIPCMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err == nil {
			g.recordActivity()
			switch msg.Cmd {
			case "bring_to_front", "show":
				fyne.Do(func() {
					g.window.Show()
					g.window.RequestFocus()
				})
			case "quick":
				fyne.Do(func() {
					g.launchQuick()
				})
			case "lock":
				fyne.Do(func() {
					g.backend.Lock()
					g.showUnlockScreen()
					g.window.Show()
				})
			}
			_, _ = conn.Write([]byte("{\"status\":\"ok\"}\n"))
		}
	}
}

func (g *GUI) startAutoLockTimer() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-g.autoLockStopChan:
				return
			case <-ticker.C:
				g.activityMu.Lock()
				timeoutMins := g.autoLockMinutes
				last := g.lastActivity
				g.activityMu.Unlock()

				if timeoutMins > 0 && g.backend.IsUnlocked() {
					if time.Since(last) >= time.Duration(timeoutMins)*time.Minute {
						fyne.Do(func() {
							if g.backend.IsUnlocked() {
								g.backend.Lock()
								g.showUnlockScreen()
								g.window.Show()
							}
						})
					}
				}
			}
		}
	}()
}

func (g *GUI) recordActivity() {
	g.activityMu.Lock()
	g.lastActivity = time.Now()
	g.activityMu.Unlock()
}

// Run creates and starts the Fyne GUI application.
// This function blocks until the application exits.
func Run(vaultName string, noKeychain bool, socketPath string, minimized ...bool) {
	isMinimized := len(minimized) > 0 && minimized[0]

	if socketPath == "" {
		socketPath = defaultGUISocketPath()
	}

	// ── Single-Instance Check ──
	// If another instance of vlt-gui is already running, notify it and exit immediately.
	if sendIPCCommand(socketPath, "bring_to_front") {
		return
	}

	g := &GUI{}
	g.ipcSocketPath = socketPath

	fyneApp := app.NewWithID("com.passwd.vlt")
	fyneApp.Settings().SetTheme(&vltTheme{})
	fyneApp.SetIcon(AppIconResource)
	g.fyneApp = fyneApp

	backend, err := NewApp(vaultName, noKeychain)
	if err != nil {
		w := fyneApp.NewWindow("vlt — Error")
		w.SetContent(container.NewVBox(
			widget.NewLabelWithStyle("Failed to open vault", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			widget.NewLabel(err.Error()),
			widget.NewLabel("\nRun 'vlt init' to create a new vault."),
			widget.NewButton("Quit", func() { fyneApp.Quit() }),
		))
		w.Resize(fyne.NewSize(420, 200))
		w.CenterOnScreen()
		w.ShowAndRun()
		return
	}
	g.backend = backend
	backend.SetOnActivity(g.recordActivity)

	// Start IPC listener for single-instance control
	g.startIPCServer(socketPath)

	// Initialize Inactivity Auto-Lock
	cfg := backend.Config()
	autoLockMins := 15
	if cfg != nil {
		if cfg.AutoLockMinutes < 0 {
			autoLockMins = 0 // Disabled
		} else if cfg.AutoLockMinutes > 0 {
			autoLockMins = cfg.AutoLockMinutes
		}
	}
	g.autoLockMinutes = autoLockMins
	g.lastActivity = time.Now()
	g.autoLockStopChan = make(chan struct{})
	g.startAutoLockTimer()

	// Initialize and start OS Global Hotkeys
	g.hotkeysManager = NewGlobalHotkeyManager(
		func() {
			fyne.Do(func() {
				g.launchQuick()
			})
		},
		func() {
			fyne.Do(func() {
				g.window.Show()
				g.window.RequestFocus()
			})
		},
	)
	if cfg != nil {
		_ = g.hotkeysManager.Start(cfg.GetHotkeys())
	}

	window := fyneApp.NewWindow("vlt — " + backend.VaultName())
	window.SetCloseIntercept(func() {
		window.Hide()
	})
	g.window = window

	g.setupTray()

	g.content = container.NewStack()
	window.SetContent(g.content)

	if backend.IsUnlocked() {
		window.Resize(fyne.NewSize(960, 680))
		g.showListScreen()
	} else {
		window.Resize(fyne.NewSize(460, 380))
		g.showUnlockScreen()
	}

	window.CenterOnScreen()

	if !isMinimized {
		window.Show()
	}
	fyneApp.Run()

	if g.hotkeysManager != nil {
		g.hotkeysManager.Stop()
	}

	close(g.autoLockStopChan)
	if g.ipcListener != nil {
		_ = g.ipcListener.Close()
		_ = os.Remove(socketPath)
	}
	backend.Close()
}

// ── System Tray ──

func (g *GUI) setupTray() {
	if desk, ok := g.fyneApp.(desktop.App); ok {
		desk.SetSystemTrayIcon(TrayIconResource)

		showItem := fyne.NewMenuItem("Show", func() {
			g.window.Show()
			g.window.RequestFocus()
		})

		quickItem := fyne.NewMenuItem("Quick Access", func() {
			g.launchQuick()
		})

		lockItem := fyne.NewMenuItem("Lock", func() {
			g.backend.Lock()
			g.showUnlockScreen()
			g.window.Show()
			g.window.RequestFocus()
		})

		aboutItem := fyne.NewMenuItem("About", func() {
			dialog.ShowInformation(aboutDialogTitle,
				fmt.Sprintf(aboutDialogTemplate, Version),
				g.window)
		})

		quitItem := fyne.NewMenuItem("Quit", func() {
			g.backend.Close()
			g.fyneApp.Quit()
		})

		menu := fyne.NewMenu("vlt", showItem, quickItem, lockItem, aboutItem, quitItem)
		desk.SetSystemTrayMenu(menu)
	}
}

// ── Quick Access ──

func (g *GUI) launchQuick() {
	if !g.backend.IsUnlocked() {
		g.window.Show()
		g.window.RequestFocus()
		return
	}

	if g.quickWindow != nil {
		g.quickWindow.Hide()
		g.quickWindow.Close()
		g.quickWindow = nil
	}

	w := newQuickWindow(g.fyneApp)
	g.quickWindow = w
	w.SetCloseIntercept(func() {
		w.Hide()
		w.Close()
		if g.quickWindow == w {
			g.quickWindow = nil
		}
	})
	showQuickPopup(w, g.backend)
	w.Show()
	w.RequestFocus()
}

// ── Helpers ──

// buildOTPAuthURI constructs a safe otpauth:// URI using url.URL and url.Values.
func buildOTPAuthURI(name, secret string) string {
	u := &url.URL{
		Scheme: otpScheme,
		Host:   otpHost,
		Path:   "/" + name,
	}
	q := url.Values{}
	q.Set("secret", secret)
	u.RawQuery = q.Encode()
	return u.String()
}

// extractDomain extracts a clean domain from a URL for display in the list view.
// Returns the original string if it can't be parsed as a URL.
func extractDomain(url string) string {
	if url == "" {
		return ""
	}

	// Remove protocol prefix
	domain := url
	for _, prefix := range []string{"https://", "http://", "ftp://", "sftp://"} {
		if strings.HasPrefix(strings.ToLower(domain), prefix) {
			domain = domain[len(prefix):]
			break
		}
	}

	// Remove path and query
	if idx := strings.Index(domain, "/"); idx > 0 {
		domain = domain[:idx]
	}
	if idx := strings.Index(domain, "?"); idx > 0 {
		domain = domain[:idx]
	}

	// Remove port
	if idx := strings.LastIndex(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}

	// Remove leading www.
	if strings.HasPrefix(strings.ToLower(domain), "www.") {
		domain = domain[4:]
	}

	return domain
}

// iconColor returns a deterministic color for a name based on its hash.
func iconColor(name string) color.NRGBA {
	if name == "" {
		return themepkg.Blue
	}

	h := 0
	for i := 0; i < len(name); i++ {
		h = h*31 + int(name[i])
	}

	palette := []color.NRGBA{
		themepkg.Blue,
		themepkg.Orange,
		themepkg.Green,
		themepkg.Red,
		themepkg.PurpleAlt,
		themepkg.Yellow,
		themepkg.LightBlue,
		themepkg.Teal,
	}

	if h < 0 {
		h = -h
	}
	return palette[h%len(palette)]
}

// openBrowser opens a URL in the default browser (macOS).
func openBrowser(url string) error {
	cmd := exec.Command("open", url)
	return cmd.Run()
}

// ── Quick Access Popup ──

// ── Custom Search Entry for Shortcut Interception ──
type quickSearchEntry struct {
	widget.Entry

	// Hooks used by the quick-popup unified keyboard model.
	// When set, navigation/shortcut keys are fully handled by the hook and
	// the base Entry implementation is NOT called (no double-handling).
	keyHook      func(fyne.KeyName)
	shortcutHook func(fyne.Shortcut) bool

	// Legacy callbacks used by the main-window list pane.
	onCopyUsername func()
	onCopyPassword func()
	onUp           func()
	onDown         func()
	onRight        func()
	onEscape       func()
}

func newQuickSearchEntry() *quickSearchEntry {
	e := &quickSearchEntry{}
	e.ExtendBaseWidget(e)
	return e
}

func (e *quickSearchEntry) TypedKey(k *fyne.KeyEvent) {
	// If a unified hook is registered (quick-popup mode), delegate everything
	// for navigation/action keys and swallow them so the base Entry doesn't act.
	if e.keyHook != nil {
		switch k.Name {
		case fyne.KeyUp, fyne.KeyDown, fyne.KeyLeft, fyne.KeyRight,
			fyne.KeyReturn, fyne.KeyEnter, fyne.KeyEscape:
			e.keyHook(k.Name)
			return
		}
		e.Entry.TypedKey(k)
		return
	}

	// Legacy path: individual callbacks for the main-window search entry.
	switch k.Name {
	case fyne.KeyUp:
		if e.onUp != nil {
			e.onUp()
		}
		return
	case fyne.KeyDown:
		if e.onDown != nil {
			e.onDown()
		}
		return
	case fyne.KeyRight:
		if e.onRight != nil {
			e.onRight()
		}
		return
	case fyne.KeyEscape:
		if e.onEscape != nil {
			e.onEscape()
		}
		return
	}
	e.Entry.TypedKey(k)
}

func (e *quickSearchEntry) TypedShortcut(s fyne.Shortcut) {
	// If a unified hook is registered, let it decide first.
	if e.shortcutHook != nil {
		if e.shortcutHook(s) {
			return
		}
		e.Entry.TypedShortcut(s)
		return
	}

	// Legacy path: individual shortcut callbacks for the main-window entry.
	if _, ok := s.(*fyne.ShortcutCopy); ok {
		if e.onCopyUsername != nil {
			e.onCopyUsername()
		}
		return
	}
	if cs, ok := s.(*desktop.CustomShortcut); ok {
		if cs.KeyName == fyne.KeyC && cs.Modifier&(fyne.KeyModifierSuper|fyne.KeyModifierShift) == fyne.KeyModifierSuper|fyne.KeyModifierShift {
			if e.onCopyPassword != nil {
				e.onCopyPassword()
			}
			return
		}
	}
	e.Entry.TypedShortcut(s)
}

// ── Unified Keyboard Model for Quick-Access Popup ──

// quickView distinguishes which screen is active inside the quick-access window.
type quickView int

const (
	quickViewList   quickView = iota
	quickViewDetail           // "more actions" detail screen
)

// quickModel is the shared state for a single quick-access window session.
// Both the list view and the detail view read from / write to this struct so
// shortcuts always act on the current selection without stale closures.
type quickModel struct {
	w        fyne.Window
	backend  *App
	all      []secret.Secret
	filtered []secret.Secret
	selected int
	query    string
	view     quickView
}

// current returns pointers to the currently-selected secret and its parsed
// password metadata. Returns (nil, nil) when nothing is selected or the
// selection is out of range.
func (m *quickModel) current() (*secret.Secret, *secret.PasswordMetadata) {
	if m.selected < 0 || m.selected >= len(m.filtered) {
		return nil, nil
	}
	s := m.filtered[m.selected]
	return &s, secret.UnmarshalPasswordMetadata(s.Metadata)
}

func (m *quickModel) dismiss() {
	if m.w != nil {
		m.w.Hide()
	}
}

// copyUsername copies the username of the selected secret to the clipboard and
// closes the window. No-op if there is no username.
func (m *quickModel) copyUsername() {
	cur, meta := m.current()
	if cur == nil || meta == nil || meta.Username == "" {
		return
	}
	fyne.CurrentApp().Clipboard().SetContent(meta.Username)
	m.dismiss()
}

// copyPassword decrypts and copies the password of the selected secret to the
// clipboard, then closes the window.
func (m *quickModel) copyPassword() {
	cur, _ := m.current()
	if cur == nil {
		return
	}
	_, value, err := m.backend.GetSecret(cur.Name)
	if err != nil {
		return
	}
	fyne.CurrentApp().Clipboard().SetContent(value)
	m.dismiss()
}

// openInBrowser opens the URL of the selected secret in the default browser and
// closes the window. No-op if there is no URL.
func (m *quickModel) openInBrowser() {
	_, meta := m.current()
	if meta == nil || meta.URL == "" {
		return
	}
	_ = openBrowser(meta.URL)
	m.dismiss()
}

// copyTOTP fetches a TOTP code for the selected secret and copies it to the
// clipboard. No-op if there is no OTPAuth field.
func (m *quickModel) copyTOTP() {
	cur, meta := m.current()
	if cur == nil || meta == nil || meta.OTPAuth == "" {
		return
	}
	code, _, err := m.backend.GetTOTP(cur.Name)
	if err != nil {
		return
	}
	fyne.CurrentApp().Clipboard().SetContent(code)
	m.dismiss()
}

// primary is the "default action" for the currently selected item:
//   - list view: open in browser if URL present, else show detail
//   - detail view: open in browser if URL present
func (m *quickModel) primary(showDetailFn func()) {
	_, meta := m.current()
	if meta != nil && meta.URL != "" {
		m.openInBrowser()
		return
	}
	if m.view == quickViewList && showDetailFn != nil {
		showDetailFn()
	}
}

// handleShortcut is the single dispatcher for ⌘-combos. It is called from
// both the search entry's shortcutHook (list view) and canvas.AddShortcut
// (detail view). Returns true if the shortcut was handled.
func (m *quickModel) handleShortcut(s fyne.Shortcut) bool {
	// ⌘ C — copy username
	if _, ok := s.(*fyne.ShortcutCopy); ok {
		m.copyUsername()
		return true
	}
	if cs, ok := s.(*desktop.CustomShortcut); ok {
		switch {
		case cs.KeyName == fyne.KeyC && cs.Modifier == fyne.KeyModifierSuper:
			m.copyUsername()
			return true
		case cs.KeyName == fyne.KeyC && cs.Modifier == fyne.KeyModifierSuper|fyne.KeyModifierShift:
			m.copyPassword()
			return true
		case cs.KeyName == fyne.KeyReturn && cs.Modifier == fyne.KeyModifierSuper:
			m.openInBrowser()
			return true
		case cs.KeyName == fyne.KeyT && cs.Modifier == fyne.KeyModifierSuper:
			m.copyTOTP()
			return true
		}
	}
	return false
}

// handleKey is the single dispatcher for named-key events (no modifiers).
// It is called from both the search entry's keyHook (list view) and
// canvas.SetOnTypedKey (detail view).
func (m *quickModel) handleKey(name fyne.KeyName, listWidget *widget.List, showDetailFn func()) {
	switch name {
	case fyne.KeyEscape:
		m.dismiss()
	case fyne.KeyReturn, fyne.KeyEnter:
		m.primary(showDetailFn)
	case fyne.KeyUp:
		if m.view == quickViewList && len(m.filtered) > 0 {
			if m.selected > 0 {
				m.selected--
			} else {
				m.selected = 0
			}
			listWidget.Select(m.selected)
			listWidget.ScrollTo(m.selected)
			listWidget.Refresh()
		}
	case fyne.KeyDown:
		if m.view == quickViewList && len(m.filtered) > 0 {
			if m.selected < len(m.filtered)-1 {
				m.selected++
			} else {
				m.selected = len(m.filtered) - 1
			}
			listWidget.Select(m.selected)
			listWidget.ScrollTo(m.selected)
			listWidget.Refresh()
		}
	case fyne.KeyRight:
		if m.view == quickViewList && showDetailFn != nil && len(m.filtered) > 0 {
			showDetailFn()
		}
	case fyne.KeyLeft:
		if m.view == quickViewDetail {
			// showDetailFn is nil in detail mode; the caller passes a showList closure instead
			if showDetailFn != nil {
				showDetailFn()
			}
		}
	}
}

func buildKeyCap(label string) fyne.CanvasObject {
	capBg := canvas.NewRectangle(color.NRGBA{R: 0x33, G: 0x33, B: 0x33, A: 0xFF})
	capBg.SetMinSize(fyne.NewSize(20, 20))
	capBg.CornerRadius = 4
	capBorder := canvas.NewRectangle(color.Transparent)
	capBorder.StrokeColor = color.NRGBA{R: 0x44, G: 0x44, B: 0x44, A: 0xFF}
	capBorder.StrokeWidth = 1
	capBorder.CornerRadius = 4

	capText := canvas.NewText(label, color.White)
	capText.TextSize = 10
	capText.TextStyle = fyne.TextStyle{Bold: true}

	return container.NewStack(capBg, capBorder, container.NewCenter(capText))
}

func buildShortcutWidget(keys []string, action string) fyne.CanvasObject {
	var elements []fyne.CanvasObject
	for _, key := range keys {
		elements = append(elements, buildKeyCap(key))
	}
	actionText := canvas.NewText(" "+action, color.NRGBA{R: 0xA1, G: 0xA1, B: 0xAA, A: 0xFF})
	actionText.TextSize = 11
	return container.NewHBox(append(elements, container.NewCenter(actionText))...)
}

// newQuickModel constructs a quickModel for the given window and backend,
// loading all secrets eagerly. Returns nil (and sets an error label) if the
// backend list call fails.
func newQuickModel(w fyne.Window, backend *App) *quickModel {
	secrets, err := backend.List()
	if err != nil {
		w.SetContent(container.NewCenter(
			widget.NewLabel("Failed to load secrets: " + err.Error()),
		))
		return nil
	}
	filtered := make([]secret.Secret, len(secrets))
	copy(filtered, secrets)
	return &quickModel{
		w:        w,
		backend:  backend,
		all:      secrets,
		filtered: filtered,
		selected: 0,
		view:     quickViewList,
	}
}

// showQuickPopup initialises (or re-initialises) the list view of the quick-
// access popup. It is safe to call repeatedly to return from the detail view.
func showQuickPopup(w fyne.Window, backend *App) {
	m := newQuickModel(w, backend)
	if m == nil {
		return
	}
	showQuickPopupWithModel(m)
}

func showQuickPopupWithModel(m *quickModel) {
	if m == nil {
		return
	}
	w := m.w
	backend := m.backend
	w.Resize(fyne.NewSize(600, 460))
	w.CenterOnScreen()
	w.SetFixedSize(true)

	isClassic := false
	if cfg := backend.Config(); cfg != nil && cfg.QuickAccessStyle == "classic" {
		isClassic = true
	}

	// ── Search Bar ──
	searchIcon := widget.NewIcon(theme.SearchIcon())
	searchEntry := newQuickSearchEntry()
	searchEntry.SetPlaceHolder("Search secrets, logins, servers...")
	if m.query != "" {
		searchEntry.Text = m.query
		m.filtered = filterSecrets(m.all, m.query)
	}

	vaultBadgeText := canvas.NewText(" "+backend.VaultName()+" ", color.White)
	vaultBadgeText.TextSize = 10
	vaultBadgeText.TextStyle = fyne.TextStyle{Bold: true}
	vaultBadgeBg := canvas.NewRectangle(themepkg.Blue)
	vaultBadgeBg.CornerRadius = 4
	vaultBadge := container.NewStack(vaultBadgeBg, container.NewCenter(vaultBadgeText))
	vaultBadgeContainer := container.NewCenter(container.NewPadded(vaultBadge))

	searchBoxInner := container.NewBorder(nil, nil, searchIcon, vaultBadgeContainer, searchEntry)
	searchBg := canvas.NewRectangle(themepkg.Surface2)
	searchBg.CornerRadius = 8
	searchBorder := canvas.NewRectangle(color.Transparent)
	searchBorder.StrokeColor = themepkg.GlassBorder
	searchBorder.StrokeWidth = 1
	searchBorder.CornerRadius = 8
	searchBox := container.NewStack(searchBg, searchBorder, container.NewPadded(searchBoxInner))
	if !isClassic {
		searchBox = container.New(layout.NewCustomPaddedLayout(8, 10, 4, 10), searchBox)
	}

	// ── List Widget ──
	// showDetail is a forward closure; we assign it after constructing the list.
	var showDetail func()
	var listWidget *widget.List

	listWidget = widget.NewList(
		func() int { return len(m.filtered) },
		// createItem: single-line row.
		func() fyne.CanvasObject {
			if isClassic {
				iconBox := container.NewStack()

				titleTxt := canvas.NewText("", themepkg.Foreground)
				titleTxt.TextSize = 13
				titleTxt.TextStyle = fyne.TextStyle{Bold: true}

				subLbl := canvas.NewText("", themepkg.Muted)
				subLbl.TextSize = 12

				titleSubRow := container.NewBorder(nil, nil, titleTxt, nil, subLbl)

				openBtn := widget.NewButton("Open", nil)
				openBtn.Importance = widget.HighImportance
				moreBtn := widget.NewButtonWithIcon("", theme.MoreHorizontalIcon(), nil)
				moreBtn.Importance = widget.LowImportance
				actionsBox := container.NewHBox(openBtn, moreBtn)

				row := container.NewBorder(nil, nil, iconBox, actionsBox, titleSubRow)
				return row
			}

			// Modern row: floating pill highlight + inset margins
			rowBg := canvas.NewRectangle(color.Transparent)
			rowBg.CornerRadius = 8

			iconBox := container.NewStack()

			titleTxt := canvas.NewText("", color.White)
			titleTxt.TextSize = 13
			titleTxt.TextStyle = fyne.TextStyle{Bold: true}

			subLbl := canvas.NewText("", color.NRGBA{R: 0x94, G: 0xA3, B: 0xB8, A: 0xFF})
			subLbl.TextSize = 12

			titleSubRow := container.NewBorder(nil, nil, titleTxt, nil, subLbl)

			openBtn := widget.NewButton("Open in Browser", nil)
			openBtn.Importance = widget.HighImportance
			moreBtn := widget.NewButtonWithIcon("", theme.MoreHorizontalIcon(), nil)
			moreBtn.Importance = widget.LowImportance
			actionsBox := container.NewHBox(openBtn, moreBtn)

			innerRow := container.NewBorder(nil, nil, container.New(layout.NewCustomPaddedLayout(3, 3, 0, 10), iconBox), actionsBox, titleSubRow)
			paddedContent := container.New(layout.NewCustomPaddedLayout(4, 4, 10, 10), innerRow)

			return container.NewStack(rowBg, paddedContent)
		},
		// updateItem: populate/refresh a reused row.
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id >= len(m.filtered) {
				return
			}
			sec := m.filtered[id]
			meta := secret.UnmarshalPasswordMetadata(sec.Metadata)

			if isClassic {
				row := obj.(*fyne.Container)
				titleSubRow := row.Objects[0].(*fyne.Container)
				iconBox := row.Objects[1].(*fyne.Container)
				actionsBox := row.Objects[2].(*fyne.Container)

				subText := titleSubRow.Objects[0].(*canvas.Text)
				titleTxt := titleSubRow.Objects[1].(*canvas.Text)

				iconBox.RemoveAll()
				iconBox.Add(FaviconOrBrandIcon(sec, "sm", func() {
					if listWidget != nil {
						listWidget.RefreshItem(id)
					}
				}))
				iconBox.Refresh()

				titleTxt.Text = sec.Name
				titleTxt.Refresh()

				var parts []string
				if meta != nil {
					if meta.Username != "" {
						parts = append(parts, meta.Username)
					}
					if meta.URL != "" {
						parts = append(parts, extractDomain(meta.URL))
					}
				}
				if len(parts) == 0 {
					parts = []string{string(sec.Kind)}
				}
				subText.Text = strings.Join(parts, "  •  ")
				subText.Refresh()

				openBtn := actionsBox.Objects[0].(*widget.Button)
				moreBtn := actionsBox.Objects[1].(*widget.Button)

				if id == m.selected {
					actionsBox.Show()
					if meta != nil && meta.URL != "" {
						openBtn.Show()
						openBtn.OnTapped = func() {
							m.selected = id
							m.openInBrowser()
						}
					} else {
						openBtn.Hide()
					}
					moreBtn.OnTapped = func() {
						m.selected = id
						if showDetail != nil {
							showDetail()
						}
					}
				} else {
					actionsBox.Hide()
				}
				return
			}

			// Modern item update:
			rowStack := obj.(*fyne.Container)
			rowBg := rowStack.Objects[0].(*canvas.Rectangle)
			paddedContent := rowStack.Objects[1].(*fyne.Container)
			innerRow := paddedContent.Objects[0].(*fyne.Container)
			titleSubRow := innerRow.Objects[0].(*fyne.Container)
			iconPadding := innerRow.Objects[1].(*fyne.Container)
			iconBox := iconPadding.Objects[0].(*fyne.Container)
			actionsBox := innerRow.Objects[2].(*fyne.Container)

			subText := titleSubRow.Objects[0].(*canvas.Text)
			titleTxt := titleSubRow.Objects[1].(*canvas.Text)

			iconBox.RemoveAll()
			iconBox.Add(FaviconOrBrandIcon(sec, "sm", func() {
				if listWidget != nil {
					listWidget.RefreshItem(id)
				}
			}))
			iconBox.Refresh()

			titleTxt.Text = sec.Name

			var parts []string
			if meta != nil {
				if meta.Username != "" {
					parts = append(parts, meta.Username)
				}
				if meta.URL != "" {
					parts = append(parts, extractDomain(meta.URL))
				}
			}
			if len(parts) == 0 {
				parts = []string{string(sec.Kind)}
			}
			subText.Text = strings.Join(parts, "  ·  ")

			openBtn := actionsBox.Objects[0].(*widget.Button)
			moreBtn := actionsBox.Objects[1].(*widget.Button)

			if id == m.selected {
				rowBg.FillColor = color.NRGBA{R: 0x0A, G: 0x85, B: 0xEA, A: 0xFF}
				titleTxt.Color = color.White
				subText.Color = color.NRGBA{R: 0xBF, G: 0xDB, B: 0xFE, A: 0xFF}
				actionsBox.Show()

				if meta != nil && meta.URL != "" {
					openBtn.SetText("Open in Browser")
					openBtn.Show()
					openBtn.OnTapped = func() {
						m.selected = id
						m.openInBrowser()
					}
				} else {
					openBtn.SetText("Copy")
					openBtn.Show()
					openBtn.OnTapped = func() {
						m.selected = id
						m.copyPassword()
					}
				}
				moreBtn.OnTapped = func() {
					m.selected = id
					if showDetail != nil {
						showDetail()
					}
				}
			} else {
				rowBg.FillColor = color.Transparent
				titleTxt.Color = color.White
				subText.Color = color.NRGBA{R: 0x94, G: 0xA3, B: 0xB8, A: 0xFF}
				actionsBox.Hide()
			}

			rowBg.Refresh()
			titleTxt.Refresh()
			subText.Refresh()
		},
	)

	listWidget.OnSelected = func(id widget.ListItemID) {
		m.selected = id
		listWidget.Refresh()
	}

	// showDetail navigates to the detail view for the currently selected item.
	showDetail = func() {
		if len(m.filtered) == 0 || m.selected >= len(m.filtered) {
			return
		}
		m.query = searchEntry.Text
		showQuickDetailWithModel(m, m.filtered[m.selected].Name, searchEntry)
	}

	// ── Unified keyboard wiring for LIST view ──
	searchEntry.keyHook = func(name fyne.KeyName) {
		m.backend.RecordActivity()
		m.handleKey(name, listWidget, showDetail)
	}
	searchEntry.shortcutHook = func(s fyne.Shortcut) bool {
		m.backend.RecordActivity()
		return m.handleShortcut(s)
	}

	// ── Search filtering ──
	searchEntry.OnChanged = func(q string) {
		m.backend.RecordActivity()
		m.query = q
		m.selected = 0
		m.filtered = filterSecrets(m.all, q)
		listWidget.Refresh()
		if len(m.filtered) > 0 {
			listWidget.Select(0)
			listWidget.ScrollTo(0)
		}
	}

	searchEntry.OnSubmitted = func(_ string) {
		m.backend.RecordActivity()
		m.primary(showDetail)
	}

	// ── Footer: single compact shortcut row ──
	hintRow := container.NewHBox(
		layout.NewSpacer(),
		buildShortcutWidget([]string{"⌘", "C"}, "Username"),
		separatorDot(),
		buildShortcutWidget([]string{"⌘", "⇧", "C"}, "Password"),
		separatorDot(),
		buildShortcutWidget([]string{"→"}, "Actions"),
		separatorDot(),
		buildShortcutWidget([]string{"Esc"}, "Close"),
		layout.NewSpacer(),
	)

	locatedText := canvas.NewText(fmt.Sprintf(footerLabelTemplate, backend.VaultName()), themepkg.Muted)
	locatedText.TextSize = 11
	locatedText.Alignment = fyne.TextAlignCenter

	footer := container.NewVBox(
		widget.NewSeparator(),
		hintRow,
		container.NewCenter(locatedText),
	)
	if !isClassic {
		footer = container.New(layout.NewCustomPaddedLayout(2, 10, 6, 10), footer)
	}

	// ── Assemble ──
	var listContent fyne.CanvasObject = listWidget
	if !isClassic {
		listContent = container.New(layout.NewCustomPaddedLayout(2, 8, 2, 8), listWidget)
	}
	w.SetContent(container.NewBorder(searchBox, footer, nil, nil, listContent))

	m.view = quickViewList
	w.Canvas().Focus(searchEntry)

	cv := w.Canvas()
	cv.SetOnTypedKey(func(k *fyne.KeyEvent) {
		m.backend.RecordActivity()
		m.handleKey(k.Name, listWidget, showDetail)
	})

	for _, sc := range []*desktop.CustomShortcut{
		{KeyName: fyne.KeyC, Modifier: fyne.KeyModifierSuper},
		{KeyName: fyne.KeyC, Modifier: fyne.KeyModifierSuper | fyne.KeyModifierShift},
		{KeyName: fyne.KeyReturn, Modifier: fyne.KeyModifierSuper},
		{KeyName: fyne.KeyT, Modifier: fyne.KeyModifierSuper},
	} {
		cv.AddShortcut(sc, func(s fyne.Shortcut) { m.handleShortcut(s) })
	}

	if len(m.filtered) > 0 {
		if m.selected < 0 || m.selected >= len(m.filtered) {
			m.selected = 0
		}
		listWidget.Select(m.selected)
		listWidget.ScrollTo(m.selected)
	}
}

// separatorDot returns a small muted dot used as a visual separator between
// hint groups in the footer bar.
func separatorDot() fyne.CanvasObject {
	dot := canvas.NewText("  ·  ", themepkg.Muted)
	dot.TextSize = 11
	return dot
}

// showQuickDetail is the public entry point that constructs a fresh model and
// shows the detail view. Callers outside this file (e.g. tests) use this.
func showQuickDetail(w fyne.Window, backend *App, name string) {
	w.Resize(fyne.NewSize(600, 460))
	w.CenterOnScreen()
	w.SetFixedSize(true)

	m := newQuickModel(w, backend)
	if m == nil {
		return
	}
	for i, s := range m.filtered {
		if s.Name == name {
			m.selected = i
			break
		}
	}
	showQuickDetailWithModel(m, name, nil)
}

// showQuickDetailWithModel renders the detail view using an existing quickModel.
func showQuickDetailWithModel(m *quickModel, name string, searchEntry *quickSearchEntry) {
	sec, password, err := m.backend.GetSecret(name)
	if err != nil {
		return
	}

	meta := secret.UnmarshalPasswordMetadata(sec.Metadata)

	for i, s := range m.filtered {
		if s.Name == name {
			m.selected = i
			break
		}
	}
	m.view = quickViewDetail

	typeIcon := FaviconOrBrandIcon(*sec, "md", nil)

	titleLbl := canvas.NewText(sec.Name, themepkg.Foreground)
	titleLbl.TextSize = 16
	titleLbl.TextStyle = fyne.TextStyle{Bold: true}

	var subParts []string
	if meta != nil {
		if meta.Username != "" {
			subParts = append(subParts, meta.Username)
		}
		if meta.URL != "" {
			subParts = append(subParts, meta.URL)
		}
	}
	subtitle := canvas.NewText(strings.Join(subParts, " — "), themepkg.Muted)
	subtitle.TextSize = 12

	// Clean back button
	backBtn := widget.NewButtonWithIcon("Back", theme.NavigateBackIcon(), func() {
		showQuickPopupWithModel(m)
	})
	backBtn.Importance = widget.LowImportance

	headerBox := container.NewBorder(nil, nil, typeIcon, backBtn,
		container.NewPadded(container.NewVBox(titleLbl, subtitle)))

	headerCardBg := canvas.NewRectangle(themepkg.Surface2)
	headerCardBg.CornerRadius = 8
	headerCard := container.NewStack(headerCardBg, container.NewPadded(headerBox))

	// ── Action Rows ──
	makeActionRow := func(iconRes fyne.Resource, label string, keys []string, onTap func()) fyne.CanvasObject {
		icon := widget.NewIcon(iconRes)
		lbl := canvas.NewText(label, themepkg.Foreground)
		lbl.TextSize = 13
		lbl.TextStyle = fyne.TextStyle{Bold: true}

		var hint fyne.CanvasObject
		if len(keys) > 0 {
			hint = buildShortcutWidget(keys, "")
		} else {
			hint = layout.NewSpacer()
		}

		inner := container.NewBorder(nil, nil, icon, container.NewCenter(hint), container.NewPadded(lbl))
		rowBg := canvas.NewRectangle(themepkg.Surface1)
		rowBg.CornerRadius = 6

		card := container.NewStack(rowBg, container.NewPadded(inner))
		return newTappableRow(card, onTap)
	}

	var copyActions []fyne.CanvasObject
	if meta != nil && meta.Username != "" {
		copyActions = append(copyActions, makeActionRow(theme.ContentCopyIcon(), "Copy Username", []string{"⌘", "C"}, m.copyUsername))
	}
	copyActions = append(copyActions, makeActionRow(theme.VisibilityIcon(), "Copy Password", []string{"⌘", "⇧", "C"}, m.copyPassword))

	var navActions []fyne.CanvasObject
	if meta != nil && meta.URL != "" {
		navActions = append(navActions, makeActionRow(theme.ComputerIcon(), "Open In Browser", []string{"⌘", "↵"}, m.openInBrowser))
	}
	navActions = append(navActions, makeActionRow(theme.ConfirmIcon(), "Autofill & Close", []string{"⇧", "↵"}, func() {
		fyne.CurrentApp().Clipboard().SetContent(password)
		m.dismiss()
	}))
	if meta != nil && meta.OTPAuth != "" {
		navActions = append(navActions, makeActionRow(theme.HistoryIcon(), "Copy TOTP Code", []string{"⌘", "T"}, m.copyTOTP))
	}

	actionList := container.NewVBox(
		canvas.NewText("ACTIONS", themepkg.Muted),
	)
	for _, a := range copyActions {
		actionList.Add(a)
	}
	if len(navActions) > 0 {
		actionList.Add(widget.NewSeparator())
		for _, a := range navActions {
			actionList.Add(a)
		}
	}

	// ── Footer ──
	vaultLabel := canvas.NewText(fmt.Sprintf(footerLabelTemplate, m.backend.VaultName()), themepkg.Muted)
	vaultLabel.TextSize = 11
	// ── Keyboard Shortcuts — DETAIL view ──
	cv := m.w.Canvas()
	cv.SetOnTypedKey(func(k *fyne.KeyEvent) {
		m.backend.RecordActivity()
		showList := func() { showQuickPopupWithModel(m) }
		switch k.Name {
		case fyne.KeyEscape:
			m.dismiss()
		case fyne.KeyLeft:
			showList()
		}
	})

	cv.AddShortcut(&desktop.CustomShortcut{
		KeyName: fyne.KeyC, Modifier: fyne.KeyModifierSuper,
	}, func(s fyne.Shortcut) {
		m.backend.RecordActivity()
		m.handleShortcut(s)
	})

	cv.AddShortcut(&desktop.CustomShortcut{
		KeyName: fyne.KeyC, Modifier: fyne.KeyModifierSuper | fyne.KeyModifierShift,
	}, func(s fyne.Shortcut) {
		m.backend.RecordActivity()
		m.handleShortcut(s)
	})

	cv.AddShortcut(&desktop.CustomShortcut{
		KeyName: fyne.KeyReturn, Modifier: fyne.KeyModifierSuper,
	}, func(s fyne.Shortcut) {
		m.backend.RecordActivity()
		m.handleShortcut(s)
	})

	cv.AddShortcut(&desktop.CustomShortcut{
		KeyName: fyne.KeyT, Modifier: fyne.KeyModifierSuper,
	}, func(s fyne.Shortcut) {
		m.backend.RecordActivity()
		m.handleShortcut(s)
	})

	cv.AddShortcut(&desktop.CustomShortcut{
		KeyName: fyne.KeyReturn, Modifier: fyne.KeyModifierShift,
	}, func(s fyne.Shortcut) {
		fyne.CurrentApp().Clipboard().SetContent(password)
		m.dismiss()
	})

	m.w.Canvas().Unfocus()

	body := container.NewVBox(
		headerCard,
		widget.NewSeparator(),
		actionList,
	)

	m.w.SetContent(container.NewBorder(
		nil,
		container.NewPadded(vaultLabel),
		nil, nil,
		container.NewPadded(container.NewScroll(body)),
	))
}

// filterSecrets filters secrets by name, username, and URL (case-insensitive).
// Returns a new slice — does not modify the input.
// Returns all secrets if query is empty.
func filterSecrets(secrets []secret.Secret, query string) []secret.Secret {
	if secrets == nil {
		return nil
	}
	if query == "" {
		result := make([]secret.Secret, len(secrets))
		copy(result, secrets)
		return result
	}

	lowerQuery := strings.ToLower(query)
	var results []secret.Secret
	for _, s := range secrets {
		if strings.Contains(strings.ToLower(s.Name), lowerQuery) {
			results = append(results, s)
			continue
		}
		// Also match username and URL from metadata
		if meta := secret.UnmarshalPasswordMetadata(s.Metadata); meta != nil {
			if strings.Contains(strings.ToLower(meta.Username), lowerQuery) ||
				strings.Contains(strings.ToLower(meta.URL), lowerQuery) {
				results = append(results, s)
			}
		}
	}
	return results
}

// ── Quick Access Standalone ──

// RunQuick creates and starts the quick access popup.
// If an instance of vlt-gui is already running, it forwards the quick command via IPC and exits immediately.
func RunQuick(vaultName string, noKeychain bool) {
	socketPath := defaultGUISocketPath()
	if sendIPCCommand(socketPath, "quick") {
		return
	}

	fyneApp := app.NewWithID("com.passwd.vlt")
	fyneApp.Settings().SetTheme(&quickTheme{})

	backend, err := NewApp(vaultName, noKeychain)
	if err != nil {
		errW := fyneApp.NewWindow("vlt — Error")
		errW.SetContent(container.NewVBox(
			widget.NewLabelWithStyle("Failed to open vault", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			widget.NewLabel(err.Error()),
			widget.NewLabel("\nRun 'vlt init' to create a new vault."),
			widget.NewButton("Quit", func() { fyneApp.Quit() }),
		))
		errW.Resize(fyne.NewSize(420, 200))
		errW.CenterOnScreen()
		errW.ShowAndRun()
		return
	}
	defer backend.Close()

	window := newQuickWindow(fyneApp)
	window.Resize(fyne.NewSize(600, 460))
	window.CenterOnScreen()
	window.SetFixedSize(true)

	if !backend.IsUnlocked() {
		showQuickUnlock(window, backend)
	} else {
		showQuickPopup(window, backend)
	}

	window.Show()
	fyneApp.Run()
}

// showQuickUnlock displays an unlock prompt inside the given window.
// On successful unlock it transitions to the search popup.
func showQuickUnlock(w fyne.Window, backend *App) {
	currentBackend := backend
	pwEntry := widget.NewEntry()
	pwEntry.SetPlaceHolder("Master password")
	pwEntry.Password = true

	header := widget.NewLabelWithStyle("Quick Access", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	instruction := widget.NewLabel("Enter your master password to unlock.")

	pwEntry.OnSubmitted = func(pw string) {
		if pw == "" {
			return
		}
		if err := currentBackend.Unlock(pw); err != nil {
			pwEntry.SetText("")
			w.Canvas().Focus(pwEntry)
			return
		}
		showQuickPopup(w, currentBackend)
	}

	unlockBtn := widget.NewButton("Unlock", func() {
		pwEntry.OnSubmitted(pwEntry.Text)
	})

	// Discover available enabled vaults
	vaultInfos, _ := config.ListEnabledVaults()
	var vaultSelector fyne.CanvasObject

	if len(vaultInfos) > 1 {
		vaultNames := make([]string, 0, len(vaultInfos))
		for _, v := range vaultInfos {
			vaultNames = append(vaultNames, v.Name)
		}

		selectWidget := widget.NewSelect(vaultNames, func(selected string) {
			if selected == "" || selected == currentBackend.VaultName() {
				return
			}
			newBackend, err := NewApp(selected, false)
			if err != nil {
				return
			}
			currentBackend.Close()
			currentBackend = newBackend
			if cfg, err := config.Load(); err == nil {
				_ = cfg.SetActiveVault(selected)
			}
			pwEntry.SetText("")
			w.Canvas().Focus(pwEntry)
		})
		selectWidget.SetSelected(currentBackend.VaultName())

		vaultSelector = container.NewHBox(
			widget.NewLabelWithStyle("Vault:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			selectWidget,
		)
	} else {
		vaultSelector = widget.NewLabel("Vault: " + currentBackend.VaultName())
	}

	w.SetContent(container.NewBorder(
		container.NewVBox(header, widget.NewSeparator()),
		nil, nil, nil,
		container.NewCenter(container.NewVBox(
			vaultSelector,
			instruction,
			widget.NewLabel(""),
			pwEntry,
			widget.NewLabel(""),
			unlockBtn,
		)),
	))
	w.Canvas().Focus(pwEntry)
	w.RequestFocus()
}

// ── Screen Helpers ──

func (g *GUI) setContent(obj fyne.CanvasObject) {
	g.content.RemoveAll()
	g.content.Add(obj)
	g.content.Refresh()
}

func (g *GUI) navigateTo(screen string) {
	g.currentScreen = screen
}

func (g *GUI) showError(err error) {
	if err != nil && g.window != nil {
		dialog.ShowError(err, g.window)
	}
}

// ── Unlock Screen ──

func (g *GUI) showUnlockScreen() {
	g.navigateTo("unlock")

	cb, _ := g.backend.GetCircuitBreakerState()
	if cb != nil && cb.IsHardLockout {
		g.showHardLockoutScreen()
		return
	}
	if cb != nil && cb.IsPINChallenge {
		g.showPINChallengeScreen()
		return
	}

	if g.window != nil {
		g.window.Resize(fyne.NewSize(420, 360))
		g.window.CenterOnScreen()
	}

	appLogo := NewAppIconImage(56)

	title := canvas.NewText("vlt Password Manager", themepkg.Foreground)
	title.TextSize = 20
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	subtitle := canvas.NewText("Zero-Knowledge Secure Vault", themepkg.Muted)
	subtitle.TextSize = 13
	subtitle.Alignment = fyne.TextAlignCenter

	passwordEntry := widget.NewEntry()
	passwordEntry.SetPlaceHolder("Master password")
	passwordEntry.Password = true
	passwordEntry.OnSubmitted = func(pw string) {
		g.doUnlock(pw, passwordEntry)
	}

	unlockBtn := widget.NewButtonWithIcon("Unlock Vault", theme.ConfirmIcon(), func() {
		g.doUnlock(passwordEntry.Text, passwordEntry)
	})
	unlockBtn.Importance = widget.HighImportance

	// Discover available enabled vaults for unlock dropdown
	vaultInfos, _ := config.ListEnabledVaults()
	var vaultHeader fyne.CanvasObject

	if len(vaultInfos) > 1 {
		vaultNames := make([]string, 0, len(vaultInfos))
		for _, v := range vaultInfos {
			vaultNames = append(vaultNames, v.Name)
		}

		selectWidget := widget.NewSelect(vaultNames, func(selected string) {
			if selected == "" || selected == g.backend.VaultName() {
				return
			}
			g.switchVault(selected)
		})
		selectWidget.SetSelected(g.backend.VaultName())

		vaultHeader = container.NewHBox(
			widget.NewLabelWithStyle("Vault:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			selectWidget,
		)
	} else {
		vaultHeader = widget.NewLabel("Vault: " + g.backend.VaultName())
	}

	formBox := container.NewVBox(
		container.NewCenter(appLogo),
		container.NewCenter(title),
		container.NewCenter(subtitle),
		widget.NewSeparator(),
		vaultHeader,
		passwordEntry,
		unlockBtn,
	)

	cardBg := canvas.NewRectangle(themepkg.Surface2)
	cardBg.CornerRadius = sizeCardRadius

	cardBorder := canvas.NewRectangle(color.Transparent)
	cardBorder.StrokeColor = themepkg.GlassBorder
	cardBorder.StrokeWidth = 1
	cardBorder.CornerRadius = sizeCardRadius

	cardWidth := canvas.NewRectangle(color.Transparent)
	cardWidth.SetMinSize(fyne.NewSize(360, 1))

	unlockCard := container.NewStack(
		cardBg,
		cardBorder,
		cardWidth,
		container.NewPadded(formBox),
	)

	g.setContent(container.NewCenter(unlockCard))
	if g.window != nil {
		g.window.Resize(fyne.NewSize(420, 360))
		g.window.CenterOnScreen()
		g.window.Canvas().Focus(passwordEntry)
		g.window.RequestFocus()
	}
}

// showPINChallengeScreen prompts for the 8-digit PIN after 3 failed master attempts.
func (g *GUI) showPINChallengeScreen() {
	if g.window != nil {
		g.window.Resize(fyne.NewSize(420, 340))
		g.window.CenterOnScreen()
	}

	warnIcon := widget.NewIcon(theme.WarningIcon())
	title := canvas.NewText("Security Circuit Breaker", themepkg.Error)
	title.TextSize = 18
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	desc := canvas.NewText("3 failed attempts detected.\nEnter your 8-digit PIN to unfreeze vault.", themepkg.Foreground)
	desc.TextSize = 13
	desc.Alignment = fyne.TextAlignCenter

	pinEntry := widget.NewEntry()
	pinEntry.SetPlaceHolder("8-digit Security PIN")
	pinEntry.Password = true

	verifyBtn := widget.NewButtonWithIcon("Verify PIN", theme.ConfirmIcon(), func() {
		pin := strings.TrimSpace(pinEntry.Text)
		if pin == "" {
			return
		}
		if err := g.backend.VerifyPIN(pin); err != nil {
			dialog.ShowError(err, g.window)
			g.showUnlockScreen()
			return
		}
		dialog.ShowInformation("PIN Verified", "Circuit breaker cleared. You may now enter your master password.", g.window)
		g.showUnlockScreen()
	})
	verifyBtn.Importance = widget.HighImportance

	rescueBtn := widget.NewButtonWithIcon("Rescue with Recovery Key", theme.HelpIcon(), func() {
		g.showHardLockoutScreen()
	})
	rescueBtn.Importance = widget.LowImportance

	box := container.NewVBox(
		container.NewCenter(warnIcon),
		container.NewCenter(title),
		container.NewCenter(desc),
		widget.NewSeparator(),
		pinEntry,
		verifyBtn,
		rescueBtn,
	)

	cardBg := canvas.NewRectangle(themepkg.Surface2)
	cardBg.CornerRadius = sizeCardRadius
	cardBorder := canvas.NewRectangle(color.Transparent)
	cardBorder.StrokeColor = themepkg.GlassBorder
	cardBorder.StrokeWidth = 1
	cardBorder.CornerRadius = sizeCardRadius
	cardWidth := canvas.NewRectangle(color.Transparent)
	cardWidth.SetMinSize(fyne.NewSize(360, 1))

	g.setContent(container.NewCenter(container.NewStack(cardBg, cardBorder, cardWidth, container.NewPadded(box))))
	if g.window != nil {
		g.window.Canvas().Focus(pinEntry)
	}
}

// showHardLockoutScreen renders the vault rescue screen using the 36-word mnemonic recovery phrase.
func (g *GUI) showHardLockoutScreen() {
	if g.window != nil {
		g.window.Resize(fyne.NewSize(520, 420))
		g.window.CenterOnScreen()
	}

	shieldIcon := widget.NewIcon(theme.WarningIcon())
	title := canvas.NewText("Vault Hard Lockout", themepkg.Error)
	title.TextSize = 20
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	desc := canvas.NewText("This vault is locked due to repeated failed attempts.\nEnter your 36-word Recovery Phrase to restore access:", themepkg.Foreground)
	desc.TextSize = 13
	desc.Alignment = fyne.TextAlignCenter

	phraseEntry := widget.NewMultiLineEntry()
	phraseEntry.SetPlaceHolder("word1 word2 word3 ... word36")
	phraseEntry.Wrapping = fyne.TextWrapWord
	phraseEntry.SetMinRowsVisible(4)

	restoreBtn := widget.NewButtonWithIcon("Rescue & Unlock Vault", theme.ConfirmIcon(), func() {
		phrase := strings.TrimSpace(phraseEntry.Text)
		if phrase == "" {
			dialog.ShowError(fmt.Errorf("please enter your recovery phrase"), g.window)
			return
		}
		if err := g.backend.RescueWithRecoveryKey(phrase); err != nil {
			dialog.ShowError(fmt.Errorf("rescue failed: %w", err), g.window)
			return
		}
		dialog.ShowInformation("Vault Rescued", "Vault lockout cleared successfully! You can now log in with your master password.", g.window)
		g.showUnlockScreen()
	})
	restoreBtn.Importance = widget.DangerImportance

	cancelBtn := widget.NewButton("Back to Login", func() {
		g.showUnlockScreen()
	})

	box := container.NewVBox(
		container.NewCenter(shieldIcon),
		container.NewCenter(title),
		container.NewCenter(desc),
		widget.NewSeparator(),
		phraseEntry,
		restoreBtn,
		cancelBtn,
	)

	cardBg := canvas.NewRectangle(themepkg.Surface2)
	cardBg.CornerRadius = sizeCardRadius
	cardBorder := canvas.NewRectangle(color.Transparent)
	cardBorder.StrokeColor = themepkg.GlassBorder
	cardBorder.StrokeWidth = 1
	cardBorder.CornerRadius = sizeCardRadius
	cardWidth := canvas.NewRectangle(color.Transparent)
	cardWidth.SetMinSize(fyne.NewSize(460, 1))

	g.setContent(container.NewCenter(container.NewStack(cardBg, cardBorder, cardWidth, container.NewPadded(box))))
}

func (g *GUI) doUnlock(password string, entry *widget.Entry) {
	if password == "" {
		return
	}

	if err := g.backend.Unlock(password); err != nil {
		entry.SetText("")
		if g.window != nil {
			g.window.Canvas().Focus(entry)
		}

		cb, _ := g.backend.GetCircuitBreakerState()
		if cb != nil && cb.IsHardLockout {
			g.showHardLockoutScreen()
			return
		}
		if cb != nil && cb.IsPINChallenge {
			g.showPINChallengeScreen()
			return
		}

		g.showError(fmt.Errorf("Unlock failed: %w", err))
		return
	}

	g.recordActivity()

	g.backend.StartAutoSync(func(seq int64) {
		g.showListScreen()
	})

	g.showListScreen()
}

// ── Compact Vertical Layout for List Rows ──
type tightVBoxLayout struct {
	spacing float32
}

func (t *tightVBoxLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	w, h := float32(0), float32(0)
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		sz := o.MinSize()
		if sz.Width > w {
			w = sz.Width
		}
		if h > 0 {
			h += t.spacing
		}
		h += sz.Height
	}
	return fyne.NewSize(w, h)
}

func (t *tightVBoxLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	y := float32(0)
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		sz := o.MinSize()
		o.Move(fyne.NewPos(0, y))
		o.Resize(fyne.NewSize(size.Width, sz.Height))
		y += sz.Height + t.spacing
	}
}

// ── Custom Row for Double Click Interception ──
type doubleTapRow struct {
	widget.BaseWidget
	content  fyne.CanvasObject
	id       widget.ListItemID
	onDouble func(widget.ListItemID)
}

func newDoubleTapRow(content fyne.CanvasObject, onDouble func(widget.ListItemID)) *doubleTapRow {
	r := &doubleTapRow{content: content, onDouble: onDouble}
	r.ExtendBaseWidget(r)
	return r
}

func (r *doubleTapRow) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(r.content)
}

func (r *doubleTapRow) DoubleTapped(e *fyne.PointEvent) {
	if r.onDouble != nil {
		r.onDouble(r.id)
	}
}

// ── Custom List for Keyboard Interception ──
type quickList struct {
	widget.List
	onEnter        func()
	onUp           func()
	onDown         func()
	onCopyUsername func()
	onCopyPassword func()
}

func (l *quickList) TypedKey(k *fyne.KeyEvent) {
	switch k.Name {
	case fyne.KeyReturn, fyne.KeyEnter:
		if l.onEnter != nil {
			l.onEnter()
		}
		return
	case fyne.KeyUp:
		if l.onUp != nil {
			l.onUp()
			return
		}
	case fyne.KeyDown:
		if l.onDown != nil {
			l.onDown()
			return
		}
	}
	l.List.TypedKey(k)
}

func (l *quickList) TypedShortcut(s fyne.Shortcut) {
	if _, ok := s.(*fyne.ShortcutCopy); ok {
		if l.onCopyUsername != nil {
			l.onCopyUsername()
			return
		}
	}
	if cs, ok := s.(*desktop.CustomShortcut); ok {
		isCtrlOrCmd := (cs.Modifier&fyne.KeyModifierSuper != 0) || (cs.Modifier&fyne.KeyModifierControl != 0)
		isShift := cs.Modifier&fyne.KeyModifierShift != 0
		if cs.KeyName == fyne.KeyC && isCtrlOrCmd {
			if isShift {
				if l.onCopyPassword != nil {
					l.onCopyPassword()
					return
				}
			} else {
				if l.onCopyUsername != nil {
					l.onCopyUsername()
					return
				}
			}
		}
	}
}

func newQuickList(length func() int, createItem func() fyne.CanvasObject, updateItem func(widget.ListItemID, fyne.CanvasObject)) *quickList {
	l := &quickList{}
	l.Length = length
	l.CreateItem = createItem
	l.UpdateItem = updateItem
	l.ExtendBaseWidget(l)
	return l
}

// ── Main Split Screen (SecVault Style — 3-column) ──

func (g *GUI) showListScreen() {
	g.navigateTo("main")

	if g.window != nil {
		sz := g.window.Canvas().Size()
		if sz.Width < 700 || sz.Height < 500 {
			g.window.Resize(fyne.NewSize(960, 680))
			g.window.CenterOnScreen()
		}
	}

	// Cancel any active TOTP goroutine when leaving the detail view.
	if g.totpCancel != nil {
		g.totpCancel()
		g.totpCancel = nil
	}

	secrets, err := g.backend.List()
	if err != nil {
		g.showError(fmt.Errorf("list secrets: %w", err))
		return
	}
	g.cachedSecrets = secrets

	// Apply active category filter
	filtered := filterByCategory(secrets, g.activeCategoryID, g.activeCategoryKind)

	rightPane := container.NewStack()

	setRight := func(c fyne.CanvasObject) {
		rightPane.RemoveAll()
		if c != nil {
			// Inset the detail pane so its card/content never sits flush against
			// the window edges (clean breathing room margin around the detail panel).
			rightPane.Add(container.New(
				layout.NewCustomPaddedLayout(detailVPad, detailVPad, detailHPad, detailHPad), c))
		}
		rightPane.Refresh()
	}

	// ── Sidebar ──
	// Discover enabled vaults for the dropdown
	vaultInfos, _ := config.ListEnabledVaults()
	vaultNames := make([]string, 0, len(vaultInfos))
	for _, v := range vaultInfos {
		vaultNames = append(vaultNames, v.Name)
	}

	sidebarCallbacks := SidebarCallbacks{
		OnCategorySelected: func(categoryID string, kind secret.Kind) {
			g.recordActivity()
			g.activeCategoryID = categoryID
			g.activeCategoryKind = kind
			g.showListScreen()
		},
		OnWatchtower: func() {
			g.recordActivity()
			g.activeCategoryID = "watchtower"
			g.showListScreen()
		},
		OnLock: func() {
			g.backend.Lock()
			g.showUnlockScreen()
		},
		OnSettings: func() {
			g.recordActivity()
			g.showSettingsScreen()
		},
		OnVaultSelected: func(vaultName string) {
			g.recordActivity()
			g.switchVault(vaultName)
		},
		OnNewVault: func() {
			g.showNewVaultDialog()
		},
	}

	sidebar := buildSidebar(g.backend.VaultName(), vaultNames, g.backend.VaultName(), g.activeCategoryID, secrets, sidebarCallbacks)
	sidebarBg := buildSidebarBackground(sidebar)

	// ── Left-Middle Pane: Search & List ──
	searchEntry := newQuickSearchEntry()
	searchEntry.SetPlaceHolder("Search secrets...")

	searchEntry.onCopyUsername = func() {
		if g.selectedName != "" {
			sec, _, err := g.backend.GetSecret(g.selectedName)
			if err == nil {
				if meta := secret.UnmarshalPasswordMetadata(sec.Metadata); meta != nil && meta.Username != "" {
					fyne.CurrentApp().Clipboard().SetContent(meta.Username)
				}
			}
		}
	}

	searchEntry.onCopyPassword = func() {
		if g.selectedName != "" {
			_, pwd, err := g.backend.GetSecret(g.selectedName)
			if err == nil {
				fyne.CurrentApp().Clipboard().SetContent(pwd)
			}
		}
	}

	if g.selectedNames == nil {
		g.selectedNames = make(map[string]bool)
	}

	// Minimum width spacer so list pane doesn't collapse
	minWidthSpacer := canvas.NewRectangle(color.Transparent)
	minWidthSpacer.SetMinSize(fyne.NewSize(240, 1))

	var listWidget *quickList
	var batchBar *fyne.Container
	var updateBatchBar func()

	listWidget = newQuickList(
		func() int { return len(filtered) },
		func() fyne.CanvasObject {
			chk := widget.NewCheck("", nil)
			iconWrapper := container.NewCenter()

			titleLbl := canvas.NewText("", themepkg.Foreground)
			titleLbl.TextSize = 13
			titleLbl.TextStyle = fyne.TextStyle{Bold: true}

			subLbl := canvas.NewText("", themepkg.Muted)
			subLbl.TextSize = 11

			textBox := container.New(&tightVBoxLayout{spacing: 1}, titleLbl, subLbl)

			leftWrapper := container.NewHBox(chk, iconWrapper)

			rowLayout := container.New(
				layout.NewCustomPaddedLayout(3, 3, 6, 6),
				container.NewBorder(nil, nil, leftWrapper, nil, container.New(layout.NewCustomPaddedLayout(0, 6, 0, 0), textBox)),
			)

			return newDoubleTapRow(rowLayout, func(id widget.ListItemID) {})
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id >= len(filtered) {
				return
			}
			sec := filtered[id]

			row := obj.(*doubleTapRow)
			row.id = id
			row.onDouble = func(clickedID widget.ListItemID) {
				if listWidget.onEnter != nil {
					listWidget.Select(clickedID)
					listWidget.onEnter()
				}
			}

			rowContainer := row.content.(*fyne.Container)
			borderContainer := rowContainer.Objects[0].(*fyne.Container)

			leftWrapper := borderContainer.Objects[1].(*fyne.Container)
			chk := leftWrapper.Objects[0].(*widget.Check)
			iconWrapper := leftWrapper.Objects[1].(*fyne.Container)

			paddedText := borderContainer.Objects[0].(*fyne.Container)
			textBox := paddedText.Objects[0].(*fyne.Container)
			titleLbl := textBox.Objects[0].(*canvas.Text)
			subLbl := textBox.Objects[1].(*canvas.Text)

			// Permanent Checkbox per row
			chk.Checked = g.selectedNames[sec.Name]
			chk.OnChanged = func(checked bool) {
				g.recordActivity()
				if checked {
					g.selectedNames[sec.Name] = true
				} else {
					delete(g.selectedNames, sec.Name)
				}
				if updateBatchBar != nil {
					updateBatchBar()
				}
			}
			chk.Refresh()

			// Render dynamic brand / favicon icon
			iconWrapper.RemoveAll()
			iconWrapper.Add(FaviconOrBrandIcon(sec, "sm", func() {
				if listWidget != nil {
					listWidget.RefreshItem(id)
				}
			}))
			iconWrapper.Refresh()

			titleLbl.Text = sec.Name
			titleLbl.Color = themepkg.Foreground
			titleLbl.Refresh()

			var metaParts []string
			if meta := secret.UnmarshalPasswordMetadata(sec.Metadata); meta != nil {
				if meta.Username != "" {
					metaParts = append(metaParts, meta.Username)
				}
				if meta.URL != "" {
					metaParts = append(metaParts, extractDomain(meta.URL))
				}
			}

			if len(metaParts) > 0 {
				subLbl.Text = strings.Join(metaParts, "  •  ")
				subLbl.Color = themepkg.Muted
				subLbl.Show()
			} else {
				subLbl.Text = ""
				subLbl.Hide()
			}
			subLbl.Refresh()
		},
	)

	// Bind searchEntry navigation AFTER listWidget is created
	searchEntry.onUp = func() {
		selectedIdx := -1
		for i, s := range filtered {
			if s.Name == g.selectedName {
				selectedIdx = i
				break
			}
		}
		if selectedIdx > 0 {
			g.recordActivity()
			listWidget.Select(selectedIdx - 1)
			listWidget.ScrollTo(selectedIdx - 1)
		} else if selectedIdx == -1 && len(filtered) > 0 {
			g.recordActivity()
			listWidget.Select(0)
			listWidget.ScrollTo(0)
		}
	}

	searchEntry.onDown = func() {
		selectedIdx := -1
		for i, s := range filtered {
			if s.Name == g.selectedName {
				selectedIdx = i
				break
			}
		}
		if selectedIdx == -1 && len(filtered) > 0 {
			g.recordActivity()
			listWidget.Select(0)
			listWidget.ScrollTo(0)
		} else if selectedIdx < len(filtered)-1 {
			g.recordActivity()
			listWidget.Select(selectedIdx + 1)
			listWidget.ScrollTo(selectedIdx + 1)
		}
	}

	listWidget.onUp = searchEntry.onUp
	listWidget.onDown = searchEntry.onDown
	listWidget.onCopyUsername = searchEntry.onCopyUsername
	listWidget.onCopyPassword = searchEntry.onCopyPassword

	listWidget.onEnter = func() {
		g.recordActivity()
		if g.selectedName != "" {
			setRight(g.buildFormView(g.selectedName, func() {
				g.showListScreen()
			}, func() {
				setRight(g.buildEnhancedDetailView(g.selectedName, setRight, func() {
					g.showListScreen()
				}))
			}))
		}
	}

	searchEntry.OnSubmitted = func(q string) {
		g.recordActivity()
		if g.selectedName != "" {
			// Automatically enter edit mode
			setRight(g.buildFormView(g.selectedName, func() {
				g.showListScreen()
			}, func() {
				setRight(g.buildEnhancedDetailView(g.selectedName, setRight, func() {
					g.showListScreen()
				}))
			}))
		}
	}

	listWidget.OnSelected = func(id widget.ListItemID) {
		g.recordActivity()
		if id < len(filtered) {
			g.selectedName = filtered[id].Name
			setRight(g.buildEnhancedDetailView(g.selectedName, setRight, func() {
				g.showListScreen()
			}))
		}
	}

	searchEntry.OnChanged = func(q string) {
		g.recordActivity()
		filtered = filterByCategoryAndSearch(g.cachedSecrets, g.activeCategoryID, g.activeCategoryKind, q)
		listWidget.Refresh()
		if len(filtered) > 0 {
			listWidget.UnselectAll()
			listWidget.Select(0)
			g.selectedName = filtered[0].Name
		} else {
			g.selectedName = ""
			setRight(container.NewCenter(widget.NewLabelWithStyle("No results found", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})))
		}
	}

	// ── Batch Delete Bar & Dialog ──
	batchCountLbl := canvas.NewText("", themepkg.Foreground)
	batchCountLbl.TextSize = 12
	batchCountLbl.TextStyle = fyne.TextStyle{Bold: true}

	deleteBatchBtn := widget.NewButtonWithIcon("Delete Selected", theme.DeleteIcon(), func() {
		g.recordActivity()
		count := len(g.selectedNames)
		if count == 0 {
			return
		}

		confirmMsg := fmt.Sprintf("Are you sure you want to delete %d selected secret(s) from your vault?", count)
		if count == 1 {
			confirmMsg = "Are you sure you want to delete 1 selected secret from your vault?"
		}

		dialog.ShowConfirm("Confirm Batch Deletion", confirmMsg, func(confirm bool) {
			if !confirm {
				return
			}
			for name := range g.selectedNames {
				_ = g.backend.DeleteSecret(name)
			}
			g.selectedNames = make(map[string]bool)
			g.showListScreen()
		}, g.window)
	})
	deleteBatchBtn.Importance = widget.DangerImportance

	selectAllBtn := widget.NewButton("Select All", func() {
		g.recordActivity()
		for _, s := range filtered {
			g.selectedNames[s.Name] = true
		}
		listWidget.Refresh()
		if updateBatchBar != nil {
			updateBatchBar()
		}
	})

	clearSelectionBtn := widget.NewButton("Deselect All", func() {
		g.recordActivity()
		g.selectedNames = make(map[string]bool)
		listWidget.Refresh()
		if updateBatchBar != nil {
			updateBatchBar()
		}
	})

	batchBar = container.NewVBox(
		widget.NewSeparator(),
		container.NewBorder(
			nil, nil,
			container.NewHBox(selectAllBtn, clearSelectionBtn),
			deleteBatchBtn,
			container.NewCenter(batchCountLbl),
		),
	)

	updateBatchBar = func() {
		count := len(g.selectedNames)
		if count > 0 {
			batchCountLbl.Text = fmt.Sprintf("%d selected", count)
			batchCountLbl.Refresh()
			deleteBatchBtn.SetText(fmt.Sprintf("Delete (%d)", count))
			batchBar.Show()
		} else {
			batchBar.Hide()
		}
	}

	// Buttons
	addBtn := widget.NewButtonWithIcon("", theme.ContentAddIcon(), func() {
		g.recordActivity()
		listWidget.UnselectAll()
		setRight(g.buildAddView(func() { g.showListScreen() }, func() {
			if g.selectedName != "" {
				setRight(g.buildEnhancedDetailView(g.selectedName, setRight, func() { g.showListScreen() }))
			} else {
				setRight(container.NewCenter(widget.NewLabel("Select a secret to view details.")))
			}
		}))
	})
	addBtn.Importance = widget.HighImportance

	toolbar := container.NewBorder(nil, nil, nil, addBtn)
	listHeader := container.NewVBox(toolbar, widget.NewSeparator(), searchEntry, widget.NewSeparator())

	// Wrap list pane with min-width spacer and persistent dynamic bottom batch bar
	updateBatchBar()
	listPaneInner := container.NewBorder(listHeader, batchBar, nil, nil, listWidget)
	listPane := container.NewStack(minWidthSpacer, listPaneInner)

	// ── Assemble 3-Column Layout ──
	// Sidebar (20%) | Search + List (30%) | Detail (50%)
	// listAndDetail.Offset = 30/80 = 0.375 of remaining space after sidebar
	listAndDetail := container.NewHSplit(listPane, rightPane)
	listAndDetail.Offset = 0.375

	outerSplit := container.NewHSplit(sidebarBg, listAndDetail)
	outerSplit.Offset = 0.20

	// Set initial right pane — restore previous selection if possible
	if g.activeCategoryID == "watchtower" {
		listWidget.UnselectAll()
		setRight(g.buildWatchtowerView(setRight))
	} else if len(filtered) > 0 {
		selectedIdx := -1
		for i, s := range filtered {
			if s.Name == g.selectedName {
				selectedIdx = i
				break
			}
		}
		if selectedIdx >= 0 {
			listWidget.Select(selectedIdx)
		} else if g.selectedName == "" {
			listWidget.Select(0)
		} else {
			// Previously selected item no longer in filtered results
			listWidget.Select(0)
		}
	} else {
		g.selectedName = ""
		setRight(container.NewCenter(widget.NewLabel("Select a secret to view details.")))
	}

	// ── Keyboard Interceptor for Search Navigation ──
	cv := g.window.Canvas()
	cv.SetOnTypedKey(func(k *fyne.KeyEvent) {
		g.recordActivity()
		focused := cv.Focused()
		// If typing in a detail/form edit field, do not intercept
		if entry, isEntry := focused.(*widget.Entry); isEntry && entry != &searchEntry.Entry {
			return
		}

		switch k.Name {
		case fyne.KeyUp:
			if searchEntry.onUp != nil {
				searchEntry.onUp()
			}
		case fyne.KeyDown:
			if searchEntry.onDown != nil {
				searchEntry.onDown()
			}
		case fyne.KeyReturn, fyne.KeyEnter:
			// Trigger edit mode if Enter is pressed from the list or the search bar
			if searchEntry.OnSubmitted != nil {
				searchEntry.OnSubmitted(searchEntry.Text)
			}
		case fyne.KeyEscape:
			// Esc from watchtower or empty state: go back to default detail view
			if g.selectedName != "" {
				setRight(g.buildEnhancedDetailView(g.selectedName, setRight, func() {
					g.showListScreen()
				}))
			} else if len(filtered) > 0 {
				listWidget.Select(0)
				g.selectedName = filtered[0].Name
				setRight(g.buildEnhancedDetailView(g.selectedName, setRight, func() {
					g.showListScreen()
				}))
			}
		}
	})

	// ── Copy Shortcuts (work regardless of focus) ──
	// Cmd+C / Ctrl+C copies username, Cmd+Shift+C / Ctrl+Shift+C copies decrypted password.
	doCopyUser := func() {
		if g.selectedName != "" {
			sec, _, err := g.backend.GetSecret(g.selectedName)
			if err == nil {
				if meta := secret.UnmarshalPasswordMetadata(sec.Metadata); meta != nil && meta.Username != "" {
					fyne.CurrentApp().Clipboard().SetContent(meta.Username)
				}
			}
		}
	}

	doCopyPass := func() {
		if g.selectedName != "" {
			_, pwd, err := g.backend.GetSecret(g.selectedName)
			if err == nil {
				fyne.CurrentApp().Clipboard().SetContent(pwd)
			}
		}
	}

	cv.AddShortcut(&desktop.CustomShortcut{
		KeyName: fyne.KeyC, Modifier: fyne.KeyModifierSuper,
	}, func(s fyne.Shortcut) {
		doCopyUser()
	})

	cv.AddShortcut(&desktop.CustomShortcut{
		KeyName: fyne.KeyC, Modifier: fyne.KeyModifierControl,
	}, func(s fyne.Shortcut) {
		doCopyUser()
	})

	cv.AddShortcut(&desktop.CustomShortcut{
		KeyName: fyne.KeyC, Modifier: fyne.KeyModifierSuper | fyne.KeyModifierShift,
	}, func(s fyne.Shortcut) {
		doCopyPass()
	})

	cv.AddShortcut(&desktop.CustomShortcut{
		KeyName: fyne.KeyC, Modifier: fyne.KeyModifierControl | fyne.KeyModifierShift,
	}, func(s fyne.Shortcut) {
		doCopyPass()
	})

	g.setContent(outerSplit)
	if g.window != nil && g.window.Canvas() != nil {
		g.window.Canvas().Focus(searchEntry)
	}
}

// ── Add / Edit Views ──

func (g *GUI) buildAddView(onSave func(), onCancel func()) fyne.CanvasObject {
	return g.buildFormView("", onSave, onCancel)
}

func (g *GUI) buildFormView(existingName string, onSave func(), onCancel func()) fyne.CanvasObject {
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Secret name (e.g. github-token)")

	kindOptions := []string{
		string(secret.KindPassword),
		string(secret.KindAPIKey),
		string(secret.KindCertificate),
		string(secret.KindSSHKey),
		string(secret.KindNote),
		string(secret.KindOther),
	}
	kindSelect := widget.NewSelect(kindOptions, nil)
	kindSelect.SetSelected(string(secret.KindPassword))

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username")

	urlEntry := widget.NewEntry()
	urlEntry.SetPlaceHolder("URL (e.g. https://github.com)")

	otpEntry := widget.NewEntry()
	otpEntry.SetPlaceHolder("TOTP Secret (optional)")

	valueEntry := widget.NewMultiLineEntry()
	valueEntry.SetPlaceHolder("Secret Value")
	valueEntry.Wrapping = fyne.TextWrapWord
	valueEntry.SetMinRowsVisible(4)

	notesEntry := widget.NewMultiLineEntry()
	notesEntry.SetPlaceHolder("Notes (optional)")
	notesEntry.Wrapping = fyne.TextWrapWord
	notesEntry.SetMinRowsVisible(6)

	// Interactive height controllers for Value and Notes
	valueRows := 4
	valueWrapper := container.NewVScroll(valueEntry)
	valueWrapper.SetMinSize(fyne.NewSize(0, 110))

	notesRows := 6
	notesWrapper := container.NewVScroll(notesEntry)
	notesWrapper.SetMinSize(fyne.NewSize(0, 160))

	expandValueBtn := widget.NewButtonWithIcon("", theme.MoveDownIcon(), func() {
		valueRows += 4
		if valueRows > 24 {
			valueRows = 24
		}
		valueWrapper.SetMinSize(fyne.NewSize(0, float32(valueRows*26)))
		valueWrapper.Refresh()
	})
	expandValueBtn.Importance = widget.LowImportance

	shrinkValueBtn := widget.NewButtonWithIcon("", theme.MoveUpIcon(), func() {
		valueRows -= 4
		if valueRows < 4 {
			valueRows = 4
		}
		valueWrapper.SetMinSize(fyne.NewSize(0, float32(valueRows*26)))
		valueWrapper.Refresh()
	})
	shrinkValueBtn.Importance = widget.LowImportance

	expandNotesBtn := widget.NewButtonWithIcon("", theme.MoveDownIcon(), func() {
		notesRows += 6
		if notesRows > 36 {
			notesRows = 36
		}
		notesWrapper.SetMinSize(fyne.NewSize(0, float32(notesRows*26)))
		notesWrapper.Refresh()
	})
	expandNotesBtn.Importance = widget.LowImportance

	shrinkNotesBtn := widget.NewButtonWithIcon("", theme.MoveUpIcon(), func() {
		notesRows -= 6
		if notesRows < 4 {
			notesRows = 4
		}
		notesWrapper.SetMinSize(fyne.NewSize(0, float32(notesRows*26)))
		notesWrapper.Refresh()
	})
	shrinkNotesBtn.Importance = widget.LowImportance

	if existingName != "" {
		sec, val, err := g.backend.GetSecret(existingName)
		if err == nil {
			nameEntry.SetText(sec.Name)
			kindSelect.SetSelected(string(sec.Kind))
			valueEntry.SetText(val)
			notesEntry.SetText(sec.Notes)

			meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
			if meta != nil {
				usernameEntry.SetText(meta.Username)
				urlEntry.SetText(meta.URL)

				if meta.OTPAuth != "" {
					otpEntry.SetText("Exists (edit via metadata only)")
					otpEntry.Disable()
				}
			}
		}
	}

	genPwBtn := widget.NewButton("Generate", func() {
		pw, err := g.backend.GeneratePassword(24)
		if err == nil {
			valueEntry.SetText(pw)
		}
	})

	kindSelect.OnChanged = func(s string) {
		if s == string(secret.KindPassword) {
			genPwBtn.Show()
		} else {
			genPwBtn.Hide()
		}
	}
	// Initial state
	if kindSelect.Selected != string(secret.KindPassword) {
		genPwBtn.Hide()
	}

	saveBtn := widget.NewButton("Save", func() {
		name := strings.TrimSpace(nameEntry.Text)
		value := valueEntry.Text

		if name == "" || value == "" {
			dialog.ShowInformation("Missing Fields", "Name and value are required.", g.window)
			return
		}

		// Metadata preparation. S-02: only the *redacted* otpauth URI ever
		// lands in the plaintext metadata column. The actual base32 seed is
		// kept separately in encrypted_otp_seed via SaveOTPSeed below.
		meta := &secret.PasswordMetadata{
			Username: usernameEntry.Text,
			URL:      urlEntry.Text,
		}
		var newOTPSeed string
		if otpEntry.Text != "" && !otpEntry.Disabled() {
			meta.OTPAuth = buildOTPAuthURI(name, secret.OTPAuthRedactedMarker)
			newOTPSeed = otpEntry.Text
		} else if otpEntry.Disabled() && existingName != "" {
			// keep existing (already redacted because MarshalPasswordMetadata enforces it)
			sec, _, _ := g.backend.GetSecret(existingName)
			existingMeta := secret.UnmarshalPasswordMetadata(sec.Metadata)
			if existingMeta != nil {
				meta.OTPAuth = existingMeta.OTPAuth
			}
		}

		notes := notesEntry.Text
		tags := ""

		var err error
		metadataJSON := secret.MarshalPasswordMetadata(meta)
		if existingName != "" {
			err = g.backend.EditSecretFull(existingName, name, kindSelect.Selected, value, notes, tags, metadataJSON, newOTPSeed)
		} else {
			err = g.backend.AddSecretFull(name, kindSelect.Selected, value, notes, tags, metadataJSON, newOTPSeed)
		}

		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to save secret: %w", err), g.window)
			return
		}

		g.selectedName = name
		onSave()
	})
	saveBtn.Importance = widget.HighImportance

	cancelBtn := widget.NewButton("Cancel", onCancel)

	title := "Add New Secret"
	if existingName != "" {
		title = "Edit " + existingName
	}

	valueHeader := container.NewBorder(nil, nil, widget.NewLabel("Secret Value:"), container.NewHBox(shrinkValueBtn, expandValueBtn, genPwBtn))
	notesHeader := container.NewBorder(nil, nil, widget.NewLabel("Notes:"), container.NewHBox(shrinkNotesBtn, expandNotesBtn))

	form := container.NewVBox(
		widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		widget.NewLabel("Name:"), nameEntry,
		widget.NewLabel("Kind:"), kindSelect,
		widget.NewLabel("Username:"), usernameEntry,
		widget.NewLabel("URL:"), urlEntry,
		widget.NewLabel("TOTP Secret:"), otpEntry,
		valueHeader, valueWrapper,
		notesHeader, notesWrapper,
		widget.NewSeparator(),
		container.NewHBox(saveBtn, cancelBtn),
	)

	return container.NewPadded(container.NewScroll(form))
}

// ── Settings Screen ──

func buildSettingsCard(title string, iconRes fyne.Resource, content fyne.CanvasObject) fyne.CanvasObject {
	headerIcon := widget.NewIcon(iconRes)
	headerTitle := canvas.NewText(title, themepkg.Foreground)
	headerTitle.TextSize = 14
	headerTitle.TextStyle = fyne.TextStyle{Bold: true}

	header := container.NewBorder(nil, nil, headerIcon, nil, container.NewPadded(headerTitle))

	inner := container.NewVBox(
		header,
		widget.NewSeparator(),
		content,
	)

	cardBg := canvas.NewRectangle(themepkg.Surface2)
	cardBg.CornerRadius = sizeCardRadius

	cardBorder := canvas.NewRectangle(color.Transparent)
	cardBorder.StrokeColor = themepkg.GlassBorder
	cardBorder.StrokeWidth = 1
	cardBorder.CornerRadius = sizeCardRadius

	return container.NewStack(cardBg, cardBorder, container.NewPadded(inner))
}

func (g *GUI) showSettingsScreen() {
	g.navigateTo("settings")

	vaultName := g.backend.VaultName()
	vaultPath := ""
	if cfg := g.backend.Config(); cfg != nil {
		vaultPath = cfg.VaultPath
	}

	// ── Top Header ──
	backBtn := widget.NewButtonWithIcon("Back to Vault", theme.NavigateBackIcon(), func() {
		if g.backend.IsUnlocked() {
			g.showListScreen()
		} else {
			g.showUnlockScreen()
		}
	})
	backBtn.Importance = widget.LowImportance

	titleText := canvas.NewText("Preferences & Vault Settings", themepkg.Foreground)
	titleText.TextSize = 20
	titleText.TextStyle = fyne.TextStyle{Bold: true}

	topBar := container.NewBorder(nil, nil, backBtn, nil, container.NewCenter(titleText))

	// ── Card 1: Vault Information ──
	vaultNameLbl := canvas.NewText("Active Vault: "+vaultName, themepkg.Foreground)
	vaultNameLbl.TextSize = 14
	vaultNameLbl.TextStyle = fyne.TextStyle{Bold: true}

	vaultPathLbl := canvas.NewText("Path: "+vaultPath, themepkg.Muted)
	vaultPathLbl.TextSize = 12

	vaults, _ := ListVaults()
	var vaultNamesList []string
	for _, v := range vaults {
		status := "enabled"
		if v.Disabled {
			status = "disabled"
		} else if v.Name == vaultName {
			status = "active"
		}
		vaultNamesList = append(vaultNamesList, fmt.Sprintf("• %s (%s)", v.Name, status))
	}
	discoveredLbl := widget.NewLabel(strings.Join(vaultNamesList, "\n"))

	manageVaultsBtn := widget.NewButtonWithIcon("Manage Vaults", theme.SettingsIcon(), func() {
		g.showManageVaultsDialog()
	})

	vaultCardContent := container.NewVBox(
		vaultNameLbl,
		vaultPathLbl,
		widget.NewSeparator(),
		canvas.NewText("Discovered Local Vaults:", themepkg.Muted),
		discoveredLbl,
		manageVaultsBtn,
	)
	cardVault := buildSettingsCard("Active Vault & Storage", theme.StorageIcon(), vaultCardContent)

	// ── Card 2: Real-time Sync (mTLS) ──
	currentSyncURL := g.backend.SyncServerURL()
	syncStatusText := "⚪ Standalone (Sync disabled)"
	if currentSyncURL != "" {
		syncStatusText = fmt.Sprintf("🟢 Connected & Synced: %s", currentSyncURL)
	}
	syncStatusLabel := widget.NewLabelWithStyle(syncStatusText, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	syncURLEntry := widget.NewEntry()
	syncURLEntry.SetPlaceHolder("http://192.168.0.104:8080 or https://sync.example.com")
	syncURLEntry.SetText(currentSyncURL)

	saveSyncBtn := widget.NewButtonWithIcon("Save & Sync", theme.DocumentSaveIcon(), func() {
		if !g.backend.IsUnlocked() {
			dialog.ShowError(fmt.Errorf("vault is locked — unlock first"), g.window)
			return
		}
		newURL := strings.TrimSpace(syncURLEntry.Text)
		if newURL == "" {
			dialog.ShowError(fmt.Errorf("server URL cannot be empty"), g.window)
			return
		}
		if err := g.backend.ConfigureSync(newURL); err != nil {
			dialog.ShowError(fmt.Errorf("sync configuration error: %w", err), g.window)
			return
		}
		g.backend.StartAutoSync(nil)
		dialog.ShowInformation("Sync Configured", fmt.Sprintf("Successfully connected and synced with:\n%s", newURL), g.window)
		g.showSettingsScreen()
	})
	saveSyncBtn.Importance = widget.HighImportance

	unlinkSyncBtn := widget.NewButtonWithIcon("Disable Sync", theme.CancelIcon(), func() {
		if err := g.backend.UnlinkSync(); err != nil {
			dialog.ShowError(fmt.Errorf("failed to unlink sync: %w", err), g.window)
			return
		}
		dialog.ShowInformation("Sync Disabled", "Sync configuration has been removed from this vault.", g.window)
		g.showSettingsScreen()
	})
	unlinkSyncBtn.Importance = widget.LowImportance

	syncCardContent := container.NewVBox(
		syncStatusLabel,
		syncURLEntry,
		container.NewHBox(saveSyncBtn, unlinkSyncBtn),
	)
	cardSync := buildSettingsCard("Real-time Synchronization (vlt-sync)", theme.ViewRefreshIcon(), syncCardContent)

	// ── Card 3: Data Migration (Import & Export) ──
	importBtn := widget.NewButtonWithIcon("Import from CSV / JSON", theme.UploadIcon(), func() {
		if !g.backend.IsUnlocked() {
			dialog.ShowError(fmt.Errorf("vault is locked — unlock first"), g.window)
			return
		}
		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if reader == nil || err != nil {
				return
			}
			defer func() { _ = reader.Close() }()
			data, err := io.ReadAll(reader)
			if err != nil {
				dialog.ShowError(fmt.Errorf("read file: %w", err), g.window)
				return
			}
			ext := strings.ToLower(filepath.Ext(reader.URI().Path()))
			if ext == "" {
				ext = filepath.Ext(reader.URI().Name())
			}
			result, err := g.backend.ImportPasswords(data, ext, false)
			if err != nil {
				dialog.ShowError(fmt.Errorf("import failed: %w", err), g.window)
				return
			}
			msg := fmt.Sprintf("Imported %d of %d secrets.\nSkipped: %d duplicates\nErrors: %d",
				result.Imported, result.Total, result.Skipped, result.Errors)
			dialog.ShowInformation("Import Complete", msg, g.window)
			g.showListScreen()
		}, g.window)
		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".csv", ".json"}))
		fileDialog.Show()
	})
	importBtn.Importance = widget.LowImportance

	exportCSVBtn := widget.NewButtonWithIcon("Export as CSV", theme.DownloadIcon(), func() {
		if !g.backend.IsUnlocked() {
			dialog.ShowError(fmt.Errorf("vault is locked — unlock first"), g.window)
			return
		}
		fileDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if writer == nil || err != nil {
				return
			}
			defer func() { _ = writer.Close() }()
			data, count, err := g.backend.ExportPasswords("csv")
			if err != nil {
				dialog.ShowError(fmt.Errorf("export failed: %w", err), g.window)
				return
			}
			if _, err := writer.Write(data); err != nil {
				dialog.ShowError(fmt.Errorf("write file: %w", err), g.window)
				return
			}
			msg := fmt.Sprintf("Exported %d secrets to CSV.", count)
			dialog.ShowInformation("Export Complete", msg, g.window)
		}, g.window)
		fileDialog.SetFileName("vlt-export.csv")
		fileDialog.Show()
	})
	exportCSVBtn.Importance = widget.LowImportance

	exportJSONBtn := widget.NewButtonWithIcon("Export as JSON", theme.DownloadIcon(), func() {
		if !g.backend.IsUnlocked() {
			dialog.ShowError(fmt.Errorf("vault is locked — unlock first"), g.window)
			return
		}
		fileDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if writer == nil || err != nil {
				return
			}
			defer func() { _ = writer.Close() }()
			data, count, err := g.backend.ExportPasswords("json")
			if err != nil {
				dialog.ShowError(fmt.Errorf("export failed: %w", err), g.window)
				return
			}
			if _, err := writer.Write(data); err != nil {
				dialog.ShowError(fmt.Errorf("write file: %w", err), g.window)
				return
			}
			msg := fmt.Sprintf("Exported %d secrets to JSON.", count)
			dialog.ShowInformation("Export Complete", msg, g.window)
		}, g.window)
		fileDialog.SetFileName("vlt-export.json")
		fileDialog.Show()
	})
	exportJSONBtn.Importance = widget.LowImportance

	migrationContent := container.NewVBox(
		container.NewHBox(importBtn, exportCSVBtn, exportJSONBtn),
	)
	cardMigration := buildSettingsCard("Data Migration & Backup", theme.FolderIcon(), migrationContent)

	// ── Card 4: Security & Auto-Lock on Inactivity ──
	autoLockOptions := []string{
		"5 minutes",
		"15 minutes (Default)",
		"30 minutes",
		"60 minutes (1 hour)",
		"Never (Disabled)",
	}
	currentAutoLockStr := "15 minutes (Default)"
	switch g.autoLockMinutes {
	case 5:
		currentAutoLockStr = "5 minutes"
	case 15:
		currentAutoLockStr = "15 minutes (Default)"
	case 30:
		currentAutoLockStr = "30 minutes"
	case 60:
		currentAutoLockStr = "60 minutes (1 hour)"
	case 0:
		currentAutoLockStr = "Never (Disabled)"
	}

	autoLockSelect := widget.NewSelect(autoLockOptions, func(selected string) {
		mins := 15
		switch selected {
		case "5 minutes":
			mins = 5
		case "15 minutes (Default)":
			mins = 15
		case "30 minutes":
			mins = 30
		case "60 minutes (1 hour)":
			mins = 60
		case "Never (Disabled)":
			mins = -1
		}
		g.activityMu.Lock()
		if mins < 0 {
			g.autoLockMinutes = 0
		} else {
			g.autoLockMinutes = mins
		}
		g.activityMu.Unlock()

		if cfg := g.backend.Config(); cfg != nil {
			cfg.AutoLockMinutes = mins
			_ = cfg.Save()
		}
	})
	autoLockSelect.SetSelected(currentAutoLockStr)

	securityCardContent := container.NewVBox(
		canvas.NewText("Auto-lock vault after inactivity:", themepkg.Foreground),
		autoLockSelect,
		canvas.NewText("Closes and zeroes all cryptographic master keys from memory.", themepkg.Muted),
	)
	cardSecurity := buildSettingsCard("Security & Inactivity Lock", theme.CancelIcon(), securityCardContent)

	// ── Card 5: Lockout PIN & Recovery Kit ──
	hasPIN := g.backend.HasPIN()
	pinStatusText := "⚪ No Lockout PIN configured"
	if hasPIN {
		pinStatusText = "🟢 8-digit Security PIN active (Anti-Brute Force Protection)"
	}
	pinStatusLbl := widget.NewLabelWithStyle(pinStatusText, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	setPINBtn := widget.NewButtonWithIcon("Set / Change 8-Digit PIN", theme.AccountIcon(), func() {
		if !g.backend.IsUnlocked() {
			dialog.ShowError(fmt.Errorf("vault is locked — unlock first"), g.window)
			return
		}

		pinEntry := widget.NewPasswordEntry()
		pinEntry.SetPlaceHolder("8 digits (e.g. 12345678)")

		confirmEntry := widget.NewPasswordEntry()
		confirmEntry.SetPlaceHolder("Confirm 8 digits")

		formItems := []*widget.FormItem{
			{Text: "New PIN", Widget: pinEntry},
			{Text: "Confirm PIN", Widget: confirmEntry},
		}

		dialog.ShowForm("Configure Security PIN", "Save PIN", "Cancel", formItems, func(ok bool) {
			if !ok {
				return
			}
			p1 := strings.TrimSpace(pinEntry.Text)
			p2 := strings.TrimSpace(confirmEntry.Text)
			if p1 != p2 {
				dialog.ShowError(fmt.Errorf("PINs do not match"), g.window)
				return
			}
			if err := g.backend.SetPIN(p1); err != nil {
				dialog.ShowError(fmt.Errorf("set PIN: %w", err), g.window)
				return
			}
			dialog.ShowInformation("PIN Configured", "8-digit PIN set successfully.\nAfter 3 failed master attempts, this PIN will be required to unfreeze the vault.", g.window)
			g.showSettingsScreen()
		}, g.window)
	})
	setPINBtn.Importance = widget.MediumImportance

	removePINBtn := widget.NewButtonWithIcon("Remove PIN", theme.DeleteIcon(), func() {
		if !hasPIN {
			return
		}
		dialog.ShowConfirm("Remove PIN", "Are you sure you want to disable PIN challenge protection for this vault?", func(confirm bool) {
			if !confirm {
				return
			}
			if err := g.backend.RemovePIN(); err != nil {
				dialog.ShowError(fmt.Errorf("remove PIN: %w", err), g.window)
				return
			}
			dialog.ShowInformation("PIN Removed", "Security PIN disabled.", g.window)
			g.showSettingsScreen()
		}, g.window)
	})
	removePINBtn.Importance = widget.LowImportance
	if !hasPIN {
		removePINBtn.Disable()
	}

	showRecoveryKitBtn := widget.NewButtonWithIcon("Generate / View Recovery Phrase (36 Words)", theme.HelpIcon(), func() {
		if !g.backend.IsUnlocked() {
			dialog.ShowError(fmt.Errorf("vault is locked — unlock first"), g.window)
			return
		}

		mnemonic, err := g.backend.GenerateRecoveryKit()
		if err != nil {
			dialog.ShowError(fmt.Errorf("generate recovery kit: %w", err), g.window)
			return
		}

		phraseBox := widget.NewMultiLineEntry()
		phraseBox.SetText(mnemonic)
		phraseBox.Wrapping = fyne.TextWrapWord
		phraseBox.Disable()

		copyBtn := widget.NewButtonWithIcon("Copy Phrase to Clipboard", theme.ContentCopyIcon(), func() {
			fyne.CurrentApp().Clipboard().SetContent(mnemonic)
			dialog.ShowInformation("Copied", "Recovery phrase copied to clipboard.\nStore it safely offline!", g.window)
		})

		content := container.NewVBox(
			canvas.NewText("⚠️ KEEP THIS SECRET AND SAFE. NEVER SHARE IT.", themepkg.Error),
			canvas.NewText("You can use this phrase to rescue your vault if it enters Hard Lockout:", themepkg.Foreground),
			widget.NewSeparator(),
			phraseBox,
			copyBtn,
		)

		d := dialog.NewCustom("Vault Recovery Kit", "Close", content, g.window)
		d.Resize(fyne.NewSize(500, 320))
		d.Show()
	})
	showRecoveryKitBtn.Importance = widget.LowImportance

	pinRecoveryContent := container.NewVBox(
		pinStatusLbl,
		container.NewHBox(setPINBtn, removePINBtn),
		widget.NewSeparator(),
		showRecoveryKitBtn,
		canvas.NewText("The recovery phrase can rescue your vault even if it is locked out.", themepkg.Muted),
	)
	cardPINRecovery := buildSettingsCard("Anti-Brute Force Protection & Recovery Kit", theme.HelpIcon(), pinRecoveryContent)

	// ── Card 6: Quick Access Appearance & Behavior ──
	currentQuickStyle := "Modern (Spacious)"
	if cfg := g.backend.Config(); cfg != nil && cfg.QuickAccessStyle == "classic" {
		currentQuickStyle = "Classic (Compact)"
	}
	quickStyleSelect := widget.NewSelect([]string{"Modern (Spacious)", "Classic (Compact)"}, func(selected string) {
		style := "modern"
		if selected == "Classic (Compact)" {
			style = "classic"
		}
		if cfg := g.backend.Config(); cfg != nil {
			cfg.QuickAccessStyle = style
			_ = cfg.Save()
		}
	})
	quickStyleSelect.SetSelected(currentQuickStyle)

	quickCardContent := container.NewVBox(
		canvas.NewText("Quick Access Popup Theme:", themepkg.Foreground),
		quickStyleSelect,
		canvas.NewText("Choose between Modern (floating highlight) and Classic (compact layout).", themepkg.Muted),
	)
	cardQuick := buildSettingsCard("Quick Access Appearance", theme.ViewFullScreenIcon(), quickCardContent)

	// ── Card 7: Global Hotkeys & Shortcuts ──
	hotkeys := config.HotkeysConfig{
		QuickAccess: config.DefaultHotkeyQuickAccess,
		MainWindow:  config.DefaultHotkeyMainWindow,
	}
	if cfg := g.backend.Config(); cfg != nil {
		hotkeys = cfg.GetHotkeys()
	}

	quickHotkeyEntry := widget.NewEntry()
	quickHotkeyEntry.SetPlaceHolder(config.DefaultHotkeyQuickAccess)
	quickHotkeyEntry.SetText(hotkeys.QuickAccess)

	mainHotkeyEntry := widget.NewEntry()
	mainHotkeyEntry.SetPlaceHolder(config.DefaultHotkeyMainWindow)
	mainHotkeyEntry.SetText(hotkeys.MainWindow)

	saveHotkeysBtn := widget.NewButtonWithIcon("Save Hotkeys", theme.DocumentSaveIcon(), func() {
		if cfg := g.backend.Config(); cfg != nil {
			qHk := strings.TrimSpace(quickHotkeyEntry.Text)
			if qHk == "" {
				qHk = config.DefaultHotkeyQuickAccess
			}
			mHk := strings.TrimSpace(mainHotkeyEntry.Text)
			if mHk == "" {
				mHk = config.DefaultHotkeyMainWindow
			}
			cfg.Hotkeys.QuickAccess = qHk
			cfg.Hotkeys.MainWindow = mHk
			_ = cfg.Save()
			if g.hotkeysManager != nil {
				_ = g.hotkeysManager.Start(cfg.GetHotkeys())
			}
			dialog.ShowInformation("Hotkeys Updated", "Global hotkeys configuration saved and active.", g.window)
		}
	})
	saveHotkeysBtn.Importance = widget.MediumImportance

	hotkeysForm := container.NewVBox(
		canvas.NewText("Quick Access Popup Hotkey (Default: shift+cmd+space):", themepkg.Foreground),
		quickHotkeyEntry,
		canvas.NewText("Main GUI Window Hotkey (Default: shift+cmd+v):", themepkg.Foreground),
		mainHotkeyEntry,
		container.NewHBox(saveHotkeysBtn),
		widget.NewSeparator(),
		canvas.NewText("Tip: In Raycast or native global hotkeys, configure these key combinations.", themepkg.Muted),
	)

	versionLbl := canvas.NewText(fmt.Sprintf("vlt GUI Engine v%s • Zero-Knowledge Single-Instance Architecture", Version), themepkg.Muted)
	versionLbl.TextSize = 11

	cardInfo := buildSettingsCard("Global Hotkeys & System", theme.InfoIcon(), container.NewVBox(hotkeysForm, versionLbl))

	// ── Assemble Page ──
	body := container.NewVBox(
		cardVault,
		cardSecurity,
		cardPINRecovery,
		cardQuick,
		cardSync,
		cardMigration,
		cardInfo,
	)

	widthConstraint := canvas.NewRectangle(color.Transparent)
	widthConstraint.SetMinSize(fyne.NewSize(740, 1))

	centeredBody := container.NewCenter(
		container.NewStack(widthConstraint, body),
	)

	page := container.NewBorder(
		container.NewVBox(topBar, widget.NewSeparator()),
		nil, nil, nil,
		container.NewPadded(container.NewScroll(centeredBody)),
	)

	g.setContent(page)

	// Esc returns to the previous screen
	g.window.Canvas().SetOnTypedKey(func(k *fyne.KeyEvent) {
		if k.Name == fyne.KeyEscape {
			if g.backend.IsUnlocked() {
				g.showListScreen()
			} else {
				g.showUnlockScreen()
			}
		}
	})
}

// switchVault closes the current backend and loads a new vault.
func (g *GUI) switchVault(vaultName string) {
	// Persist active vault
	if cfg, err := config.Load(); err == nil {
		_ = cfg.SetActiveVault(vaultName)
	}

	// Close current backend
	g.backend.Close()

	// Create new backend
	newBackend, err := NewApp(vaultName, false)
	if err != nil {
		dialog.ShowError(fmt.Errorf("failed to open vault %q: %w", vaultName, err), g.window)
		// Try to restore previous vault
		return
	}
	g.backend = newBackend
	newBackend.SetOnActivity(g.recordActivity)
	g.recordActivity()

	// Update window title
	g.window.SetTitle("vlt — " + g.backend.VaultName())

	// Reset state
	g.selectedName = ""
	g.activeCategoryID = ""
	g.activeCategoryKind = ""
	g.cachedSecrets = nil

	// Try auto-unlock, fall back to unlock screen
	if g.backend.IsUnlocked() {
		g.showListScreen()
	} else {
		g.showUnlockScreen()
	}
}

// showNewVaultDialog shows a dialog to create a new vault.
func (g *GUI) showNewVaultDialog() {
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Vault name (e.g. work)")

	pwEntry := widget.NewEntry()
	pwEntry.SetPlaceHolder("Master password")
	pwEntry.Password = true

	confirmEntry := widget.NewEntry()
	confirmEntry.SetPlaceHolder("Confirm password")
	confirmEntry.Password = true

	content := container.NewVBox(
		widget.NewLabel("Create a new vault. Each vault stores secrets separately."),
		widget.NewLabel("Name:"), nameEntry,
		widget.NewLabel("Password:"), pwEntry,
		widget.NewLabel("Confirm:"), confirmEntry,
	)

	dialog.ShowCustomConfirm("New Vault", "Create", "Cancel", content, func(create bool) {
		if !create {
			return
		}
		name := nameEntry.Text
		pw := pwEntry.Text
		confirm := confirmEntry.Text

		if name == "" {
			dialog.ShowError(fmt.Errorf("vault name is required"), g.window)
			return
		}
		if pw == "" {
			dialog.ShowError(fmt.Errorf("password is required"), g.window)
			return
		}
		if pw != confirm {
			dialog.ShowError(fmt.Errorf("passwords do not match"), g.window)
			return
		}

		mnemonic, err := g.backend.CreateVault(name, pw)
		if err != nil {
			dialog.ShowError(fmt.Errorf("create vault failed: %w", err), g.window)
			return
		}

		// Show recovery kit
		recoveryContent := container.NewVBox(
			widget.NewLabelWithStyle("Recovery Kit — Write these words down", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			widget.NewLabel(mnemonic),
			widget.NewLabelWithStyle("This phrase will NOT be shown again.", fyne.TextAlignLeading, fyne.TextStyle{Italic: true}),
		)
		dialog.ShowCustom("Vault Created", "OK", recoveryContent, g.window)

		// Switch to the new vault
		g.switchVault(name)
	}, g.window)
}

// showManageVaultsDialog displays a dialog to enable/disable, rename, delete vaults and set the default vault.
func (g *GUI) showManageVaultsDialog() {
	var d dialog.Dialog
	body := container.NewStack()

	var refresh func()
	refresh = func() {
		vaults, _ := config.ListVaults()
		cfg, _ := config.Load()
		if cfg == nil {
			cfg, _ = config.DefaultConfig()
		}

		rows := container.NewVBox()
		for _, v := range vaults {
			vName := v.Name
			isDisabled := v.Disabled
			isActive := (cfg.ActiveVault == "" && vName == "vault") || cfg.ActiveVault == vName

			statusStr := "[Enabled]"
			if isDisabled {
				statusStr = "[Disabled]"
			} else if isActive {
				statusStr = "[Active / Default]"
			}

			statusLbl := widget.NewLabelWithStyle(fmt.Sprintf("%-16s %s", vName, statusStr), fyne.TextAlignLeading, fyne.TextStyle{Bold: isActive})

			btnBox := container.NewHBox()

			// Rename button (for all vaults)
			renameBtn := widget.NewButtonWithIcon("Rename", theme.DocumentCreateIcon(), func() {
				nameEntry := widget.NewEntry()
				nameEntry.SetText(vName)
				renameItems := []*widget.FormItem{
					widget.NewFormItem("New Vault Name", nameEntry),
				}
				dialog.ShowForm("Rename Vault", "Rename", "Cancel", renameItems, func(ok bool) {
					if !ok {
						return
					}
					newName := strings.TrimSpace(nameEntry.Text)
					if newName == "" || newName == vName {
						return
					}
					if isActive {
						g.backend.Close()
						if err := RenameVault(vName, newName); err != nil {
							dialog.ShowError(fmt.Errorf("rename vault failed: %w", err), g.window)
							g.switchVault(vName)
							return
						}
						g.switchVault(newName)
						if d != nil {
							d.Hide()
						}
					} else {
						if err := RenameVault(vName, newName); err != nil {
							dialog.ShowError(fmt.Errorf("rename vault failed: %w", err), g.window)
							return
						}
						refresh()
					}
				}, g.window)
			})
			renameBtn.Importance = widget.LowImportance
			btnBox.Add(renameBtn)

			if isDisabled {
				enableBtn := widget.NewButtonWithIcon("Enable", theme.ConfirmIcon(), func() {
					_ = cfg.EnableVault(vName)
					refresh()
				})
				btnBox.Add(enableBtn)
			} else {
				if !isActive {
					setDefaultBtn := widget.NewButtonWithIcon("Set Default", theme.NavigateNextIcon(), func() {
						_ = cfg.SetActiveVault(vName)
						g.switchVault(vName)
						if d != nil {
							d.Hide()
						}
					})
					disableBtn := widget.NewButtonWithIcon("Disable", theme.CancelIcon(), func() {
						_ = cfg.DisableVault(vName)
						refresh()
					})
					disableBtn.Importance = widget.LowImportance
					btnBox.Add(setDefaultBtn)
					btnBox.Add(disableBtn)
				}
			}

			// Delete button
			deleteBtn := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() {
				confirmMsg := fmt.Sprintf("Are you sure you want to permanently delete vault %q?\nAll encrypted secrets and files in this vault will be lost forever.", vName)
				dialog.ShowConfirm("Delete Vault", confirmMsg, func(confirmed bool) {
					if !confirmed {
						return
					}
					if isActive {
						g.backend.Close()
						if err := DeleteVault(vName); err != nil {
							dialog.ShowError(fmt.Errorf("delete vault failed: %w", err), g.window)
							g.switchVault(vName)
							return
						}
						remaining, _ := config.ListEnabledVaults()
						if len(remaining) > 0 {
							g.switchVault(remaining[0].Name)
						} else {
							g.showNewVaultDialog()
						}
						if d != nil {
							d.Hide()
						}
					} else {
						if err := DeleteVault(vName); err != nil {
							dialog.ShowError(fmt.Errorf("delete vault failed: %w", err), g.window)
							return
						}
						refresh()
					}
				}, g.window)
			})
			deleteBtn.Importance = widget.DangerImportance
			btnBox.Add(deleteBtn)

			row := container.NewBorder(nil, nil, statusLbl, btnBox)
			rows.Add(row)
		}

		content := container.NewVBox(
			widget.NewLabelWithStyle("Manage Local Vaults", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			widget.NewSeparator(),
			rows,
		)
		body.Objects = []fyne.CanvasObject{content}
		body.Refresh()
	}

	refresh()
	d = dialog.NewCustom("Vault Manager", "Close", body, g.window)
	d.Resize(fyne.NewSize(620, 380))
	d.Show()
}
