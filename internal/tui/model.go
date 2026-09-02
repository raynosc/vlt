// Package tui provides a Bubble Tea terminal UI for browsing and viewing secrets.
//
// Architecture: state-machine with 6 states (unlock → list → detail → search → add → inspect).
// TUI reuses CLI core — imports internal/crypto, internal/store, internal/config directly.
// Never duplicates crypto or store logic.
package tui

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/otp"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
	"github.com/raynosc/vlt/internal/theme"
)

// clipboardClearDuration is how long the clipboard persists before best-effort clear.
const clipboardClearDuration = 30 * time.Second

// inactivityCheckInterval is how often we check for inactivity.
const inactivityCheckInterval = 30 * time.Second

// appState represents the current screen in the TUI state machine.
type appState int

const (
	stateUnlock       appState = iota // Master password prompt
	statePINChallenge                 // Circuit breaker PIN challenge (after 3 failed master attempts)
	stateHardLockout                  // Hard lockout screen (requires 36-word BIP39 recovery kit)
	stateList                         // Scrollable secret list
	stateDetail                       // Secret detail with decrypted value
	stateSearch                       // Search overlay with real-time filtering
	stateAdd                          // Add new secret form
	stateInspect                      // Certificate/key metadata inspector
)

// Styles used throughout the TUI.
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(theme.HexPurple)).
			Padding(0, 1)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.HexDim))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.HexError)).
			Bold(true)

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.HexPurple)).
			Bold(true)

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.HexDimLight))

	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(theme.HexLabel))

	clipboardStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.HexSuccess)).
			Italic(true)

	separator = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.HexSeparator)).
			Render(separatorLine)

	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.HexWarning)).
			Italic(true)
)

// Messages.
type (
	clipboardCopiedMsg struct{}
	clipboardClearMsg  struct{}
	inactivityTickMsg  struct{}
	otpTickMsg         struct{}
)

// model is the root Bubble Tea model for the passwd TUI.
type model struct {
	// Dependencies (injected, never nil)
	st         store.Store
	engine     *crypto.Engine
	salt       []byte
	verifyHash []byte

	// Session key — derived on unlock, zeroized on quit
	key []byte

	// Terminal dimensions
	width  int
	height int

	// Application state
	state appState

	// ── Unlock & Circuit Breaker state ──
	passwordInput  textinput.Model
	pinInput       textinput.Model
	recoveryInput  textinput.Model
	attempts       int
	maxAttempts    int
	noKeychain     bool // skip keychain for this session
	vaultName      string
	vaultNames     []string
	activeVaultIdx int

	// ── List state ──
	secrets []secret.Secret
	cursor  int

	// ── Detail state ──
	detailSecret  secret.Secret
	plaintext     []byte // zeroized before release
	showPlaintext bool
	detailVP      viewport.Model

	// ── Search state ──
	searchInput   textinput.Model
	searchQuery   string
	searchResults []secret.Secret

	// ── Inspect state ──
	inspectSecret secret.Secret

	// ── Add state ──
	addNameInput  textinput.Model
	addValueInput textinput.Model
	addUserInput  textinput.Model // username (password kind only)
	addSiteInput  textinput.Model // site/url (password kind only)
	addNotesInput textinput.Model // free text notes
	addFocusIndex int             // 0=name, 1=value, 2=user, 3=site, 4=notes
	addKindIndex  int             // index into secret.ValidKinds() for kind selector
	addFileMode   bool            // when true, show file path input instead of value
	addFileInput  textinput.Model // file path input when in file mode

	// ── Edit state (reuses add form) ──
	editMode       bool   // when true, add form acts as edit form
	editSecretName string // original name before edit (for delete+store)

	// ── List state ──
	kindFilter   string // "" = no filter, "certificate", "ssh_key", etc.
	tagFilter    string // "" = no filter, tag name to filter by
	expiringMode bool   // when true, show expiring certs only

	// ── Export confirmation ──
	confirmExport bool

	// ── Audit log ──
	auditEntries []secret.AuditEntry

	// ── Error and feedback ──
	err             string
	clipboardMsg    string
	lastCopiedValue string

	// ── OTP / TOTP detail code ──
	otpCode      string // current TOTP code
	otpCountdown int    // remaining seconds in current period
	otpPeriod    int    // period in seconds (default 30)

	// ── Inactivity auto-lock ──
	inactivityTimeout time.Duration // 0 = never lock
	lastActivity      time.Time     // last user interaction time

	// ── Quit ──
	quitting bool
}

// NewModel creates a new TUI model with the given dependencies.
// timeoutMinutes is the auto-lock inactivity timeout in minutes (0 = never lock).
func NewModel(st store.Store, engine *crypto.Engine, salt, verifyHash []byte, timeoutMinutes int, noKeychain bool) model {
	pi := textinput.New()
	pi.Placeholder = placeholderMasterPassword
	pi.EchoMode = textinput.EchoPassword
	pi.EchoCharacter = '•'
	pi.Focus()

	si := textinput.New()
	si.Placeholder = placeholderSearch
	si.CharLimit = 100

	ani := textinput.New()
	ani.Placeholder = placeholderSecretName
	ani.CharLimit = 100
	ani.Focus()

	avi := textinput.New()
	avi.Placeholder = placeholderSecretValue
	avi.EchoMode = textinput.EchoPassword
	avi.EchoCharacter = '•'

	afi := textinput.New()
	afi.Placeholder = placeholderFilePath
	afi.CharLimit = 512

	aui := textinput.New()
	aui.Placeholder = placeholderUsername
	aui.CharLimit = 100

	asi := textinput.New()
	asi.Placeholder = placeholderSiteURL
	asi.CharLimit = 256

	ant := textinput.New()
	ant.Placeholder = placeholderNotes
	ant.CharLimit = 500

	pinIn := textinput.New()
	pinIn.Placeholder = "Enter 8-digit PIN"
	pinIn.CharLimit = 8
	pinIn.EchoMode = textinput.EchoPassword
	pinIn.EchoCharacter = '•'

	recIn := textinput.New()
	recIn.Placeholder = "Enter 36-word recovery phrase"
	recIn.CharLimit = 512
	recIn.EchoMode = textinput.EchoPassword
	recIn.EchoCharacter = '•'

	// Convert minutes to duration (0 means never lock)
	var timeout time.Duration
	if timeoutMinutes > 0 {
		timeout = time.Duration(timeoutMinutes) * time.Minute
	}

	vaultInfos, _ := config.ListEnabledVaults()
	var vaultNames []string
	currentVaultName := ""
	currentIdx := 0
	cfg, err := config.Load()
	if err == nil && cfg.ActiveVault != "" {
		currentVaultName = cfg.ActiveVault
	}
	for i, v := range vaultInfos {
		vaultNames = append(vaultNames, v.Name)
		if v.Name == currentVaultName {
			currentIdx = i
		}
	}
	if currentVaultName == "" && len(vaultNames) > 0 {
		currentVaultName = vaultNames[0]
	}

	// Check initial Circuit Breaker state
	initialState := stateUnlock
	if sqlSt, ok := st.(*store.SQLStore); ok {
		if cb, err := sqlSt.GetCircuitBreakerState(); err == nil {
			if cb.IsHardLockout {
				initialState = stateHardLockout
				recIn.Focus()
			} else if cb.IsPINChallenge {
				initialState = statePINChallenge
				pinIn.Focus()
			}
		}
	}

	return model{
		st:                st,
		engine:            engine,
		salt:              salt,
		verifyHash:        verifyHash,
		state:             initialState,
		passwordInput:     pi,
		pinInput:          pinIn,
		recoveryInput:     recIn,
		searchInput:       si,
		addNameInput:      ani,
		addValueInput:     avi,
		addFileInput:      afi,
		addUserInput:      aui,
		addSiteInput:      asi,
		addNotesInput:     ant,
		maxAttempts:       3,
		width:             80,
		height:            24,
		detailVP:          viewport.New(78, 10),
		inactivityTimeout: timeout,
		lastActivity:      time.Now(),
		tagFilter:         "",
		noKeychain:        noKeychain,
		vaultName:         currentVaultName,
		vaultNames:        vaultNames,
		activeVaultIdx:    currentIdx,
	}
}

// switchVault closes current store and opens the specified vault.
func (m *model) switchVault(newVault string) error {
	vaultPath, err := config.VaultPathForName(newVault)
	if err != nil {
		return err
	}

	newSt := store.NewSQLStore()
	if err := newSt.Init(vaultPath); err != nil {
		return err
	}

	salt, err := newSt.ConfigGet("salt")
	if err != nil {
		_ = newSt.Close()
		return err
	}

	verifyHash, err := newSt.ConfigGet("verify_hash")
	if err != nil {
		_ = newSt.Close()
		return err
	}

	argon2Params := crypto.DefaultArgon2Params
	if timeBytes, err := newSt.ConfigGet("argon2_time"); err == nil && len(timeBytes) == 4 {
		argon2Params.Time = binary.BigEndian.Uint32(timeBytes)
	}
	if memBytes, err := newSt.ConfigGet("argon2_memory"); err == nil && len(memBytes) == 4 {
		argon2Params.Memory = binary.BigEndian.Uint32(memBytes)
	}
	if threadBytes, err := newSt.ConfigGet("argon2_threads"); err == nil && len(threadBytes) == 1 {
		argon2Params.Threads = threadBytes[0]
	}

	if m.st != nil {
		_ = m.st.Close()
	}

	m.st = newSt
	m.salt = salt
	m.verifyHash = verifyHash
	m.engine = crypto.NewEngine(&argon2Params)
	m.vaultName = newVault

	if cfg, err := config.Load(); err == nil {
		_ = cfg.SetActiveVault(newVault)
	}
	return nil
}

// Init implements tea.Model.
func (m model) Init() tea.Cmd {
	var cmds []tea.Cmd
	cmds = append(cmds, textinput.Blink)

	// Start inactivity ticker if timeout is configured
	if m.inactivityTimeout > 0 {
		cmds = append(cmds, m.startInactivityTicker())
	}

	return tea.Batch(cmds...)
}

// startInactivityTicker returns a command that ticks periodically to check inactivity.
func (m model) startInactivityTicker() tea.Cmd {
	return tea.Tick(inactivityCheckInterval, func(t time.Time) tea.Msg {
		return inactivityTickMsg{}
	})
}

// Update implements tea.Model.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.detailVP.Width = msg.Width - 4
		m.detailVP.Height = msg.Height - 14
		if m.detailVP.Height < 3 {
			m.detailVP.Height = 3
		}
		return m, nil

	case tea.KeyMsg:
		// Track last activity for auto-lock (only when unlocked).
		if m.state != stateUnlock && m.inactivityTimeout > 0 {
			m.lastActivity = time.Now()
		}

		// Global quit: Ctrl+C always quits immediately.
		if msg.Type == tea.KeyCtrlC {
			m.zeroizeKey()
			m.quitting = true
			return m, tea.Quit
		}

		// Dispatch by state.
		switch m.state {
		case stateUnlock:
			return m.updateUnlock(msg)
		case statePINChallenge:
			return m.updatePINChallenge(msg)
		case stateHardLockout:
			return m.updateHardLockout(msg)
		case stateList:
			return m.updateList(msg)
		case stateDetail:
			return m.updateDetail(msg)
		case stateSearch:
			return m.updateSearch(msg)
		case stateAdd:
			return m.updateAdd(msg)
		case stateInspect:
			return m.updateInspect(msg)
		}

	case clipboardCopiedMsg:
		m.clipboardMsg = "✓ Copied to clipboard! Will auto-clear in 30s."
		return m, tea.Tick(clipboardClearDuration, func(t time.Time) tea.Msg {
			return clipboardClearMsg{}
		})

	case clipboardClearMsg:
		m.clipboardMsg = ""
		if current, err := clipboard.ReadAll(); err == nil && current == m.lastCopiedValue {
			_ = clipboard.WriteAll("")
		}
		return m, nil

	case otpTickMsg:
		if m.state == stateDetail && m.otpCode != "" {
			currentTime := time.Now().UTC()
			remaining := m.otpPeriod - int(currentTime.Unix()%int64(m.otpPeriod))

			// If countdown wrapped past 0, regenerate the code.
			// S-02: rebuild a full otpauth URI from the encrypted_otp_seed
			// column when present; fall back to legacy metadata otherwise.
			if remaining > m.otpCountdown || remaining == m.otpPeriod-1 {
				meta := secret.UnmarshalPasswordMetadata(m.detailSecret.Metadata)
				if meta != nil && meta.OTPAuth != "" {
					uriStr := meta.OTPAuth
					if len(m.detailSecret.EncryptedOTPSeed) > 0 && len(m.key) == 32 {
						if seed, err := decryptOTPSeed(m.engine, m.detailSecret.EncryptedOTPSeed, m.key); err == nil {
							uriStr = otp.InjectOTPSecret(uriStr, seed)
						}
					}
					if uri, err := otp.ParseOTPURI(uriStr); err == nil {
						if code, err := otp.GenerateTOTP(uri.Secret, currentTime, uri.Digits, uri.Algorithm); err == nil {
							m.otpCode = code
						}
					}
				}
			}
			m.otpCountdown = remaining
			return m, m.startOTPTicker()
		}
		return m, nil

	case inactivityTickMsg:
		// Check for inactivity timeout — only when unlocked.
		if m.state != stateUnlock && m.state != statePINChallenge && m.state != stateHardLockout && m.inactivityTimeout > 0 {
			if time.Since(m.lastActivity) >= m.inactivityTimeout {
				// Lock the session.
				m.zeroizeKey()
				m.state = stateUnlock
				m.passwordInput.SetValue("")
				m.passwordInput.Focus()
				m.err = "Session locked due to inactivity."
				// Reset last activity to avoid re-locking immediately.
				m.lastActivity = time.Now()
				return m, nil
			}
		}
		// Re-schedule the ticker.
		return m, m.startInactivityTicker()
	}

	return m, nil
}

// View implements tea.Model.
func (m model) View() string {
	if m.quitting {
		return ""
	}

	var content string
	switch m.state {
	case stateUnlock:
		content = m.viewUnlock()
	case statePINChallenge:
		content = m.viewPINChallenge()
	case stateHardLockout:
		content = m.viewHardLockout()
	case stateList:
		content = m.viewList()
	case stateDetail:
		content = m.viewDetail()
	case stateSearch:
		content = m.viewSearch()
	case stateAdd:
		content = m.viewAdd()
	case stateInspect:
		content = m.viewInspect()
	}

	return lipgloss.JoinVertical(lipgloss.Top,
		titleStyle.Render("passwd"),
		separator,
		content,
	)
}

// unpackEnvelope splits a stored blob (nonce || ciphertext) into its components.
func unpackEnvelope(blob []byte) (nonce, ciphertext []byte, err error) {
	return crypto.UnpackEnvelope(blob)
}

// zeroizeKey clears the session key from memory.
func (m *model) zeroizeKey() {
	if m.key != nil {
		crypto.Zeroize(m.key)
		m.key = nil
	}
}

// loadSecrets loads all secrets from the store and decrypts their metadata.
func (m model) loadSecrets() ([]secret.Secret, error) {
	secrets, err := m.st.List()
	if err != nil {
		return nil, err
	}
	if m.key != nil && m.engine != nil {
		for i := range secrets {
			_ = decryptSecretMetadata(&secrets[i], m.engine, m.key)
		}
	}
	return secrets, nil
}

// decryptSecretMetadata decrypts all encrypted metadata fields of a secret in-place.
func decryptSecretMetadata(sec *secret.Secret, eng *crypto.Engine, key []byte) error {
	if len(sec.EncryptedName) > 0 {
		nonce, ct, err := unpackEnvelope(sec.EncryptedName)
		if err != nil {
			return fmt.Errorf("decrypt name: %w", err)
		}
		pt, err := eng.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt name: %w", err)
		}
		sec.Name = string(pt)
		crypto.Zeroize(pt)
	}
	if len(sec.EncryptedNotes) > 0 {
		nonce, ct, err := unpackEnvelope(sec.EncryptedNotes)
		if err != nil {
			return fmt.Errorf("decrypt notes: %w", err)
		}
		pt, err := eng.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt notes: %w", err)
		}
		sec.Notes = string(pt)
		crypto.Zeroize(pt)
	}
	if len(sec.EncryptedTags) > 0 {
		nonce, ct, err := unpackEnvelope(sec.EncryptedTags)
		if err != nil {
			return fmt.Errorf("decrypt tags: %w", err)
		}
		pt, err := eng.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt tags: %w", err)
		}
		sec.Tags = string(pt)
		crypto.Zeroize(pt)
	}
	if len(sec.EncryptedMetadata) > 0 {
		nonce, ct, err := unpackEnvelope(sec.EncryptedMetadata)
		if err != nil {
			return fmt.Errorf("decrypt metadata: %w", err)
		}
		pt, err := eng.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt metadata: %w", err)
		}
		sec.Metadata = string(pt)
		crypto.Zeroize(pt)
	}
	return nil
}

// encryptSecretMetadata encrypts all plaintext metadata fields.
func encryptSecretMetadata(s *secret.Secret, eng *crypto.Engine, key []byte) error {
	ct, nonce, err := eng.Encrypt([]byte(s.Name), key)
	if err != nil {
		return fmt.Errorf("encrypt name: %w", err)
	}
	s.EncryptedName = crypto.PackEnvelope(nonce, ct)

	if s.Notes != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Notes), key)
		if err != nil {
			return fmt.Errorf("encrypt notes: %w", err)
		}
		s.EncryptedNotes = crypto.PackEnvelope(nonce, ct)
	} else {
		s.EncryptedNotes = []byte{}
	}

	if s.Tags != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Tags), key)
		if err != nil {
			return fmt.Errorf("encrypt tags: %w", err)
		}
		s.EncryptedTags = crypto.PackEnvelope(nonce, ct)
	} else {
		s.EncryptedTags = []byte{}
	}

	if s.Metadata != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Metadata), key)
		if err != nil {
			return fmt.Errorf("encrypt metadata: %w", err)
		}
		s.EncryptedMetadata = crypto.PackEnvelope(nonce, ct)
	} else {
		s.EncryptedMetadata = []byte{}
	}

	s.NameLookup = crypto.ComputeNameLookup(key, s.Name)
	return nil
}
