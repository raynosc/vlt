package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/otp"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/theme"
)

const displayTimeFormat = "2006-01-02 15:04"

// updateDetail handles messages in the detail state.
func (m model) updateDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc, tea.KeyLeft:
		// Go back to list, zeroize secret plaintext.
		return m.backToList(), nil

	case tea.KeyEnter, tea.KeySpace:
		// Toggle reveal of decrypted value.
		m.showPlaintext = !m.showPlaintext
		if !m.showPlaintext {
			crypto.Zeroize(m.plaintext)
		}
		m.detailVP.SetContent(m.buildDetailContent())
		return m, nil

	case tea.KeyCtrlE:
		// Enter edit mode — pre-fill add form with current values.
		return m.enterEditMode(), nil

	case tea.KeyRunes:
		switch string(msg.Runes) {
		case "c", "C":
			return m.copyToClipboard()
		case "q":
			return m.backToList(), nil
		case "r", "R":
			m.showPlaintext = !m.showPlaintext
			if !m.showPlaintext {
				crypto.Zeroize(m.plaintext)
			}
			m.detailVP.SetContent(m.buildDetailContent())
			return m, nil
		case "e", "E":
			// Enter edit mode — pre-fill add form with current values.
			return m.enterEditMode(), nil
		case "x", "X":
			// Export current secret as a file with confirmation.
			return m.exportSecretAsFile()
		case "y", "Y":
			// Confirm export.
			if m.confirmExport {
				return m.doExportSecretAsFile()
			}
			return m, nil
		case "n", "N":
			// Cancel export.
			if m.confirmExport {
				m.confirmExport = false
				m.err = "Export cancelled."
				return m, nil
			}
			return m, nil
		}

	case tea.KeyUp, tea.KeyDown, tea.KeyPgUp, tea.KeyPgDown:
		var cmd tea.Cmd
		m.detailVP, cmd = m.detailVP.Update(msg)
		return m, cmd
	}

	return m, nil
}

// backToList transitions from detail back to list, zeroizing the secret.
// OTP fields are cleared, which stops the ticker (no tick cmd returned).
func (m model) backToList() model {
	crypto.Zeroize(m.plaintext)
	m.plaintext = nil
	m.showPlaintext = false
	m.detailSecret = secret.Secret{}
	m.clipboardMsg = ""
	m.err = ""
	m.otpCode = ""
	m.otpCountdown = 0
	m.otpPeriod = 30
	m.state = stateList
	return m
}

// copyToClipboard copies the decrypted value to the system clipboard.
func (m model) copyToClipboard() (tea.Model, tea.Cmd) {
	if len(m.plaintext) == 0 {
		return m, nil
	}

	if err := clipboard.WriteAll(string(m.plaintext)); err != nil {
		m.err = fmt.Sprintf("Clipboard error: %v", err)
		return m, nil
	}

	m.lastCopiedValue = string(m.plaintext)

	return m, func() tea.Msg {
		return clipboardCopiedMsg{}
	}
}

// viewDetail renders the detail screen.
func (m model) viewDetail() string {
	var content string

	sec := m.detailSecret

	content += fmt.Sprintf("\n  %s\n\n", lipgloss.NewStyle().Bold(true).Render(sec.Name))

	// Metadata.
	content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Kind:"), string(sec.Kind))
	tagsLabel := dimStyle.Render("[" + sec.Tags + "]")
	content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Tags:"), tagsLabel)
	content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Created:"), sec.CreatedAt.Format(displayTimeFormat))
	content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Updated:"), sec.UpdatedAt.Format(displayTimeFormat))

	if sec.Notes != "" {
		content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Notes:"), sec.Notes)
	}

	// OTP section — show live TOTP code and countdown bar.
	if m.otpCode != "" {
		content += "\n"
		content += fmt.Sprintf("  %s\n", labelStyle.Render("TOTP:"))
		content += fmt.Sprintf("  %s\n", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.HexSuccess)).Render(m.otpCode))
		bar := renderOTPBar(m.otpCountdown, m.otpPeriod)
		content += fmt.Sprintf("  %s  %ds\n\n", bar, m.otpCountdown)
	}

	content += "\n"

	// Clipboard message.
	if m.clipboardMsg != "" {
		content += "  " + clipboardStyle.Render(m.clipboardMsg) + "\n\n"
	}

	// Error message.
	if m.err != "" {
		content += "  " + errorStyle.Render("! "+m.err) + "\n\n"
	}

	// Decrypted value (hidden by default).
	if m.showPlaintext {
		content += fmt.Sprintf("  %s\n", labelStyle.Render("Value:"))
		content += m.detailVP.View() + "\n"
	} else {
		content += fmt.Sprintf("  %s %s\n\n", labelStyle.Render("Value:"), dimStyle.Render("[hidden — press Enter to reveal]"))
	}

	content += "\n" + detailFooter(m.showPlaintext)
	return lipgloss.NewStyle().PaddingLeft(2).Render(content)
}

// renderOTPBar renders a countdown progress bar for OTP.
func renderOTPBar(remaining, period int) string {
	const barWidth = 30
	filled := (barWidth * (period - remaining)) / period
	if filled < 0 {
		filled = 0
	}
	if filled > barWidth {
		filled = barWidth
	}
	bar := "["
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	bar += "]"
	return bar
}

// initOTP initializes the OTP code and countdown for the current detail secret.
// Returns the model and a tick command if OTPAuth is present.
//
// S-02: when the secret carries a separate EncryptedOTPSeed, the real seed is
// decrypted on the fly and injected into the URI so that ParseOTPURI sees a
// complete `secret=` parameter. Legacy vaults that still hold the seed in
// metadata continue to work via the existing path.
func (m model) initOTP() (model, tea.Cmd) {
	meta := secret.UnmarshalPasswordMetadata(m.detailSecret.Metadata)
	if meta == nil || meta.OTPAuth == "" {
		return m, nil
	}

	uriStr := meta.OTPAuth
	if len(m.detailSecret.EncryptedOTPSeed) > 0 && len(m.key) == 32 {
		if seed, err := decryptOTPSeed(m.engine, m.detailSecret.EncryptedOTPSeed, m.key); err == nil {
			uriStr = otp.InjectOTPSecret(uriStr, seed)
		}
	}

	uri, err := otp.ParseOTPURI(uriStr)
	if err != nil {
		return m, nil
	}

	m.otpPeriod = uri.Period
	if m.otpPeriod <= 0 {
		m.otpPeriod = 30
	}

	currentTime := time.Now().UTC()
	m.otpCountdown = m.otpPeriod - int(currentTime.Unix()%int64(m.otpPeriod))

	code, err := otp.GenerateTOTP(uri.Secret, currentTime, uri.Digits, uri.Algorithm)
	if err != nil {
		return m, nil
	}
	m.otpCode = code

	return m, m.startOTPTicker()
}

// decryptOTPSeed unpacks the nonce-prefixed AES-GCM envelope used for
// EncryptedOTPSeed and returns the plaintext seed. The caller is responsible
// for not retaining the returned string beyond what's necessary.
func decryptOTPSeed(engine *crypto.Engine, blob, key []byte) (string, error) {
	if len(blob) < 12 {
		return "", fmt.Errorf("otp seed blob too short")
	}
	nonce, ct := blob[:12], blob[12:]
	pt, err := engine.Decrypt(ct, key, nonce)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// startOTPTicker returns a command that ticks every second for OTP countdown.
func (m model) startOTPTicker() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return otpTickMsg{}
	})
}

// buildDetailContent builds the scrollable content for the detail viewport.
func (m model) buildDetailContent() string {
	if !m.showPlaintext || len(m.plaintext) == 0 {
		return ""
	}

	content := warnStyle.Render("WARNING: This value is visible on screen") + "\n"
	content += warnStyle.Render("and in the system clipboard. Clear both after use.") + "\n\n"
	content += string(m.plaintext)
	return content
}

// enterEditMode transitions from detail to the add form in edit mode,
// pre-filled with the current secret's values.
func (m model) enterEditMode() model {
	sec := m.detailSecret
	m.editMode = true
	m.editSecretName = sec.Name
	m.addNameInput.SetValue(sec.Name)
	m.addValueInput.SetValue(string(m.plaintext))
	m.addNotesInput.SetValue(sec.Notes)

	// Set kind index to match the current secret's kind
	validKinds := secret.ValidKinds()
	for i, k := range validKinds {
		if k == sec.Kind {
			m.addKindIndex = i
			break
		}
	}

	m.addFocusIndex = 0
	m.addFileMode = false
	m.addNameInput.Focus()
	m.addValueInput.Blur()
	m.err = ""
	m.state = stateAdd
	return m
}

// exportSecretAsFile shows a confirmation prompt before exporting.
func (m model) exportSecretAsFile() (tea.Model, tea.Cmd) {
	if len(m.plaintext) == 0 {
		m.err = "No decrypted value to export"
		return m, nil
	}

	m.confirmExport = true
	m.err = fmt.Sprintf("Export %q to disk? This will write decrypted values. Press Y to confirm, N to cancel.", m.detailSecret.Name)
	return m, nil
}

// doExportSecretAsFile writes the current secret's decrypted value to a file.
func (m model) doExportSecretAsFile() (tea.Model, tea.Cmd) {
	m.confirmExport = false

	if len(m.plaintext) == 0 {
		m.err = "No decrypted value to export"
		return m, nil
	}

	// Determine file extension based on kind
	ext := fileExtensionForTUIFile(m.detailSecret.Kind, m.plaintext)
	filename := m.detailSecret.Name + ext

	// Write to current working directory
	outPath, err := filepath.Abs(filename)
	if err != nil {
		m.err = fmt.Sprintf("Path error: %v", err)
		return m, nil
	}

	if err := os.WriteFile(outPath, m.plaintext, 0o600); err != nil {
		m.err = fmt.Sprintf("Write error: %v", err)
		return m, nil
	}

	m.err = ""
	fmt.Fprintf(os.Stderr, "WARNING: exported plaintext %q to %s\n", m.detailSecret.Name, outPath)
	m.clipboardMsg = fmt.Sprintf("Exported to %s", filename)
	return m, nil
}

// fileExtensionForTUIFile returns the appropriate file extension for exporting a secret.
func fileExtensionForTUIFile(kind secret.Kind, data []byte) string {
	switch kind {
	case secret.KindCertificate:
		return ".pem"
	case secret.KindSSHKey:
		dataStr := string(data)
		if strings.Contains(dataStr, "PUBLIC KEY") || strings.Contains(dataStr, "ssh-") {
			return ".pub"
		}
		return ".key"
	case secret.KindNote:
		return ".txt"
	default:
		return ".txt"
	}
}

// detailFooter renders the keybinding help bar for the detail screen.
func detailFooter(showPlaintext bool) string {
	return helpStyle.Render(detailFooterText)
}
