package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/store"
	"github.com/raynosc/vlt/internal/theme"
)

// updatePINChallenge handles PIN input when the circuit breaker is engaged.
func (m model) updatePINChallenge(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		pin := m.pinInput.Value()
		if pin == "" {
			m.err = "PIN must not be empty"
			return m, nil
		}
		defer crypto.Zeroize([]byte(pin))

		sqlSt, ok := m.st.(*store.SQLStore)
		if !ok {
			m.err = "Store does not support PIN circuit breaker"
			return m, nil
		}

		pinHash, pinSalt, err := sqlSt.GetPINConfig()
		if err != nil || !m.engine.VerifyPIN(pin, pinSalt, pinHash) {
			newSt, _ := sqlSt.RecordFailedPINAttempt()
			m.pinInput.SetValue("")
			if newSt != nil && newSt.IsHardLockout {
				m.state = stateHardLockout
				m.err = "🚨 3 failed PIN attempts. HARD LOCKOUT engaged!\nEnter recovery phrase to rescue."
				m.recoveryInput.Focus()
				return m, nil
			}
			remaining := 3
			if newSt != nil {
				remaining = 3 - newSt.PINFailedAttempts
			}
			m.err = fmt.Sprintf("❌ Invalid PIN. %d attempts remaining before HARD LOCKOUT.", remaining)
			return m, nil
		}

		// PIN correct: unfreeze master password prompt
		_ = sqlSt.ResetMasterAttempts()
		m.state = stateUnlock
		m.err = "✅ PIN verified! Enter your Master Password."
		m.passwordInput.SetValue("")
		m.passwordInput.Focus()
		return m, nil

	case tea.KeyEsc:
		m.quitting = true
		return m, tea.Quit
	}

	var cmd tea.Cmd
	m.pinInput, cmd = m.pinInput.Update(msg)
	return m, cmd
}

// viewPINChallenge renders the PIN circuit breaker challenge screen.
func (m model) viewPINChallenge() string {
	var content string
	content += "\n\n"
	content += lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.HexWarning)).Render("⚠️  CIRCUIT BREAKER ENGAGED") + "\n\n"
	content += dimStyle.Render("3 failed master password attempts detected. Vault is frozen.") + "\n\n"

	if m.err != "" {
		content += errorStyle.Render("! "+m.err) + "\n\n"
	}

	content += labelStyle.Render("Enter 8-Digit PIN:") + "\n"
	content += m.pinInput.View() + "\n\n"
	content += helpStyle.Render("Enter to submit PIN · Esc to quit")

	return lipgloss.NewStyle().PaddingLeft(2).Render(content)
}

// updateHardLockout handles BIP39 recovery input during hard lockout.
func (m model) updateHardLockout(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		phrase := strings.TrimSpace(m.recoveryInput.Value())
		if phrase == "" {
			m.err = "Recovery phrase must not be empty"
			return m, nil
		}

		sqlSt, ok := m.st.(*store.SQLStore)
		if !ok {
			m.err = "Store does not support recovery"
			return m, nil
		}

		blob, err := sqlSt.ConfigGet(store.ConfigKeyRecoveryBlob)
		if err != nil || len(blob) == 0 {
			m.err = "No recovery blob found in vault"
			return m, nil
		}

		valid, err := m.engine.VerifyRecoveryKit(phrase, blob, m.salt, m.verifyHash)
		if err != nil || !valid {
			m.recoveryInput.SetValue("")
			m.err = "❌ Invalid recovery phrase. Verification failed."
			return m, nil
		}

		// Rescue successful: reset circuit breaker
		_ = sqlSt.ResetCircuitBreaker()
		m.state = stateUnlock
		m.err = "✅ Recovery verified! Hard lockout reset. Enter Master Password."
		m.passwordInput.SetValue("")
		m.passwordInput.Focus()
		return m, nil

	case tea.KeyEsc:
		m.quitting = true
		return m, tea.Quit
	}

	var cmd tea.Cmd
	m.recoveryInput, cmd = m.recoveryInput.Update(msg)
	return m, cmd
}

// viewHardLockout renders the Hard Lockout recovery screen.
func (m model) viewHardLockout() string {
	var content string
	content += "\n\n"
	content += lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.HexError)).Render("🚨 HARD LOCKOUT ACTIVE") + "\n\n"
	content += dimStyle.Render("The vault has been locked to prevent brute-force attacks.") + "\n"
	content += dimStyle.Render("Provide your 36-word recovery phrase to restore access.") + "\n\n"

	if m.err != "" {
		content += errorStyle.Render("! "+m.err) + "\n\n"
	}

	content += labelStyle.Render("Recovery Phrase:") + "\n"
	content += m.recoveryInput.View() + "\n\n"
	content += helpStyle.Render("Enter to verify recovery phrase · Esc to quit")

	return lipgloss.NewStyle().PaddingLeft(2).Render(content)
}
