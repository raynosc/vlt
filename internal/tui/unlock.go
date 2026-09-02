package tui

import (
	"encoding/json"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/parse"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
	"github.com/raynosc/vlt/internal/theme"
)

// updateUnlock handles messages in the unlock state.
// Everything is done synchronously for testability.
func (m model) updateUnlock(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyTab, tea.KeyLeft, tea.KeyRight:
		if len(m.vaultNames) > 1 {
			if msg.Type == tea.KeyLeft {
				m.activeVaultIdx = (m.activeVaultIdx - 1 + len(m.vaultNames)) % len(m.vaultNames)
			} else {
				m.activeVaultIdx = (m.activeVaultIdx + 1) % len(m.vaultNames)
			}
			newVault := m.vaultNames[m.activeVaultIdx]
			if err := m.switchVault(newVault); err == nil {
				m.err = ""
				m.passwordInput.SetValue("")
				return m, nil
			}
		}
		return m, nil

	case tea.KeyEnter:
		password := m.passwordInput.Value()
		if password == "" {
			m.err = "Password must not be empty"
			return m, nil
		}

		// Verify the master password against stored hash.
		if !m.engine.VerifyMasterPassword([]byte(password), m.salt, m.verifyHash) {
			m.attempts++
			crypto.Zeroize([]byte(password))
			m.passwordInput.SetValue("")

			if sqlSt, ok := m.st.(*store.SQLStore); ok {
				newCb, _ := sqlSt.RecordFailedMasterAttempt()
				if newCb != nil && newCb.IsPINChallenge {
					m.state = statePINChallenge
					m.err = "⚠️  3 failed master password attempts! Vault frozen.\nEnter 8-digit PIN to unfreeze."
					m.pinInput.SetValue("")
					m.pinInput.Focus()
					return m, nil
				}
			}

			if m.attempts >= m.maxAttempts {
				m.err = fmt.Sprintf("Too many failed attempts (%d/%d). Exiting.", m.attempts, m.maxAttempts)
				m.quitting = true
				return m, tea.Quit
			}
			m.err = fmt.Sprintf("Invalid master password. Attempt %d/%d", m.attempts+1, m.maxAttempts)
			return m, nil
		}

		// Clear failed attempts counter on success
		if sqlSt, ok := m.st.(*store.SQLStore); ok {
			_ = sqlSt.ResetMasterAttempts()
		}

		// Derive the master key for this session.
		key, err := m.engine.DeriveKey([]byte(password), m.salt)
		if err != nil {
			m.err = fmt.Sprintf("Key derivation failed: %v", err)
			crypto.Zeroize([]byte(password))
			return m, nil
		}
		crypto.Zeroize([]byte(password))

		m.key = key

		if cfg, err := config.Load(); err == nil {
			if cfg.ActiveVault != m.vaultName {
				_ = cfg.SetActiveVault(m.vaultName)
			}
		}

		// Load secrets immediately — stay synchronous for testability.
		secrets, err := m.loadSecrets()
		if err != nil {
			m.err = fmt.Sprintf("Failed to load secrets: %v", err)
			m.zeroizeKey()
			return m, nil
		}

		m.secrets = secrets
		m.cursor = 0
		m.err = ""
		m.passwordInput.Blur()

		// Load audit log for footer display
		entries, err := m.st.GetAuditLog(3)
		if err == nil {
			m.auditEntries = entries
		}

		// Log audit entry for vault unlock
		_ = m.st.LogAction("vault_unlock", "", "")

		// Startup checks: expiry warning and duplicate names
		m = m.runStartupChecks()

		m.state = stateList
		return m, nil

	case tea.KeyEsc:
		// Esc during unlock closes the app.
		m.quitting = true
		return m, tea.Quit

	case tea.KeyRunes:
		// Ignore custom rune handling in unlock.
	}

	// Forward key presses to text input.
	var cmd tea.Cmd
	m.passwordInput, cmd = m.passwordInput.Update(msg)
	return m, cmd
}

// runStartupChecks performs vault integrity checks after unlock.
// Checks: expiring certificates, duplicate names.
func (m model) runStartupChecks() model {
	// Check expiring certificates (30 days threshold)
	expiringCount := 0
	for _, sec := range m.secrets {
		if sec.Kind == secret.KindCertificate {
			if sec.Metadata != "" {
				var meta parse.Metadata
				if err := json.Unmarshal([]byte(sec.Metadata), &meta); err == nil && meta.NotAfter != "" {
					if meta.DaysUntilExpiry() <= 30 {
						expiringCount++
					}
				}
			}
		}
	}
	if expiringCount > 0 {
		m.err = fmt.Sprintf("⚠️  %d certificate(s) expiring within 30 days — press 'e' to view", expiringCount)
	}

	// Check for duplicate names in the loaded secrets
	seen := make(map[string]int)
	for _, sec := range m.secrets {
		seen[sec.Name]++
	}
	for name, count := range seen {
		if count > 1 {
			dupWarning := fmt.Sprintf("WARNING: duplicate name %q found (%d occurrences) — data may be corrupted", name, count)
			if m.err != "" {
				m.err += "\n" + dupWarning
			} else {
				m.err = dupWarning
			}
			break // show first duplicate found
		}
	}

	return m
}

// viewUnlock renders the unlock screen.
func (m model) viewUnlock() string {
	var content string

	content += "\n\n"
	content += lipgloss.NewStyle().Bold(true).Render("Unlock Vault") + "\n\n"

	if len(m.vaultNames) > 1 {
		content += labelStyle.Render("Vault: ") + lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.HexPurple)).Render(fmt.Sprintf("< %s >", m.vaultName)) +
			dimStyle.Render("  (Tab / ← → to change vault)") + "\n\n"
	} else if m.vaultName != "" {
		content += labelStyle.Render("Vault: ") + m.vaultName + "\n\n"
	}

	if m.err != "" {
		content += errorStyle.Render("! "+m.err) + "\n\n"
	}

	content += labelStyle.Render("Master Password:") + "\n"
	content += m.passwordInput.View() + "\n\n"
	if len(m.vaultNames) > 1 {
		content += helpStyle.Render("Enter to unlock · Tab to switch vault · Esc to quit")
	} else {
		content += helpStyle.Render(unlockFooterText)
	}

	return lipgloss.NewStyle().PaddingLeft(2).Render(content)
}
