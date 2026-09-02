package tui

import (
	"encoding/json"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/raynosc/vlt/internal/parse"
	"github.com/raynosc/vlt/internal/secret"
)

// isInspectable returns true if the secret kind supports metadata inspection.
func isInspectable(kind secret.Kind) bool {
	return kind == secret.KindCertificate || kind == secret.KindSSHKey
}

// inspectSecretAtCursor transitions to inspect state for the selected secret.
func (m model) inspectSecretAtCursor() (tea.Model, tea.Cmd) {
	if m.cursor < 0 || m.cursor >= len(m.secrets) {
		return m, nil
	}

	sec := m.secrets[m.cursor]

	// Non-inspectable kinds show error in list.
	if !isInspectable(sec.Kind) {
		m.err = "No metadata available for this secret type"
		return m, nil
	}

	// Check for empty metadata.
	if sec.Metadata == "" {
		m.err = "No metadata available for this secret type"
		return m, nil
	}

	// Validate metadata JSON.
	if !json.Valid([]byte(sec.Metadata)) {
		m.err = "Error: Unable to parse metadata"
		return m, nil
	}

	// Transition to inspect state.
	m.inspectSecret = sec
	m.state = stateInspect
	m.err = ""
	return m, nil
}

// updateInspect handles key events in the inspect state.
func (m model) updateInspect(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		// Return to list
		m.state = stateList
		m.inspectSecret = secret.Secret{}
		m.err = ""
		return m, nil

	case tea.KeyRunes:
		switch string(msg.Runes) {
		case "q":
			m.state = stateList
			m.inspectSecret = secret.Secret{}
			m.err = ""
			return m, nil
		}
	}
	return m, nil
}

// viewInspect renders the certificate/key metadata inspector screen.
func (m model) viewInspect() string {
	var content string

	sec := m.inspectSecret
	content += fmt.Sprintf("\n  %s\n\n", titleStyle.Render("Inspect: "+sec.Name))
	content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Kind:"), string(sec.Kind))

	// Parse metadata JSON.
	var meta parse.Metadata
	if err := json.Unmarshal([]byte(sec.Metadata), &meta); err != nil {
		content += fmt.Sprintf("\n  %s\n", errorStyle.Render("Error: Unable to parse metadata"))
		content += "\n" + helpStyle.Render("Esc back · q back")
		return lipgloss.NewStyle().PaddingLeft(2).Render(content)
	}

	content += "\n"

	// Render certificate fields.
	if meta.SubjectCN != "" || meta.IssuerCN != "" {
		content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Subject:"), meta.SubjectCN)
		content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Issuer:"), meta.IssuerCN)
		if meta.NotAfter != "" {
			expiryInfo := meta.NotAfter
			if meta.IsExpired() {
				expiryInfo += " ⚠️ EXPIRED"
			} else {
				days := meta.DaysUntilExpiry()
				expiryInfo += fmt.Sprintf("  (%dd until expiry)", days)
			}
			content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Expiry:"), expiryInfo)
		}
		if meta.NotBefore != "" {
			content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Not Before:"), meta.NotBefore)
		}
		if meta.SerialNumber != "" {
			content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Serial:"), meta.SerialNumber)
		}
		if meta.SignatureAlgorithm != "" {
			content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Sig Algo:"), meta.SignatureAlgorithm)
		}
		if meta.FingerprintSHA256 != "" {
			content += fmt.Sprintf("  %s SHA256:%s\n", labelStyle.Render("Fingerprint:"), meta.FingerprintSHA256)
		}
		if meta.FingerprintSHA1 != "" {
			content += fmt.Sprintf("  %s SHA1:%s\n", labelStyle.Render("Fingerprint:"), meta.FingerprintSHA1)
		}
		if len(meta.SANs) > 0 {
			content += fmt.Sprintf("  %s %s\n", labelStyle.Render("SANs:"), strings.Join(meta.SANs, ", "))
		}
		if len(meta.KeyUsage) > 0 {
			content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Key Usage:"), strings.Join(meta.KeyUsage, ", "))
		}
		if len(meta.ExtKeyUsage) > 0 {
			content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Ext Key Usage:"), strings.Join(meta.ExtKeyUsage, ", "))
		}
		if meta.IsCA {
			content += fmt.Sprintf("  %s %s\n", labelStyle.Render("CA:"), "true")
		}
	}

	// Render SSH fields.
	if meta.KeyType != "" {
		content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Key Type:"), meta.KeyType)
		if meta.BitLength > 0 {
			content += fmt.Sprintf("  %s %d\n", labelStyle.Render("Bits:"), meta.BitLength)
		}
		if meta.FingerprintSHA256 != "" {
			content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Fingerprint:"), meta.FingerprintSHA256)
		}
		if meta.Comment != "" {
			content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Comment:"), meta.Comment)
		}
	}

	// PKCS12 fields.
	if meta.CertCount > 0 {
		content += fmt.Sprintf("  %s %d\n", labelStyle.Render("Cert Count:"), meta.CertCount)
		if len(meta.FriendlyNames) > 0 {
			content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Friendly Names:"), strings.Join(meta.FriendlyNames, ", "))
		}
	}

	content += fmt.Sprintf("\n  %s %s\n", labelStyle.Render("Created:"), sec.CreatedAt.Format(displayTimeFormat))
	content += fmt.Sprintf("  %s %s\n", labelStyle.Render("Updated:"), sec.UpdatedAt.Format(displayTimeFormat))

	content += "\n" + helpStyle.Render(inspectFooterText)
	return lipgloss.NewStyle().PaddingLeft(2).Render(content)
}
