package tui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/parse"
	"github.com/raynosc/vlt/internal/secret"
)

// updateList handles messages in the list state.
func (m model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		if m.cursor > 0 {
			m.cursor--
		}

	case tea.KeyDown, tea.KeyTab:
		if len(m.secrets) > 0 && m.cursor < len(m.secrets)-1 {
			m.cursor++
		}

	case tea.KeyRunes:
		switch string(msg.Runes) {
		case "j":
			if len(m.secrets) > 0 && m.cursor < len(m.secrets)-1 {
				m.cursor++
			}
		case "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "/":
			// Activate search overlay — also resets kind filter.
			m.state = stateSearch
			m.kindFilter = ""
			m.searchInput.SetValue("")
			m.searchInput.Focus()
			m.searchQuery = ""
			m.searchResults = nil
			m.err = ""
			return m, nil
		case "a":
			// Enter add secret form.
			m.state = stateAdd
			m.addNameInput.Reset()
			m.addValueInput.Reset()
			m.addFileInput.Reset()
			m.addFocusIndex = 0
			m.addKindIndex = 0
			m.addFileMode = false
			m.addNameInput.Focus()
			m.addValueInput.Blur()
			m.err = ""
			return m, nil
		case "d":
			// Delete selected secret with confirmation.
			if len(m.secrets) == 0 || m.cursor >= len(m.secrets) {
				return m, nil
			}
			return m.deleteSelected()
		case "q":
			m.zeroizeKey()
			m.quitting = true
			return m, tea.Quit
		case "f":
			// Cycle kind filter.
			m = m.cycleKindFilter()
			return m, nil
		case "t":
			// Cycle tag filter.
			m = m.cycleTagFilter()
			return m, nil
		case "e":
			// Toggle expiring mode.
			return m.toggleExpiring()
		case "i":
			// Inspect certificate/key metadata.
			if len(m.secrets) == 0 || m.cursor >= len(m.secrets) {
				return m, nil
			}
			return m.inspectSecretAtCursor()
		}

	case tea.KeyEnter:
		if len(m.secrets) == 0 {
			return m, nil
		}
		return m.selectSecret(m.secrets[m.cursor])

	case tea.KeyEsc:
		// Esc on list — quit.
		m.zeroizeKey()
		m.quitting = true
		return m, tea.Quit
	}

	return m, nil
}

// selectSecret retrieves full secret details and transitions to detail state.
func (m model) selectSecret(sec secret.Secret) (tea.Model, tea.Cmd) {
	// Retrieve full secret with encrypted value.
	full, err := m.st.GetByNameLookup(sec.NameLookup)
	if err != nil {
		m.err = fmt.Sprintf("Failed to load secret: %v", err)
		return m, nil
	}

	// Unpack the envelope (nonce || ciphertext) and decrypt.
	nonce, ciphertext, err := unpackEnvelope(full.EncryptedValue)
	if err != nil {
		m.err = "Failed to unpack encrypted data"
		return m, nil
	}

	plaintext, err := m.engine.Decrypt(ciphertext, m.key, nonce)
	if err != nil {
		m.err = "Decryption failed"
		return m, nil
	}

	m.detailSecret = full
	m.plaintext = plaintext
	m.showPlaintext = false
	m.err = ""
	m.detailVP.SetContent(m.buildDetailContent())

	m.state = stateDetail

	// Initialize OTP if the secret has OTPAuth metadata.
	var otpCmd tea.Cmd
	m, otpCmd = m.initOTP()

	return m, otpCmd
}

// viewList renders the list screen.
func (m model) viewList() string {
	var content string

	var header string
	if m.expiringMode {
		header = fmt.Sprintf("\n  %s  %d secrets (expiring only)\n\n",
			lipgloss.NewStyle().Bold(true).Render("Expiring Certificates"),
			len(m.secrets),
		)
	} else if m.kindFilter != "" {
		header = fmt.Sprintf("\n  %s  %d secrets (filter: %s)\n\n",
			lipgloss.NewStyle().Bold(true).Render("Secrets"),
			len(m.secrets),
			m.kindFilter,
		)
	} else if m.tagFilter != "" {
		header = fmt.Sprintf("\n  %s  %d secrets (tag: %s)\n\n",
			lipgloss.NewStyle().Bold(true).Render("Secrets"),
			len(m.secrets),
			m.tagFilter,
		)
	} else {
		header = fmt.Sprintf("\n  %s  %d secrets\n\n",
			lipgloss.NewStyle().Bold(true).Render("Secrets"),
			len(m.secrets),
		)
	}
	content += header

	if m.err != "" {
		content += errorStyle.Render("! "+m.err) + "\n\n"
		m.err = ""
	}

	if m.clipboardMsg != "" {
		content += clipboardStyle.Render(m.clipboardMsg) + "\n"
		m.clipboardMsg = ""
	}

	if len(m.secrets) == 0 {
		if m.expiringMode {
			content += dimStyle.Render("  No expiring certificates.") + "\n"
		} else {
			content += dimStyle.Render("  No secrets found.") + "\n"
		}
	} else {
		// Apply client-side kind and tag filters when active (non-expiring mode).
		displayed := m.secrets
		if !m.expiringMode {
			if m.kindFilter != "" {
				var filtered []secret.Secret
				for _, sec := range m.secrets {
					if string(sec.Kind) == m.kindFilter {
						filtered = append(filtered, sec)
					}
				}
				displayed = filtered
			}
			if m.tagFilter != "" {
				var filtered []secret.Secret
				for _, sec := range displayed {
					if containsTagTUI(sec.Tags, m.tagFilter) {
						filtered = append(filtered, sec)
					}
				}
				displayed = filtered
			}
		}
		maxVisible := m.height - 9
		if maxVisible < 5 {
			maxVisible = 15
		}

		start := 0
		end := len(displayed)
		if len(displayed) > maxVisible {
			start = m.cursor - maxVisible/2
			if start < 0 {
				start = 0
			}
			end = start + maxVisible
			if end > len(displayed) {
				end = len(displayed)
				start = max(0, end-maxVisible)
			}
		}

		for i := start; i < end; i++ {
			sec := displayed[i]
			line := formatSecretLine(sec, i == m.cursor)
			if m.expiringMode {
				expiry := formatExpiryStatus(sec)
				if expiry != "" {
					line += "  " + dimStyle.Render(expiry)
				}
			}
			content += line + "\n"
		}
	}

	content += "\n" + m.listFooter()
	return lipgloss.NewStyle().PaddingLeft(2).Render(content)
}

// formatExpiryStatus returns a human-readable expiry string for a certificate secret.
func formatExpiryStatus(sec secret.Secret) string {
	if sec.Metadata == "" {
		return ""
	}
	var meta parse.Metadata
	if err := json.Unmarshal([]byte(sec.Metadata), &meta); err != nil {
		return ""
	}
	if meta.NotAfter == "" {
		return ""
	}
	if meta.IsExpired() {
		return "! EXPIRED"
	}
	days := meta.DaysUntilExpiry()
	if days <= 0 {
		return "! EXPIRED"
	}
	return fmt.Sprintf("~ %dd", days)
}

// formatSecretLine renders a single secret list item.
func formatSecretLine(sec secret.Secret, selected bool) string {
	kind := string(sec.Kind)
	if kind == "" {
		kind = "other"
	}

	name := sec.Name
	tags := ""
	if sec.Tags != "" {
		tags = dimStyle.Render("[" + sec.Tags + "]")
	}

	if selected {
		return selectedStyle.Render(fmt.Sprintf("▸ %s", name)) +
			"  " + dimStyle.Render(kind) +
			" " + tags
	}

	return fmt.Sprintf("  %s  %s  %s",
		name,
		dimStyle.Render(kind),
		tags,
	)
}

// listFooter renders the keybinding help bar for the list screen.
func (m model) listFooter() string {
	var parts string

	// Recent audit activity
	if len(m.auditEntries) > 0 {
		parts += dimStyle.Render("recent: ")
		for i, e := range m.auditEntries {
			if i > 0 {
				parts += dimStyle.Render(" · ")
			}
			action := e.Action
			if e.SecretName != "" {
				action += " " + e.SecretName
			}
			parts += dimStyle.Render(action)
		}
		parts += "\n"
	}

	parts += listFooterText
	if m.kindFilter != "" {
		parts += "\n" + dimStyle.Render("filter: "+m.kindFilter)
	}
	if m.tagFilter != "" {
		parts += "\n" + dimStyle.Render("tag: "+m.tagFilter)
	}
	if m.expiringMode {
		parts += "\n" + warnStyle.Render("expiring only")
	}
	return helpStyle.Render(parts)
}

// kindFilterCycle defines the order for cycling the kind filter in list.
var kindFilterCycle = []string{"", "certificate", "ssh_key", "api_key", "password", "note", "other"}

// cycleKindFilter advances the kind filter to the next value in the cycle.
func (m model) cycleKindFilter() model {
	for i, k := range kindFilterCycle {
		if m.kindFilter == k {
			next := (i + 1) % len(kindFilterCycle)
			m.kindFilter = kindFilterCycle[next]
			m.cursor = 0
			return m
		}
	}
	// Fallback: start at "certificate"
	m.kindFilter = "certificate"
	m.cursor = 0
	return m
}

// toggleExpiring switches between expiring-only and full list mode.
func (m model) toggleExpiring() (tea.Model, tea.Cmd) {
	if m.expiringMode {
		// Turn off — restore full list.
		m.expiringMode = false
		secrets, err := m.loadSecrets()
		if err != nil {
			m.err = fmt.Sprintf("List failed: %v", err)
			return m, nil
		}
		m.secrets = secrets
	} else {
		// Turn on — show expiring certs only.
		m.expiringMode = true
		all, err := m.loadSecrets()
		if err != nil {
			m.err = fmt.Sprintf("List failed: %v", err)
			return m, nil
		}
		var expiring []secret.Secret
		for _, s := range all {
			if s.Kind != secret.KindCertificate {
				continue
			}
			if s.Metadata != "" {
				var meta parse.Metadata
				if err := json.Unmarshal([]byte(s.Metadata), &meta); err == nil && meta.NotAfter != "" {
					if meta.DaysUntilExpiry() <= 30 {
						expiring = append(expiring, s)
					}
				}
			}
		}
		m.secrets = expiring
	}
	m.cursor = 0
	return m, nil
}

// collectTags returns all unique tags from the current secret list.
func (m model) collectTags() []string {
	tagSet := make(map[string]struct{})
	for _, sec := range m.secrets {
		if sec.Tags == "" {
			continue
		}
		for _, tag := range strings.Split(sec.Tags, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				tagSet[tag] = struct{}{}
			}
		}
	}
	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	// Sort for deterministic order
	sort.Strings(tags)
	return tags
}

// tagFilterCycle returns the cycle of tag filter values: "" → each unique tag → "".
func (m model) tagFilterCycle() []string {
	tags := m.collectTags()
	cycle := make([]string, 0, len(tags)+2)
	cycle = append(cycle, "")      // start with no filter
	cycle = append(cycle, tags...) // then each unique tag
	cycle = append(cycle, "")      // wrap back to no filter
	return cycle
}

// cycleTagFilter advances the tag filter to the next value in the cycle.
func (m model) cycleTagFilter() model {
	cycle := m.tagFilterCycle()
	if len(cycle) <= 2 {
		// No tags available — just reset
		m.tagFilter = ""
		m.cursor = 0
		return m
	}
	for i, t := range cycle {
		if m.tagFilter == t {
			next := (i + 1) % len(cycle)
			m.tagFilter = cycle[next]
			m.cursor = 0
			return m
		}
	}
	// Fallback: start with first tag
	if len(cycle) > 1 {
		m.tagFilter = cycle[1]
	} else {
		m.tagFilter = ""
	}
	m.cursor = 0
	return m
}

// containsTagTUI checks if a comma-separated tag string contains the given tag.
func containsTagTUI(tags, tag string) bool {
	if tags == "" || tag == "" {
		return false
	}
	n := len(tags)
	m := len(tag)
	for i := 0; i <= n-m; i++ {
		match := true
		for j := 0; j < m; j++ {
			if tags[i+j] != tag[j] {
				match = false
				break
			}
		}
		if match {
			leftOk := i == 0 || tags[i-1] == ','
			rightOk := i+m >= n || tags[i+m] == ','
			if leftOk && rightOk {
				return true
			}
		}
	}
	return false
}

// deleteSelected deletes the secret at the current cursor position.
func (m model) deleteSelected() (tea.Model, tea.Cmd) {
	if m.cursor < 0 || m.cursor >= len(m.secrets) {
		return m, nil
	}
	sec := m.secrets[m.cursor]
	lookup := sec.NameLookup
	if len(lookup) == 0 && sec.Name != "" {
		if m.key != nil {
			lookup = crypto.ComputeNameLookup(m.key, sec.Name)
		} else {
			lookup = []byte(sec.Name)
		}
	}
	if err := m.st.SoftDeleteByLookup(lookup); err != nil {
		m.err = fmt.Sprintf("Delete failed: %v", err)
		return m, nil
	}

	// Log audit entry
	_ = m.st.LogAction("secret_delete", sec.Name, "")
	entries, _ := m.st.GetAuditLog(3)
	m.auditEntries = entries

	// Refresh list
	secrets, err := m.loadSecrets()
	if err != nil {
		m.err = fmt.Sprintf("List failed: %v", err)
		return m, nil
	}
	m.secrets = secrets
	if m.cursor >= len(m.secrets) && len(m.secrets) > 0 {
		m.cursor = len(m.secrets) - 1
	}
	m.err = ""
	return m, nil
}
