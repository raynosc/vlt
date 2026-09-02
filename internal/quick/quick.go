// Package quick provides a Bubble Tea TUI for quickly searching and copying secrets.
//
// It connects to the vlt daemon, retrieves the secret list, presents a compact
// search-as-you-type interface, and copies the selected secret value to the
// clipboard.
//
// Architecture:
//   - Model is created with a pre-loaded list of secrets and an onSelect callback
//   - Daemon connection and unlocking happens before the model is created
//   - onSelect encapsulates getting the secret value and copying to clipboard
//   - filterSecrets is a pure function for testability
package quick

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/raynosc/vlt/internal/theme"
)

// ── Types ──

// SecretInfo holds minimal information about a secret for display and selection.
type SecretInfo struct {
	Name string
	Kind string
}

// OnSelectFn is called when the user presses Enter on a secret.
// It receives the secret name, should get the value and copy to clipboard.
type OnSelectFn func(name string) error

// copiedMsg is sent after a 1s delay to trigger auto-close after copy.
type copiedMsg struct{}

// inactivityTickMsg is sent periodically to check for inactivity timeout.
type inactivityTickMsg struct{}

// ── Styles ──

var (
	itemStyle = lipgloss.NewStyle().
			PaddingLeft(2)

	selectedItemStyle = lipgloss.NewStyle().
				PaddingLeft(2).
				Foreground(lipgloss.Color(theme.HexPurple)).
				Bold(true)

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.HexDimLight))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.HexDim))

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.HexSuccess)).
			Italic(true)

	errStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.HexError)).
			Bold(true)

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(1, 2)
)

// ── Model ──

// Model is a Bubble Tea model for the quick search window.
// Zero value is not usable — use NewModel() to create an instance.
type Model struct {
	// All secrets from the daemon (unfiltered)
	allSecrets []SecretInfo

	// Filtered results based on current search query
	results []SecretInfo

	// Current search query string
	query string

	// Cursor position in the results list
	cursor int

	// Search text input component
	input textinput.Model

	// Callback to execute when a secret is selected (Enter)
	onSelect OnSelectFn

	// Status message shown after successful copy
	status string

	// Last error encountered
	err error

	// Terminal dimensions
	width  int
	height int

	// Inactivity timeout duration
	timeout time.Duration

	// Timestamp of the last user interaction
	lastActivity time.Time

	// quitting is set when the model should exit
	quitting bool

	// vaultName is the active vault name displayed in the search header
	vaultName string
}

// NewModel creates a Model with the given secrets and onSelect callback.
// The model starts with all secrets visible and an empty search query.
func NewModel(secrets []SecretInfo, onSelect OnSelectFn) Model {
	return NewModelWithVault(secrets, onSelect, "")
}

// NewModelWithVault creates a Model with vault name branding.
func NewModelWithVault(secrets []SecretInfo, onSelect OnSelectFn, vaultName string) Model {
	return NewModelWithVaultAndTimeout(secrets, onSelect, vaultName, 0)
}

// NewModelWithVaultAndTimeout creates a Model with vault name branding and inactivity timeout.
func NewModelWithVaultAndTimeout(secrets []SecretInfo, onSelect OnSelectFn, vaultName string, timeoutMinutes int) Model {
	if secrets == nil {
		secrets = []SecretInfo{}
	}

	ti := textinput.New()
	ti.Placeholder = "Search secrets..."
	ti.CharLimit = 100
	ti.Focus()

	// Start with all secrets visible
	results := make([]SecretInfo, len(secrets))
	copy(results, secrets)

	var timeout time.Duration
	if timeoutMinutes > 0 {
		timeout = time.Duration(timeoutMinutes) * time.Minute
	}

	return Model{
		allSecrets:   secrets,
		results:      results,
		query:        "",
		cursor:       0,
		input:        ti,
		onSelect:     onSelect,
		vaultName:    vaultName,
		timeout:      timeout,
		lastActivity: time.Now(),
		width:        60,
		height:       20,
	}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	var cmds []tea.Cmd
	cmds = append(cmds, textinput.Blink)
	if m.timeout > 0 {
		cmds = append(cmds, m.startInactivityTicker())
	}
	return tea.Batch(cmds...)
}

// startInactivityTicker returns a command that ticks periodically to check inactivity.
func (m Model) startInactivityTicker() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return inactivityTickMsg{}
	})
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case copiedMsg:
		m.quitting = true
		return m, tea.Quit

	case inactivityTickMsg:
		if m.timeout > 0 && time.Since(m.lastActivity) >= m.timeout {
			m.quitting = true
			return m, tea.Quit
		}
		if m.timeout > 0 {
			return m, m.startInactivityTicker()
		}
		return m, nil

	case tea.KeyMsg:
		m.lastActivity = time.Now()

		// Handle navigation and action keys BEFORE forwarding to input
		// so they don't get swallowed by the text input.
		switch msg.Type {
		case tea.KeyEsc, tea.KeyCtrlC:
			m.quitting = true
			return m, tea.Quit

		case tea.KeyEnter:
			return m.handleEnter()

		case tea.KeyUp, tea.KeyCtrlK:
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil

		case tea.KeyDown, tea.KeyCtrlJ:
			if len(m.results) > 0 && m.cursor < len(m.results)-1 {
				m.cursor++
			}
			return m, nil
		}

		// All other keys (including KeyRunes) are forwarded to the
		// text input. Navigation uses arrow keys and Ctrl+J/Ctrl+K.

		// Forward to search text input
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		m.query = m.input.Value()
		m.cursor = 0
		m.results = filterSecrets(m.allSecrets, m.query)
		return m, cmd
	}

	return m, nil
}

// handleEnter is called when the user presses Enter in the search state.
// It invokes the onSelect callback and transitions to the Copied! state.
func (m Model) handleEnter() (Model, tea.Cmd) {
	if len(m.results) == 0 {
		return m, nil
	}

	selected := m.results[m.cursor].Name
	if err := m.onSelect(selected); err != nil {
		m.err = err
		return m, nil
	}

	m.status = "Copied!"
	// Auto-close after 1 second
	return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return copiedMsg{}
	})
}

// View implements tea.Model.
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var content string

	// Search bar with prompt and optional vault badge
	searchPrompt := dimStyle.Render("🔍 ")
	headerLine := searchPrompt + m.input.View()
	if m.vaultName != "" {
		badge := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.HexPurple)).Render(fmt.Sprintf("[%s]", m.vaultName))
		headerLine += "  " + badge
	}
	content += headerLine + "\n"

	// Divider
	content += dimStyle.Render(strings.Repeat("─", max(40, m.width-4))) + "\n"

	// Results
	if len(m.results) == 0 {
		if m.query != "" {
			content += dimStyle.Render(fmt.Sprintf("  No results for %q", m.query)) + "\n"
		} else {
			content += dimStyle.Render("  No secrets found.") + "\n"
		}
	} else {
		maxVisible := m.height - 7
		if maxVisible < 5 {
			maxVisible = 10
		}
		if maxVisible > 20 {
			maxVisible = 20
		}

		start := 0
		end := len(m.results)
		if len(m.results) > maxVisible {
			start = m.cursor - maxVisible/2
			if start < 0 {
				start = 0
			}
			end = start + maxVisible
			if end > len(m.results) {
				end = len(m.results)
				start = max(0, end-maxVisible)
			}
		}

		for i := start; i < end; i++ {
			line := formatItem(m.results[i], i == m.cursor)
			content += line + "\n"
		}
	}

	// Status or error message
	if m.err != nil {
		content += "\n" + errStyle.Render("! "+m.err.Error())
	} else if m.status != "" {
		content += "\n" + statusStyle.Render("✓ "+m.status)
	}

	// Footer help
	content += "\n" + helpStyle.Render("type to search · enter: copy · esc: cancel · ↑/↓ navigate · Ctrl+J/K")

	// Wrap in a bordered box
	return borderStyle.Render(content)
}

// ── Pure functions ──

// filterSecrets filters secrets by name (case-insensitive substring match).
// Returns a new slice — does not modify the input.
// Returns all secrets if query is empty.
func filterSecrets(secrets []SecretInfo, query string) []SecretInfo {
	if secrets == nil {
		return nil
	}
	if query == "" {
		result := make([]SecretInfo, len(secrets))
		copy(result, secrets)
		return result
	}

	lowerQuery := strings.ToLower(query)
	var results []SecretInfo
	for _, s := range secrets {
		if strings.Contains(strings.ToLower(s.Name), lowerQuery) {
			results = append(results, s)
		}
	}
	return results
}

// formatItem renders a single secret list item with optional selection indicator.
func formatItem(s SecretInfo, selected bool) string {
	kind := s.Kind
	if kind == "" {
		kind = "other"
	}

	name := s.Name
	kindLabel := dimStyle.Render(kind)

	if selected {
		return selectedItemStyle.Render("▸ "+name) + "  " + kindLabel
	}
	return itemStyle.Render("  "+name) + "  " + kindLabel
}

// Copied returns true if a secret was successfully copied to clipboard.
func (m Model) Copied() bool {
	return m.status == "Copied!"
}

// max returns the maximum of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
