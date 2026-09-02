package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/raynosc/vlt/internal/secret"
)

// updateSearch handles messages in the search state.
func (m model) updateSearch(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		// Exit search, return to full list.
		m.state = stateList
		m.searchInput.Blur()
		m.searchInput.SetValue("")
		m.searchQuery = ""
		m.searchResults = nil
		m.err = ""
		return m, nil

	case tea.KeyEnter:
		if len(m.searchResults) == 0 {
			return m, nil
		}
		// Select the highlighted search result.
		return m.selectSecret(m.searchResults[m.cursor])

	case tea.KeyUp, tea.KeyCtrlK:
		if m.cursor > 0 {
			m.cursor--
		}
		return m, nil

	case tea.KeyDown, tea.KeyCtrlJ:
		if len(m.searchResults) > 0 && m.cursor < len(m.searchResults)-1 {
			m.cursor++
		}
		return m, nil
	}

	// Note: no KeyRunes handler — all typed characters are forwarded
	// to the text input below.

	// Forward to search text input and run filter.
	var cmd tea.Cmd
	m.searchInput, cmd = m.searchInput.Update(msg)
	m.searchQuery = m.searchInput.Value()
	m.cursor = 0

	// Run filter on the full secret list.
	m.searchResults = runFilter(m.secrets, m.searchQuery)

	return m, cmd
}

// viewSearch renders the search overlay on top of the list view.
func (m model) viewSearch() string {
	var content string

	// Search bar
	content += fmt.Sprintf("\n  %s\n\n", lipgloss.NewStyle().Bold(true).Render("Search Secrets"))
	content += "  " + m.searchInput.View() + "\n\n"

	if m.err != "" {
		content += errorStyle.Render("! "+m.err) + "\n\n"
	}

	// Results
	list := m.searchResults
	if m.searchQuery == "" {
		list = m.secrets
	}

	if len(list) == 0 {
		if m.searchQuery != "" {
			content += dimStyle.Render(fmt.Sprintf("  No results for %q", m.searchQuery)) + "\n"
		} else {
			content += dimStyle.Render("  No secrets found.") + "\n"
		}
	} else {
		content += fmt.Sprintf("  %s\n\n", dimStyle.Render(fmt.Sprintf("%d results", len(list))))

		maxVisible := m.height - 9
		if maxVisible < 5 {
			maxVisible = 15
		}

		start := 0
		end := len(list)
		if len(list) > maxVisible {
			start = m.cursor - maxVisible/2
			if start < 0 {
				start = 0
			}
			end = start + maxVisible
			if end > len(list) {
				end = len(list)
				start = max(0, end-maxVisible)
			}
		}

		for i := start; i < end; i++ {
			sec := list[i]
			line := formatSecretLine(sec, i == m.cursor)
			content += line + "\n"
		}
	}

	content += "\n" + searchFooter()
	return lipgloss.NewStyle().PaddingLeft(2).Render(content)
}

// runFilter filters secrets by name and tags matching the query.
func runFilter(secrets []secret.Secret, query string) []secret.Secret {
	if query == "" {
		return nil
	}

	lowerQuery := strings.ToLower(query)
	var results []secret.Secret

	for _, sec := range secrets {
		if strings.Contains(strings.ToLower(sec.Name), lowerQuery) {
			results = append(results, sec)
			continue
		}
		if strings.Contains(strings.ToLower(sec.Tags), lowerQuery) {
			results = append(results, sec)
		}
	}

	return results
}

// searchFooter renders the keybinding help bar for the search screen.
func searchFooter() string {
	return helpStyle.Render(searchFooterText)
}
