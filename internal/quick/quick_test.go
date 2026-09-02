package quick

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// ── Fixtures ──

var testSecrets = []SecretInfo{
	{Name: "GitHub Token", Kind: "api_key"},
	{Name: "AWS Access Key", Kind: "api_key"},
	{Name: "Stripe API Key", Kind: "api_key"},
	{Name: "MyPassword", Kind: "password"},
	{Name: "dev.example.com", Kind: "password"},
}

// cast is a helper to type-assert tea.Model to Model.
func cast(m tea.Model) Model {
	return m.(Model)
}

// ── NewModel ──

func TestNewModel_initialState(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })

	if len(m.allSecrets) != 5 {
		t.Errorf("expected 5 secrets, got %d", len(m.allSecrets))
	}
	if len(m.results) != 5 {
		t.Errorf("expected 5 results (no filter), got %d", len(m.results))
	}
	if m.cursor != 0 {
		t.Errorf("expected cursor 0, got %d", m.cursor)
	}
	if m.quitting {
		t.Error("expected not quitting initially")
	}
	if m.status != "" {
		t.Errorf("expected empty status, got %q", m.status)
	}
	if m.err != nil {
		t.Errorf("expected nil err, got %v", m.err)
	}
	if m.query != "" {
		t.Errorf("expected empty query, got %q", m.query)
	}
}

func TestNewModel_emptySecrets(t *testing.T) {
	m := NewModel(nil, func(string) error { return nil })
	if len(m.results) != 0 {
		t.Errorf("expected 0 results for nil secrets, got %d", len(m.results))
	}
	if m.cursor != 0 {
		t.Errorf("expected cursor 0, got %d", m.cursor)
	}
}

// ── filterSecrets (pure function) ──

func TestFilterSecrets_emptyQuery_returnsAll(t *testing.T) {
	results := filterSecrets(testSecrets, "")
	if len(results) != 5 {
		t.Errorf("expected all 5 secrets, got %d", len(results))
	}
}

func TestFilterSecrets_matchByName(t *testing.T) {
	results := filterSecrets(testSecrets, "github")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Name != "GitHub Token" {
		t.Errorf("expected 'GitHub Token', got %q", results[0].Name)
	}
}

func TestFilterSecrets_caseInsensitive(t *testing.T) {
	results := filterSecrets(testSecrets, "STRIPE")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Name != "Stripe API Key" {
		t.Errorf("expected 'Stripe API Key', got %q", results[0].Name)
	}
}

func TestFilterSecrets_multipleMatches(t *testing.T) {
	results := filterSecrets(testSecrets, "key")
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	expected := []string{"AWS Access Key", "Stripe API Key"}
	for i, r := range results {
		if r.Name != expected[i] {
			t.Errorf("result[%d] expected %q, got %q", i, expected[i], r.Name)
		}
	}
}

func TestFilterSecrets_noMatch(t *testing.T) {
	results := filterSecrets(testSecrets, "zzzzznotfound")
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestFilterSecrets_partialMatch(t *testing.T) {
	results := filterSecrets(testSecrets, "pass")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Name != "MyPassword" {
		t.Errorf("expected 'MyPassword', got %q", results[0].Name)
	}
}

func TestFilterSecrets_nilInput(t *testing.T) {
	results := filterSecrets(nil, "test")
	if len(results) != 0 {
		t.Errorf("expected 0 results for nil input, got %d", len(results))
	}
}

// ── Update: KeyEnter ──

func TestUpdate_Enter_callsOnSelect(t *testing.T) {
	var calledWith string
	m := NewModel(testSecrets, func(name string) error {
		calledWith = name
		return nil
	})

	// Move cursor down to "AWS Access Key"
	for i := 0; i < 1; i++ {
		rm, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = cast(rm)
	}

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	rm := cast(result)
	if calledWith != "AWS Access Key" {
		t.Errorf("expected onSelect called with 'AWS Access Key', got %q", calledWith)
	}
	if rm.status != "Copied!" {
		t.Errorf("expected status 'Copied!', got %q", rm.status)
	}
}

func TestUpdate_Enter_emptyResults_doesNothing(t *testing.T) {
	var called bool
	m := NewModel(testSecrets, func(name string) error {
		called = true
		return nil
	})

	// Type something that matches nothing, then update manually
	m.query = "zzzzz"
	m.results = filterSecrets(m.allSecrets, "zzzzz")
	m.input.SetValue("zzzzz")

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	rm := cast(result)
	if called {
		t.Error("onSelect should NOT be called with empty results")
	}
	if rm.status != "" {
		t.Errorf("expected empty status, got %q", rm.status)
	}
}

// ── Update: KeyEsc ──

func TestUpdate_Esc_quits(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})

	rm := cast(result)
	if !rm.quitting {
		t.Error("expected quitting = true after Esc")
	}
}

// ── Update: Arrow keys ──

func TestUpdate_arrowDown_movesCursor(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	rm := cast(result)
	if rm.cursor != 1 {
		t.Errorf("expected cursor 1 after KeyDown, got %d", rm.cursor)
	}
}

func TestUpdate_arrowDown_atBottom_stays(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	for i := 0; i < 10; i++ {
		r, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = cast(r)
	}
	if m.cursor != 4 {
		t.Errorf("expected cursor clamped to 4, got %d", m.cursor)
	}
}

func TestUpdate_arrowUp_movesCursor(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	r1, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = cast(r1)
	r2, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = cast(r2)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	rm := cast(result)
	if rm.cursor != 1 {
		t.Errorf("expected cursor 1 after KeyUp from 2, got %d", rm.cursor)
	}
}

func TestUpdate_arrowUp_atTop_stays(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	rm := cast(result)
	if rm.cursor != 0 {
		t.Errorf("expected cursor 0 (clamped at top), got %d", rm.cursor)
	}
}

func TestUpdate_ctrlJ_movesDown(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlJ})
	rm := cast(result)
	if rm.cursor != 1 {
		t.Errorf("expected cursor 1 after Ctrl+J, got %d", rm.cursor)
	}
}

func TestUpdate_ctrlK_movesUp(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	r1, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = cast(r1)
	r2, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = cast(r2)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlK})
	rm := cast(result)
	if rm.cursor != 1 {
		t.Errorf("expected cursor 1 after Ctrl+K, got %d", rm.cursor)
	}
}

// ── Update: Typing filters results ──

func TestUpdate_typing_filtersResults(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("aws")})
	rm := cast(result)

	if rm.query != "aws" {
		t.Errorf("expected query 'aws', got %q", rm.query)
	}
	if len(rm.results) != 1 {
		t.Fatalf("expected 1 result after typing 'aws', got %d", len(rm.results))
	}
	if rm.results[0].Name != "AWS Access Key" {
		t.Errorf("expected 'AWS Access Key', got %q", rm.results[0].Name)
	}
	if rm.cursor != 0 {
		t.Errorf("expected cursor reset to 0 after filter, got %d", rm.cursor)
	}
}

func TestUpdate_typing_resetsCursor(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })

	// Move down to index 2
	for i := 0; i < 2; i++ {
		r, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = cast(r)
	}
	if m.cursor != 2 {
		t.Fatalf("expected cursor 2, got %d", m.cursor)
	}

	// Type to filter
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("key")})
	rm := cast(result)
	if rm.cursor != 0 {
		t.Errorf("expected cursor reset to 0 after filter, got %d", rm.cursor)
	}
}

// ── Update: OnSelect error ──

func TestUpdate_Enter_onSelectError_showsError(t *testing.T) {
	expectedErr := errors.New("daemon error")
	m := NewModel(testSecrets, func(name string) error {
		return expectedErr
	})

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	rm := cast(result)
	if rm.err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, rm.err)
	}
}

// ── View ──

func TestView_containsResults(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	view := m.View()

	if !strings.Contains(view, "GitHub Token") {
		t.Error("expected view to contain 'GitHub Token'")
	}
	if !strings.Contains(view, "AWS Access Key") {
		t.Error("expected view to contain 'AWS Access Key'")
	}
	if !strings.Contains(view, "Stripe API Key") {
		t.Error("expected view to contain 'Stripe API Key'")
	}
}

func TestView_emptySearch_showsEmptyMessage(t *testing.T) {
	m := NewModel(nil, func(string) error { return nil })
	view := m.View()

	if !strings.Contains(view, "No secrets") {
		t.Errorf("expected empty message in view, got:\n%s", view)
	}
}

func TestView_copiedStatus(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	m.status = "Copied!"
	view := m.View()

	if !strings.Contains(view, "Copied!") {
		t.Errorf("expected 'Copied!' in view, got:\n%s", view)
	}
}

func TestView_selectedItemHighlighted(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	view := m.View()

	// The selected item (first) should have "▸" indicator
	if !strings.Contains(view, "▸") {
		t.Errorf("expected current selection indicator (▸) in view, got:\n%s", view)
	}
}

// ── copiedMsg ──

func TestUpdate_copiedMsg_setsQuitting(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	result, _ := m.Update(copiedMsg{})

	rm := cast(result)
	if !rm.quitting {
		t.Error("expected quitting = true after copiedMsg")
	}
}

// ── Init ──

func TestInit_returnsBlinkCmd(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	cmd := m.Init()
	if cmd == nil {
		t.Error("expected non-nil cmd from Init (textinput.Blink)")
	}
}

// ── Window resize ──

func TestUpdate_windowResize_setsDimensions(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	result, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 20})
	rm := cast(result)
	if rm.width != 80 {
		t.Errorf("expected width 80, got %d", rm.width)
	}
	if rm.height != 20 {
		t.Errorf("expected height 20, got %d", rm.height)
	}
}

// ── Tick after copy ──

func TestUpdate_enter_returnsTickCmd(t *testing.T) {
	m := NewModel(testSecrets, func(name string) error { return nil })

	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	rm := cast(result)

	if rm.status != "Copied!" {
		t.Errorf("expected 'Copied!' after enter, got %q", rm.status)
	}
	if cmd == nil {
		t.Error("expected non-nil Tick cmd after Enter, got nil")
	}
}

// ── No results view when filtered ──

func TestView_noResultsMessageWithQuery(t *testing.T) {
	m := NewModel(testSecrets, func(string) error { return nil })
	m.query = "zzzzz"
	m.results = nil
	view := m.View()

	if !strings.Contains(view, "No results") {
		t.Errorf("expected 'No results' message in view, got:\n%s", view)
	}
}

func TestView_paginationClampsResults(t *testing.T) {
	// Create 50 dummy secrets
	var manySecrets []SecretInfo
	for i := 0; i < 50; i++ {
		manySecrets = append(manySecrets, SecretInfo{
			Name: "Secret " + string(rune('A'+(i%26))) + "-" + string(rune('0'+(i%10))),
			Kind: "password",
		})
	}

	m := NewModel(manySecrets, func(string) error { return nil })
	m.height = 20 // maxVisible = 20 - 7 = 13
	view := m.View()

	// Ensure the search prompt and divider are always present
	if !strings.Contains(view, "🔍") {
		t.Errorf("expected search prompt in view, got:\n%s", view)
	}
	if !strings.Contains(view, "type to search") {
		t.Errorf("expected footer help in view, got:\n%s", view)
	}

	// Count rendered lines
	lines := strings.Split(view, "\n")
	// The total height of the rendered box should be well bounded
	if len(lines) > 25 {
		t.Errorf("expected view lines <= 25, got %d", len(lines))
	}
}

func TestUpdate_inactivityTimeout(t *testing.T) {
	m := NewModelWithVaultAndTimeout(testSecrets, func(string) error { return nil }, "vault", 1)
	if m.timeout != 1*time.Minute {
		t.Errorf("expected 1m timeout, got %v", m.timeout)
	}

	// Fast forward lastActivity by 2 minutes
	m.lastActivity = time.Now().Add(-2 * time.Minute)

	// Inactivity tick should trigger quit
	result, cmd := m.Update(inactivityTickMsg{})
	rm := cast(result)
	if !rm.quitting {
		t.Error("expected model quitting after inactivity timeout")
	}
	if cmd == nil {
		t.Error("expected tea.Quit cmd, got nil")
	}
}
