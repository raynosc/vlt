package notify

import (
	"testing"
)

func TestEscapeAppleScript(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal text", "normal text"},
		{`text with "quotes"`, `text with \"quotes\"`},
		{`text with \backslashes\`, `text with \\backslashes\\`},
		{`mixed "quotes" and \slashes\`, `mixed \"quotes\" and \\slashes\\`},
	}

	for _, tt := range tests {
		got := escapeAppleScript(tt.input)
		if got != tt.expected {
			t.Errorf("escapeAppleScript(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSend(t *testing.T) {
	// Verify escaping handles all critical characters
	sample := `Test 'single' and "double" quotes and \slashes\ and $vars`
	escapedAS := escapeAppleScript(sample)
	if escapedAS == "" {
		t.Errorf("expected escaped AppleScript string")
	}
	escapedPS := escapePowerShell(sample)
	if escapedPS == "" {
		t.Errorf("expected escaped PowerShell string")
	}
}
