//go:build darwin

package gui

import (
	"testing"
)

func TestParseCarbonHotkey_Valid(t *testing.T) {
	tests := []struct {
		input       string
		wantKeyCode uint32
		wantMods    uint32
	}{
		{
			input:       "shift+cmd+space",
			wantKeyCode: 49,
			wantMods:    carbonCmdKey | carbonShiftKey,
		},
		{
			input:       "shift+cmd+v",
			wantKeyCode: 9,
			wantMods:    carbonCmdKey | carbonShiftKey,
		},
		{
			input:       "ctrl+alt+k",
			wantKeyCode: 40,
			wantMods:    carbonControlKey | carbonOptionKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			keyCode, mods, err := parseCarbonHotkey(tt.input)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if keyCode != tt.wantKeyCode {
				t.Errorf("expected keyCode %d, got %d", tt.wantKeyCode, keyCode)
			}
			if mods != tt.wantMods {
				t.Errorf("expected mods 0x%X, got 0x%X", tt.wantMods, mods)
			}
		})
	}
}

func TestParseCarbonHotkey_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"   ",
		"shift+cmd",
		"unknownkey",
	}

	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			_, _, err := parseCarbonHotkey(s)
			if err == nil {
				t.Errorf("expected error for %q, got nil", s)
			}
		})
	}
}
