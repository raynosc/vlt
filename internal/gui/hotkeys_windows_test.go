//go:build windows

package gui

import (
	"testing"
)

func TestParseWindowsHotkey_Valid(t *testing.T) {
	tests := []struct {
		input    string
		wantVK   uint32
		wantMods uint32
	}{
		{
			input:    "shift+ctrl+space",
			wantVK:   0x20,
			wantMods: modControl | modShift,
		},
		{
			input:    "shift+cmd+space", // "cmd" mapped to Control on Windows
			wantVK:   0x20,
			wantMods: modControl | modShift,
		},
		{
			input:    "shift+ctrl+v",
			wantVK:   0x56,
			wantMods: modControl | modShift,
		},
		{
			input:    "ctrl+alt+k",
			wantVK:   0x4B,
			wantMods: modControl | modAlt,
		},
		{
			input:    "win+v",
			wantVK:   0x56,
			wantMods: modWin,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			vk, mods, err := parseWindowsHotkey(tt.input)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if vk != tt.wantVK {
				t.Errorf("expected VK 0x%X, got 0x%X", tt.wantVK, vk)
			}
			if mods != tt.wantMods {
				t.Errorf("expected mods 0x%X, got 0x%X", tt.wantMods, mods)
			}
		})
	}
}

func TestParseWindowsHotkey_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"   ",
		"shift+ctrl",
		"unknownkey",
	}

	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			_, _, err := parseWindowsHotkey(s)
			if err == nil {
				t.Errorf("expected error for %q, got nil", s)
			}
		})
	}
}
