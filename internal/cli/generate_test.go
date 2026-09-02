package cli

import (
	"strings"
	"testing"
)

// ── Password Generator Tests ──

func TestGenerate_Length(t *testing.T) {
	pw, err := generatePassword(24, true)
	if err != nil {
		t.Fatalf("generatePassword failed: %v", err)
	}
	if len(pw) != 24 {
		t.Errorf("expected length 24, got %d", len(pw))
	}
}

func TestGenerate_DefaultLength(t *testing.T) {
	pw, err := generatePassword(0, true)
	if err != nil {
		t.Fatalf("generatePassword failed: %v", err)
	}
	if len(pw) != 24 {
		t.Errorf("expected default length 24, got %d", len(pw))
	}
}

func TestGenerate_NoSymbols(t *testing.T) {
	pw, err := generatePassword(32, false)
	if err != nil {
		t.Fatalf("generatePassword failed: %v", err)
	}
	if len(pw) != 32 {
		t.Errorf("expected length 32, got %d", len(pw))
	}

	// Verify no symbols present
	symbols := "!@#$%^&*()_+-=[]{}|;:',.<>?/~"
	for _, ch := range string(pw) {
		if strings.ContainsRune(symbols, ch) {
			t.Errorf("found symbol %c in no-symbol password: %s", ch, pw)
		}
	}
}

func TestGenerate_Charset(t *testing.T) {
	pw, err := generatePassword(100, true)
	if err != nil {
		t.Fatalf("generatePassword failed: %v", err)
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSymbol := false

	for _, ch := range string(pw) {
		switch {
		case 'A' <= ch && ch <= 'Z':
			hasUpper = true
		case 'a' <= ch && ch <= 'z':
			hasLower = true
		case '0' <= ch && ch <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	if !hasUpper {
		t.Error("expected at least one uppercase letter")
	}
	if !hasLower {
		t.Error("expected at least one lowercase letter")
	}
	if !hasDigit {
		t.Error("expected at least one digit")
	}
	if !hasSymbol {
		t.Error("expected at least one symbol")
	}
}

func TestGenerate_Entropy(t *testing.T) {
	// Generate multiple passwords and verify they're all different
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pw, err := generatePassword(16, true)
		if err != nil {
			t.Fatalf("generatePassword failed: %v", err)
		}
		if seen[string(pw)] {
			t.Error("duplicate password generated")
		}
		seen[string(pw)] = true
	}
}

func TestGenerate_LengthBounds(t *testing.T) {
	// With includeSymbols=true, minimum is 4 (one char per category).
	// Requesting length 1 should auto-expand to the category count.
	pw, err := generatePassword(1, true)
	if err != nil {
		t.Fatalf("generatePassword(1) failed: %v", err)
	}
	if len(pw) != 4 {
		t.Errorf("expected minimum length 4 (one per category), got %d", len(pw))
	}

	// Without symbols, minimum is 3 (upper, lower, digit).
	pw, err = generatePassword(1, false)
	if err != nil {
		t.Fatalf("generatePassword(1, false) failed: %v", err)
	}
	if len(pw) != 3 {
		t.Errorf("expected minimum length 3 (one per category), got %d", len(pw))
	}

	// Test larger length
	pw, err = generatePassword(128, true)
	if err != nil {
		t.Fatalf("generatePassword(128) failed: %v", err)
	}
	if len(pw) != 128 {
		t.Errorf("expected length 128, got %d", len(pw))
	}
}

func TestGenerate_UniformDistribution(t *testing.T) {
	// Chi-squared-like test: generate a large password and verify
	// all character classes appear with reasonable frequency
	pw, err := generatePassword(1000, true)
	if err != nil {
		t.Fatalf("generatePassword failed: %v", err)
	}

	counts := make(map[byte]int)
	for i := 0; i < len(pw); i++ {
		counts[pw[i]]++
	}

	// With 1000 chars and ~72 possible symbols, average is ~14 each
	// Just check no single char dominates (> 50%)

	// With 1000 chars and ~72 possible symbols, average is ~14 each
	// Just check no single char dominates (> 50%)
	for ch, count := range counts {
		if float64(count)/float64(len(pw)) > 0.5 {
			t.Errorf("character %c appears %d/%d times (%.1f%%) - possible bias", ch, count, len(pw), float64(count)/float64(len(pw))*100)
		}
	}
}
