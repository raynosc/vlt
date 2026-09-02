package crypto

import (
	"crypto/rand"
	"testing"
)

func TestValidatePINFormat(t *testing.T) {
	valid := []string{"00000000", "12345678", "99999999", "01020304"}
	for _, p := range valid {
		if err := ValidatePINFormat(p); err != nil {
			t.Errorf("expected valid PIN %q, got err: %v", p, err)
		}
	}

	invalid := []string{"", "1234", "1234567", "123456789", "1234abcd", "1234 567", "1234-567", "abcdefgh"}
	for _, p := range invalid {
		if err := ValidatePINFormat(p); err == nil {
			t.Errorf("expected invalid PIN for %q, got nil error", p)
		}
	}
}

func TestEngine_HashAndVerifyPIN(t *testing.T) {
	eng := NewEngine(nil)
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)

	pin := "87654321"
	hash, err := eng.HashPIN(pin, salt)
	if err != nil {
		t.Fatalf("HashPIN failed: %v", err)
	}
	if len(hash) != 32 {
		t.Errorf("expected 32-byte hash, got %d", len(hash))
	}

	if !eng.VerifyPIN(pin, salt, hash) {
		t.Errorf("expected VerifyPIN to succeed for correct PIN")
	}

	if eng.VerifyPIN("12345678", salt, hash) {
		t.Errorf("expected VerifyPIN to fail for wrong PIN")
	}

	if eng.VerifyPIN("invalid", salt, hash) {
		t.Errorf("expected VerifyPIN to fail for malformed PIN")
	}
}
