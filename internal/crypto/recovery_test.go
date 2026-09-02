package crypto

import (
	"strings"
	"testing"
)

func TestEncodeMnemonic_InvalidLength_ReturnsError(t *testing.T) {
	// 31-byte key is invalid
	key31 := make([]byte, 31)
	_, err := encodeMnemonic(key31)
	if err == nil {
		t.Fatal("expected error for 31-byte key, got nil")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("expected error to mention 32 bytes, got: %v", err)
	}

	// 33-byte key is also invalid
	key33 := make([]byte, 33)
	_, err = encodeMnemonic(key33)
	if err == nil {
		t.Fatal("expected error for 33-byte key, got nil")
	}
}
