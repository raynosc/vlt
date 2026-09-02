package crypto

import (
	"testing"
)

// FuzzUnpackEnvelope tests that UnpackEnvelope handles any arbitrary byte slices without panicking.
func FuzzUnpackEnvelope(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("12345678901"))                    // 11 bytes (< NonceSize)
	f.Add([]byte("123456789012"))                   // exactly NonceSize
	f.Add([]byte("123456789012ciphertext_payload")) // Nonce + ciphertext
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		nonce, ciphertext, err := UnpackEnvelope(data)
		if len(data) < NonceSize {
			if err == nil {
				t.Errorf("expected error for data shorter than NonceSize, got nil")
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if len(nonce) != NonceSize {
				t.Errorf("expected nonce length %d, got %d", NonceSize, len(nonce))
			}
			if len(ciphertext) != len(data)-NonceSize {
				t.Errorf("expected ciphertext length %d, got %d", len(data)-NonceSize, len(ciphertext))
			}
		}
	})
}

// FuzzValidatePINFormat tests PIN validation against mutated strings.
func FuzzValidatePINFormat(f *testing.F) {
	f.Add("12345678")
	f.Add("00000000")
	f.Add("99999999")
	f.Add("1234567")
	f.Add("123456789")
	f.Add("abcdefgh")
	f.Add("1234 5678")
	f.Add("1234-5678")
	f.Add("")
	f.Add("\x00\x00\x00\x00\x00\x00\x00\x00")

	f.Fuzz(func(t *testing.T, pin string) {
		_ = ValidatePINFormat(pin)
	})
}

// FuzzMnemonicDecode tests decodeMnemonic robustness on mutated phrases.
func FuzzMnemonicDecode(f *testing.F) {
	f.Add("bonus assist area arctic barrel bird brisk audit almost aerobic base all cabin banner attack brass bullet bus awful afford base bamboo battle apple candy avoid ability answer between bread blood brisk beef butter ball beyond")
	f.Add("")
	f.Add("invalid words that are not in bip39 wordlist at all")
	f.Add("bonus assist area")
	f.Add("bonus assist area arctic barrel bird brisk audit almost aerobic base all cabin banner attack brass bullet bus awful afford base bamboo battle apple candy avoid ability answer between bread blood brisk beef butter ball invalidword")

	f.Fuzz(func(t *testing.T, phrase string) {
		_, _ = decodeMnemonic(phrase)
	})
}
