package crypto

import (
	"crypto/subtle"
	"fmt"
	"regexp"
)

var pinRegex = regexp.MustCompile(`^[0-9]{8}$`)

// ValidatePINFormat ensures the PIN is strictly 8 ASCII numeric digits.
func ValidatePINFormat(pin string) error {
	if !pinRegex.MatchString(pin) {
		return fmt.Errorf("PIN must be exactly 8 numeric digits (0-9)")
	}
	return nil
}

// HashPIN derives an Argon2id hash for an 8-digit PIN using the engine's parameters and a 16-byte salt.
func (e *Engine) HashPIN(pin string, salt []byte) ([]byte, error) {
	if err := ValidatePINFormat(pin); err != nil {
		return nil, err
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("salt must not be empty")
	}
	return e.DeriveKey([]byte(pin), salt)
}

// VerifyPIN verifies a candidate PIN against a salt and expected Argon2id hash in constant time.
func (e *Engine) VerifyPIN(pin string, salt, expectedHash []byte) bool {
	if err := ValidatePINFormat(pin); err != nil {
		return false
	}
	if len(salt) == 0 || len(expectedHash) == 0 {
		return false
	}
	derived, err := e.DeriveKey([]byte(pin), salt)
	if err != nil {
		return false
	}
	defer Zeroize(derived)

	return subtle.ConstantTimeCompare(derived, expectedHash) == 1
}
