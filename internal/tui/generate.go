package tui

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/raynosc/vlt/internal/crypto"
)

// generatePassword creates a cryptographically secure random password.
// Uses crypto/rand for uniform selection across the full character set.
// Length 24 by default, includes symbols.
func generatePassword(length int) ([]byte, error) {
	if length <= 0 {
		length = 24
	}

	password := make([]byte, length)
	for i := range password {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(crypto.DefaultPasswordCharset))))
		if err != nil {
			return nil, fmt.Errorf("rand.Int: %w", err)
		}
		password[i] = crypto.DefaultPasswordCharset[idx.Int64()]
	}

	return password, nil
}
