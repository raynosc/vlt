package cli

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
)

// Default password length when none is specified.
const defaultPasswordLength = 24

// Character sets for password generation.
const (
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	digitChars  = "0123456789"
	symbolChars = "!@#$%^&*()_+-=[]{}|;:',.<>?/~"
)

// generatePassword generates a cryptographically secure random password.
// If length is 0, uses defaultPasswordLength.
// If includeSymbols is false, excludes symbol characters.
//
// LOW-01: Guarantees at least one character from each active category
// by seeding required chars first, then filling randomly, then shuffling.
func generatePassword(length int, includeSymbols bool) ([]byte, error) {
	if length <= 0 {
		length = defaultPasswordLength
	}

	// Build the active character categories
	categories := []string{upperChars, lowerChars, digitChars}
	if includeSymbols {
		categories = append(categories, symbolChars)
	}

	// Ensure minimum length covers all categories
	if length < len(categories) {
		length = len(categories)
	}

	charset := upperChars + lowerChars + digitChars
	if includeSymbols {
		charset += symbolChars
	}

	password := make([]byte, length)

	// Seed one character from each required category
	for i, cat := range categories {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(cat))))
		if err != nil {
			return nil, fmt.Errorf("rand.Int: %w", err)
		}
		password[i] = cat[idx.Int64()]
	}

	// Fill the rest with random characters from the full charset
	for i := len(categories); i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return nil, fmt.Errorf("rand.Int: %w", err)
		}
		password[i] = charset[idx.Int64()]
	}

	// Fisher-Yates shuffle using crypto/rand to avoid predictable positions
	for i := length - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, fmt.Errorf("rand.Int: %w", err)
		}
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}

	return password, nil
}

func newGenerateCmd() *cobra.Command {
	var length int
	var noSymbols bool
	var copyToClip bool

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a secure random password",
		Long: `Generate a cryptographically secure random password using crypto/rand.

Outputs only the password to stdout (pipeable).
Use --copy to copy to clipboard instead of printing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pw, err := generatePassword(length, !noSymbols)
			if err != nil {
				return fmt.Errorf("generate: %w", err)
			}
			// MED-02: Use crypto.Zeroize instead of local zeroizeBytes
			// to prevent compiler dead-store elimination.
			defer crypto.Zeroize(pw)

			if copyToClip {
				if err := clipboard.WriteAll(string(pw)); err != nil {
					return fmt.Errorf("clipboard: %w", err)
				}
				StartClipboardAutoClear(string(pw))
				fmt.Fprintln(os.Stderr, "Password copied to clipboard.")
				return nil
			}

			fmt.Print(string(pw))
			return nil
		},
	}

	cmd.Flags().IntVarP(&length, "length", "l", defaultPasswordLength, "password length (default: 24)")
	cmd.Flags().BoolVar(&noSymbols, "no-symbols", false, "exclude symbols from generated password")
	cmd.Flags().BoolVarP(&copyToClip, "copy", "c", false, "copy to clipboard instead of printing")

	return cmd
}
