// Package otp provides pure-Go OTP code generation (TOTP, HOTP, Steam).
//
// All functions are pure domain logic — zero I/O, zero project dependencies
// beyond the Go standard library (crypto/hmac, crypto/sha*, encoding/base32).
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

// SteamAlphabet is the custom character set used by Steam Guard codes.
const SteamAlphabet = "23456789BCDFGHJKMNPQRTVWXY"

// defaultPeriod is the standard TOTP time step in seconds.
const defaultPeriod int64 = 30

const (
	minDigits = 5
	maxDigits = 8
)

// GenerateHOTP generates an HMAC-based one-time password per RFC 4226.
// secret is a base32-encoded string.
func GenerateHOTP(secret string, counter uint64, digits int) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", fmt.Errorf("invalid secret encoding: %w", err)
	}
	if len(key) == 0 {
		return "", fmt.Errorf("empty secret")
	}
	if digits < minDigits || digits > maxDigits {
		return "", fmt.Errorf("digits must be between %d and %d, got %d", minDigits, maxDigits, digits)
	}

	mac := hmac.New(sha1.New, key)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac.Write(counterBytes[:])
	hs := mac.Sum(nil)

	return truncate(hs, digits), nil
}

// GenerateTOTP generates a time-based one-time password per RFC 6238.
// secret is a base32-encoded string. algo defaults to SHA1; supports SHA256, SHA512.
// The period is always 30 seconds — callers adjust time for custom periods.
func GenerateTOTP(secret string, t time.Time, digits int, algo string) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", fmt.Errorf("invalid secret encoding: %w", err)
	}
	if len(key) == 0 {
		return "", fmt.Errorf("empty secret")
	}
	if digits < minDigits || digits > maxDigits {
		return "", fmt.Errorf("digits must be between %d and %d, got %d", minDigits, maxDigits, digits)
	}

	counter := uint64(t.Unix() / defaultPeriod)

	h := hashForAlgo(algo)
	if h == nil {
		return "", fmt.Errorf("unsupported algorithm: %s", algo)
	}

	mac := hmac.New(h, key)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac.Write(counterBytes[:])
	hs := mac.Sum(nil)

	return truncate(hs, digits), nil
}

// truncate applies the HOTP dynamic truncation (RFC 4226 §5.3) and reduces
// to the requested number of decimal digits.
func truncate(hs []byte, digits int) string {
	if len(hs) == 0 {
		// Guard against empty/nil slice — cannot read offset byte.
		return fmt.Sprintf("%0*d", digits, 0)
	}
	if len(hs) < int(hs[len(hs)-1]&0x0F)+4 {
		// This cannot happen with SHA1/256/512 but guards future algorithm additions.
		return fmt.Sprintf("%0*d", digits, 0)
	}
	offset := hs[len(hs)-1] & 0x0F
	binaryCode := (int32(hs[offset]&0x7F) << 24) |
		(int32(hs[offset+1]&0xFF) << 16) |
		(int32(hs[offset+2]&0xFF) << 8) |
		int32(hs[offset+3]&0xFF)

	code := int(binaryCode) % int(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, code)
}

// hashForAlgo returns a hash.Hash constructor for the given algorithm name.
// Returns nil for unsupported algorithms. Empty string defaults to SHA1.
func hashForAlgo(algo string) func() hash.Hash {
	switch strings.ToUpper(algo) {
	case "", "SHA1":
		return sha1.New
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	default:
		return nil
	}
}

// decodeSecret decodes a base32-encoded OTP secret.
// Handles both padded and unpadded base32, uppercase and lowercase.
func decodeSecret(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty secret")
	}

	// Normalise to uppercase
	s = strings.ToUpper(s)

	// Remove any existing padding
	s = strings.TrimRight(s, "=")

	// Add correct padding for base32
	switch len(s) % 8 {
	case 2:
		s += "======"
	case 4:
		s += "===="
	case 5:
		s += "==="
	case 7:
		s += "="
	}

	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base32 decode: %w", err)
	}
	return key, nil
}
