package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"time"
)

// GenerateSteamCode generates a Steam Guard code using the current time.
// The code is 5 characters from the SteamAlphabet.
func GenerateSteamCode(secret string) (string, error) {
	return generateSteamCodeAt(secret, time.Now())
}

// generateSteamCodeAt generates a Steam Guard code for the given time.
// Exposed for testing; callers should use GenerateSteamCode.
func generateSteamCodeAt(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", fmt.Errorf("invalid secret encoding: %w", err)
	}
	if len(key) == 0 {
		return "", fmt.Errorf("empty secret")
	}

	counter := uint64(t.Unix() / 30)

	mac := hmac.New(sha1.New, key)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac.Write(counterBytes[:])
	hs := mac.Sum(nil)

	// Dynamic truncation (same as HOTP)
	offset := hs[len(hs)-1] & 0x0F
	binaryCode := (int32(hs[offset]&0x7F) << 24) |
		(int32(hs[offset+1]&0xFF) << 16) |
		(int32(hs[offset+2]&0xFF) << 8) |
		int32(hs[offset+3]&0xFF)

	// Convert to Steam's 5-char custom alphabet
	code := make([]byte, 5)
	for i := range code {
		code[i] = SteamAlphabet[binaryCode%26]
		binaryCode /= 26
	}
	return string(code), nil
}
