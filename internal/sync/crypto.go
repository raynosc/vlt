package sync

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// EncryptBlob encrypts plaintext using AES-256-GCM with the given key and optional AAD.
// key must be 32 bytes (256-bit).
// Returns packed nonce || ciphertext (includes GCM authentication tag).
func EncryptBlob(plaintext, key, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext must not be empty")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	// Seal appends ciphertext+tag to nonce (preserving nonce for return)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Pack: nonce || ciphertext
	packed := make([]byte, 0, len(nonce)+len(ciphertext))
	packed = append(packed, nonce...)
	packed = append(packed, ciphertext...)

	return packed, nil
}

// DecryptBlob decrypts ciphertext packed by EncryptBlob using optional AAD.
// key must be 32 bytes (256-bit).
// The input blob must be nonce || ciphertext (as produced by EncryptBlob).
func DecryptBlob(blob, key, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	if len(blob) == 0 {
		return nil, fmt.Errorf("blob must not be empty")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return nil, fmt.Errorf("blob too short: got %d bytes, need at least %d", len(blob), nonceSize)
	}

	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed")
	}

	return plaintext, nil
}
