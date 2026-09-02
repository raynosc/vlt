package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
)

const (
	// recoveryKeyLen is the length of the recovery key in bytes.
	recoveryKeyLen = 32
	// mnemonicChecksumLen is the number of checksum bytes appended to the key.
	mnemonicChecksumLen = 4
	// mnemonicWordsTotal is the number of words in the mnemonic phrase.
	mnemonicWordsTotal = recoveryKeyLen + mnemonicChecksumLen // 36
)

// GenerateRecoveryKit generates a recovery kit for a master key.
//
// It generates a random 32-byte recovery key, wraps the master key using
// AES-256-GCM with the recovery key, and encodes the recovery key as a
// mnemonic phrase of English words.
//
// Returns:
//   - mnemonic: a space-separated phrase of 36 words encoding the recovery key.
//   - blob: binary blob containing (nonce || wrapped_master_key) for recovery.
//   - err: any error encountered.
func (e *Engine) GenerateRecoveryKit(masterKey []byte) (mnemonic string, blob []byte, err error) {
	if len(masterKey) == 0 {
		return "", nil, fmt.Errorf("master key must not be empty")
	}

	// Generate random 32-byte recovery key.
	recoveryKey := make([]byte, recoveryKeyLen)
	if _, err := rand.Read(recoveryKey); err != nil {
		return "", nil, fmt.Errorf("recovery key generation: %w", err)
	}
	defer Zeroize(recoveryKey)

	// Wrap the master key with the recovery key using AES-256-GCM.
	wrappedKey, nonce, err := e.Encrypt(masterKey, recoveryKey)
	if err != nil {
		return "", nil, fmt.Errorf("wrap master key: %w", err)
	}

	// Encode recovery key as mnemonic phrase.
	mnemonic, err = encodeMnemonic(recoveryKey)
	if err != nil {
		return "", nil, fmt.Errorf("encode mnemonic: %w", err)
	}

	// Blob: nonce (12 bytes) || wrapped key (ciphertext + GCM tag).
	blob = make([]byte, 0, len(nonce)+len(wrappedKey))
	blob = append(blob, nonce...)
	blob = append(blob, wrappedKey...)

	return mnemonic, blob, nil
}

// RecoverMasterKey recovers the master key from a recovery kit.
//
// mnemonic: the 36-word mnemonic phrase (space-separated).
// blob: binary blob containing (nonce || wrapped_master_key) as produced by GenerateRecoveryKit.
//
// Returns the recovered master key.
func (e *Engine) RecoverMasterKey(mnemonic string, blob []byte) ([]byte, error) {
	if len(blob) < 12 {
		return nil, fmt.Errorf("recovery blob too short")
	}

	// Decode mnemonic to recovery key.
	recoveryKey, err := decodeMnemonic(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("decode mnemonic: %w", err)
	}
	defer Zeroize(recoveryKey)

	// Extract nonce and wrapped key.
	nonce := blob[:12]
	wrappedKey := blob[12:]

	// Decrypt to recover the master key.
	masterKey, err := e.Decrypt(wrappedKey, recoveryKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("recover master key: %w", err)
	}

	return masterKey, nil
}

// VerifyRecoveryKit verifies if a mnemonic phrase correctly un性質/decrypts the recovery blob to the expected master key.
func (e *Engine) VerifyRecoveryKit(mnemonic string, blob, salt, verifyHash []byte) (bool, error) {
	masterKey, err := e.RecoverMasterKey(mnemonic, blob)
	if err != nil {
		return false, err
	}
	defer Zeroize(masterKey)

	// Validate the recovered master key against the vault's verify hash
	expectedVerify := e.DeriveVerifyHash(masterKey, salt)
	defer Zeroize(expectedVerify)

	return hmacEqual(expectedVerify, verifyHash), nil
}

// encodeMnemonic encodes a 32-byte key as a space-separated mnemonic phrase.
// Appends a 4-byte checksum (first 4 bytes of SHA-256(key)) for integrity.
func encodeMnemonic(key []byte) (string, error) {
	if len(key) != recoveryKeyLen {
		return "", fmt.Errorf("encodeMnemonic: key must be %d bytes, got %d", recoveryKeyLen, len(key))
	}

	// Compute checksum.
	hash := sha256.Sum256(key)
	checksum := hash[:mnemonicChecksumLen]

	// Combine key + checksum and map each byte to a word.
	words := make([]string, mnemonicWordsTotal)
	for i := 0; i < recoveryKeyLen; i++ {
		words[i] = mnemonicWords[key[i]]
	}
	for i := 0; i < mnemonicChecksumLen; i++ {
		words[recoveryKeyLen+i] = mnemonicWords[checksum[i]]
	}

	return strings.Join(words, " "), nil
}

// decodeMnemonic decodes a mnemonic phrase back to the original key.
// Validates the checksum before returning the key.
func decodeMnemonic(phrase string) ([]byte, error) {
	words := strings.Fields(phrase)
	if len(words) != mnemonicWordsTotal {
		return nil, fmt.Errorf("expected %d words, got %d", mnemonicWordsTotal, len(words))
	}

	// Build reverse lookup: word → index.
	wordIndex := make(map[string]byte, len(mnemonicWords))
	for i, w := range mnemonicWords {
		wordIndex[w] = byte(i)
	}

	// Map each word back to a byte.
	keyAndChecksum := make([]byte, mnemonicWordsTotal)
	for i, w := range words {
		idx, ok := wordIndex[w]
		if !ok {
			return nil, fmt.Errorf("unknown word in position %d: %q", i, w)
		}
		keyAndChecksum[i] = idx
	}

	// Separate key and checksum.
	key := keyAndChecksum[:recoveryKeyLen]
	storedChecksum := keyAndChecksum[recoveryKeyLen:]

	// Verify checksum.
	hash := sha256.Sum256(key)
	expectedChecksum := hash[:mnemonicChecksumLen]
	if !hmacEqual(storedChecksum, expectedChecksum) {
		return nil, fmt.Errorf("mnemonic checksum mismatch")
	}

	return key, nil
}

// hmacEqual provides constant-time comparison for checksum validation.
func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
