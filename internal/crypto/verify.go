package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// VerifyMasterPassword verifies a master password against a stored verification hash.
//
// password: the candidate master password.
// salt: the 16-byte salt used during original key derivation.
// storedHash: the 32-byte verification hash stored during init.
//
// Verification works by:
//  1. Deriving the master key from password + salt using Argon2id.
//  2. Deriving a verification hash from the master key using HKDF-SHA256.
//  3. Comparing the derived hash with storedHash using constant-time comparison.
//
// Returns true if the password is correct, false otherwise.
func (e *Engine) VerifyMasterPassword(password, salt, storedHash []byte) bool {
	_, ok := e.VerifyAndDeriveKey(password, salt, storedHash)
	return ok
}

// VerifyAndDeriveKey verifies the master password and returns the derived key
// in a single Argon2id pass. This avoids the performance penalty of calling
// VerifyMasterPassword followed by DeriveKey (which would run Argon2id twice).
//
// Returns (key, true) if the password is correct, (nil, false) otherwise.
// The caller is responsible for calling Zeroize on the returned key.
func (e *Engine) VerifyAndDeriveKey(password, salt, storedHash []byte) ([]byte, bool) {
	if len(password) == 0 || len(salt) == 0 || len(storedHash) == 0 {
		return nil, false
	}

	key, err := e.DeriveKey(password, salt)
	if err != nil {
		return nil, false
	}

	// Derive verify hash using HKDF with the master key.
	// Using the same salt as Argon2id for HKDF salt provides additional separation.
	// The info parameter binds this derivation to "passwd.verify".
	hkdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	verifyHash := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, verifyHash); err != nil {
		Zeroize(key)
		return nil, false
	}
	defer Zeroize(verifyHash)

	// Constant-time comparison prevents timing side-channel attacks.
	if hmac.Equal(verifyHash, storedHash) {
		return key, true
	}

	// Password incorrect — zeroize derived key before returning.
	Zeroize(key)
	return nil, false
}

// DeriveVerifyHash derives the 32-byte verification hash from a master key and salt using HKDF-SHA256.
func (e *Engine) DeriveVerifyHash(key, salt []byte) []byte {
	hkdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	verifyHash := make([]byte, 32)
	_, _ = io.ReadFull(hkdf, verifyHash)
	return verifyHash
}
