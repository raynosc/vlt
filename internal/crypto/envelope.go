package crypto

import "fmt"

// NonceSize is the AES-256-GCM nonce length in bytes. It matches
// cipher.AEAD.NonceSize() for the standard GCM construction used by Encrypt.
const NonceSize = 12

// PackEnvelope combines a nonce and ciphertext into a single storage blob laid
// out as nonce || ciphertext. This is the canonical on-disk envelope format for
// every encrypted value in the vault (secret values, OTP seeds, config keys).
//
// It is the single source of truth: cli, gui, tui, daemon, and watchtower all
// call this instead of re-implementing the split/join, which previously drifted
// across five packages.
func PackEnvelope(nonce, ciphertext []byte) []byte {
	blob := make([]byte, 0, len(nonce)+len(ciphertext))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)
	return blob
}

// UnpackEnvelope splits a nonce || ciphertext blob back into its parts. It
// returns an error when the blob is too short to contain a full nonce.
func UnpackEnvelope(blob []byte) (nonce, ciphertext []byte, err error) {
	if len(blob) < NonceSize {
		return nil, nil, fmt.Errorf("encrypted blob too short")
	}
	return blob[:NonceSize], blob[NonceSize:], nil
}
