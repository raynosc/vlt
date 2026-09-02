package sync

import (
	"bytes"
	"fmt"
)

// wrappedConfigMagic identifies a config-table value that has been encrypted
// with the master key (issue S-01). It is stored as the first 4 bytes of the
// blob, followed by the same nonce||ciphertext layout used by EncryptBlob.
//
// Legacy plaintext values (vaults created before the fix) lack this prefix
// and are detected on read and migrated lazily.
var wrappedConfigMagic = []byte{0x76, 0x6c, 0x74, 0x31} // "vlt1"

// Config format version constants (ADR-9).
//
// ConfigFormatVersionLegacy (1) allows the nil-AAD fallback decryption path,
// permitting lazy migration of older vaults on first authenticated read.
//
// ConfigFormatVersionAAD (2) disables the nil-AAD fallback entirely. Once a
// vault has been fully migrated (both api_key and sync_encryption_key re-wrapped
// with key-specific AAD and config_format_version persisted as "2"), this version
// prevents a tampered or replayed legacy blob from silently downgrading decryption.
const (
	ConfigFormatVersionLegacy = 1
	ConfigFormatVersionAAD    = 2
)

// WrapConfigValue encrypts a sensitive config value with the master key and binds it to its key name using AAD.
// The returned blob has the layout: magic(4) || nonce(12) || ciphertext+tag.
func WrapConfigValue(keyName string, value, masterKey []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("value must not be empty")
	}
	blob, err := EncryptBlob(value, masterKey, []byte(keyName))
	if err != nil {
		return nil, fmt.Errorf("wrap config value: %w", err)
	}
	out := make([]byte, 0, len(wrappedConfigMagic)+len(blob))
	out = append(out, wrappedConfigMagic...)
	out = append(out, blob...)
	return out, nil
}

// IsWrappedConfigValue reports whether the blob carries the magic prefix that
// marks it as encrypted with the master key.
func IsWrappedConfigValue(blob []byte) bool {
	return bytes.HasPrefix(blob, wrappedConfigMagic)
}

// UnwrapConfigValue inspects a config-table value and returns the plaintext.
// It decrypts the value using its key name as AAD (M1).
//
// configVersion controls the nil-AAD fallback behaviour (ADR-9):
//   - ConfigFormatVersionLegacy (1): if AAD decryption fails, falls back to nil-AAD
//     decryption to support migrating older vaults seamlessly.
//   - ConfigFormatVersionAAD (2): the nil-AAD fallback is DISABLED; the AAD-decrypt
//     error is returned directly. Use this once a vault has been fully migrated so
//     that a tampered legacy blob cannot silently downgrade decryption.
//
// The boolean return reports whether the input was successfully unwrapped in the LATEST format:
//   - true:  the value was decrypted using masterKey with the correct key-specific AAD.
//   - false: the value was stored in legacy plaintext (pre-S-01) or encrypted with legacy nil AAD.
//     Callers should re-write it with WrapConfigValue to migrate the vault to the latest secure format.
func UnwrapConfigValue(keyName string, stored, masterKey []byte, configVersion int) (plaintext []byte, wrapped bool, err error) {
	if !IsWrappedConfigValue(stored) {
		return stored, false, nil
	}
	blob := stored[len(wrappedConfigMagic):]

	// First, attempt to decrypt with correct key-specific AAD binding (M1)
	pt, err := DecryptBlob(blob, masterKey, []byte(keyName))
	if err == nil {
		return pt, true, nil
	}

	// ADR-9: when configVersion >= ConfigFormatVersionAAD, skip the nil-AAD fallback
	// and return the AAD-decrypt error directly. This prevents a tampered or replayed
	// legacy blob from silently downgrading a migrated vault.
	if configVersion >= ConfigFormatVersionAAD {
		return nil, false, fmt.Errorf("unwrap config value: %w", err)
	}

	// Fallback to nil AAD for backward compatibility / vault migration (version 1 only)
	pt, fallbackErr := DecryptBlob(blob, masterKey, nil)
	if fallbackErr == nil {
		// Return wrapped = false to trigger automatic lazy migration to key-specific AAD!
		return pt, false, nil
	}

	return nil, true, fmt.Errorf("unwrap config value: %w", err)
}
