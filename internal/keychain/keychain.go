// Package keychain provides platform-specific secure storage for the derived master key.
//
// macOS: Keychain via github.com/keybase/go-keychain (pure Go, no CGo needed).
// Other platforms: returns ErrUnsupported.
package keychain

import "errors"

// Errors returned by keychain operations.
var (
	ErrUnsupported = errors.New("keychain: not supported on this platform")
	ErrNotFound    = errors.New("keychain: item not found")
	// ErrBiometricCanceled is returned when the user dismisses the Touch ID prompt.
	ErrBiometricCanceled = errors.New("keychain: biometric authentication canceled")
	// ErrBiometricFailed is returned when Touch ID authentication fails or is unavailable.
	ErrBiometricFailed = errors.New("keychain: biometric authentication failed")
)

// Keychain is the interface for platform-specific secure storage.
type Keychain interface {
	// Save stores a key in the keychain.
	Save(key []byte, service, account string) error
	// Load retrieves a key from the keychain.
	Load(service, account string) ([]byte, error)
	// Delete removes a key from the keychain.
	Delete(service, account string) error
}
