//go:build darwin && cgo && !keychain_biometric

package keychain

import (
	gokeychain "github.com/keybase/go-keychain"
)

// New creates a macOS Keychain implementation for UNSIGNED builds.
//
// It stores the key in the legacy (file-based) Keychain with
// AccessibleWhenUnlockedThisDeviceOnly and gates every read behind a
// biometrics-only Touch ID prompt at the application layer (see PromptBiometric).
//
// Why not native biometric access control? A SecAccessControl-protected item
// lives in the data-protection Keychain, which requires the binary to be
// code-signed with a keychain-access-groups entitlement (Apple Developer). An
// unsigned `go build` binary gets errSecMissingEntitlement (-34018) on SecItemAdd.
// For signed/production builds, compile with `-tags keychain_biometric` (see
// keychain_acl_darwin.go and `make build-signed`) to get OS-native biometric
// gating where reading the item itself requires Touch ID.
func New() Keychain {
	return &darwinKeychain{}
}

type darwinKeychain struct{}

// Save persists key in the legacy Keychain. It deletes any existing item first
// (delete-then-add) so that changing the stored key always succeeds — the old
// AddItem-only code failed silently with errSecDuplicateItem on key rotation.
func (k *darwinKeychain) Save(key []byte, service, account string) error {
	_ = k.Delete(service, account) // best-effort; ignore not-found

	item := gokeychain.NewItem()
	item.SetSecClass(gokeychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(account)
	item.SetData(key)
	item.SetAccessible(gokeychain.AccessibleWhenUnlockedThisDeviceOnly)

	return gokeychain.AddItem(item)
}

// Load retrieves the key from the legacy Keychain, gating it behind a
// biometrics-only Touch ID prompt. The item is looked up first so that a
// missing item (e.g. first run) returns ErrNotFound WITHOUT a pointless Touch ID
// prompt; biometric auth is only requested once we know there is something to
// release. Returns ErrBiometricFailed if Touch ID is declined or unavailable.
func (k *darwinKeychain) Load(service, account string) ([]byte, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(service)
	query.SetAccount(account)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := gokeychain.QueryItem(query)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}

	// Item exists — require Touch ID before releasing the key.
	if !PromptBiometric("Unlock SecVault") {
		return nil, ErrBiometricFailed
	}

	key := results[0].Data
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return keyCopy, nil
}

func (k *darwinKeychain) Delete(service, account string) error {
	item := gokeychain.NewItem()
	item.SetSecClass(gokeychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(account)

	return gokeychain.DeleteItem(item)
}
