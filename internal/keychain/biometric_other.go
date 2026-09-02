//go:build !darwin

package keychain

// PromptBiometric is a no-op on non-macOS platforms.
func PromptBiometric(reason string) bool {
	return false
}
