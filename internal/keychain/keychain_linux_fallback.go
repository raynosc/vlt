//go:build linux

package keychain

// unsupportedKeychain is a stub implementation used as fallback on Linux
// when D-Bus session bus is not available.
type unsupportedKeychain struct{}

func (k *unsupportedKeychain) Save(_ []byte, _, _ string) error {
	return ErrUnsupported
}

func (k *unsupportedKeychain) Load(_, _ string) ([]byte, error) {
	return nil, ErrUnsupported
}

func (k *unsupportedKeychain) Delete(_, _ string) error {
	return ErrUnsupported
}
