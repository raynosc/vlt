//go:build !darwin && !linux

package keychain

// New creates a stub Keychain implementation that returns ErrUnsupported.
func New() Keychain {
	return &unsupportedKeychain{}
}

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
