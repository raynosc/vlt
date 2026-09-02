package parse

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ParseSSHPrivate parses a PEM-encoded SSH private key.
//
// Supports RSA, Ed25519, and ECDSA (P-256, P-384, P-521) key types.
// Returns ErrEmptyInput for empty data, ErrInvalidPEM for non-PEM or
// encrypted keys, ErrUnsupportedKeyType for DSA or other unsupported types.
func ParseSSHPrivate(data []byte) (*Metadata, error) {
	if len(data) == 0 {
		return nil, ErrEmptyInput
	}

	// Check for valid PEM before delegating to ssh.ParsePrivateKey.
	// This ensures non-PEM data gets ErrInvalidPEM rather than ErrNotSSH.
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: not a PEM-encoded key", ErrInvalidPEM)
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		var passErr *ssh.PassphraseMissingError
		if errors.As(err, &passErr) {
			return nil, fmt.Errorf("%w: key is encrypted", ErrInvalidPEM)
		}
		return nil, fmt.Errorf("%w: %v", ErrNotSSH, err)
	}

	pub := signer.PublicKey()
	m := &Metadata{
		Format:            FormatSSHPrivate.String(),
		FingerprintSHA256: ssh.FingerprintSHA256(pub),
		KeyType:           pub.Type(),
	}

	// Extract comment from PEM block headers (RSA PRIVATE KEY format).
	if block, _ := pem.Decode(data); block != nil {
		if comment := block.Headers["Comment"]; comment != "" {
			m.Comment = comment
		}
	}

	// Bit length from the underlying crypto public key.
	if cpk, ok := pub.(ssh.CryptoPublicKey); ok {
		m.BitLength = bitLength(cpk.CryptoPublicKey())
	}

	return m, nil
}

// ParseSSHPublic parses an SSH public key (authorized_keys format).
//
// Accepts "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256/384/521" formats.
// Returns ErrEmptyInput for empty data, ErrNotSSH for invalid key data.
func ParseSSHPublic(data []byte) (*Metadata, error) {
	if len(data) == 0 {
		return nil, ErrEmptyInput
	}

	key, comment, _, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotSSH, err)
	}
	_ = rest // remaining data (unused — single key per call)

	m := &Metadata{
		Format:            FormatSSHPublic.String(),
		FingerprintSHA256: ssh.FingerprintSHA256(key),
		KeyType:           key.Type(),
		Comment:           comment,
	}

	if cpk, ok := key.(ssh.CryptoPublicKey); ok {
		m.BitLength = bitLength(cpk.CryptoPublicKey())
	}

	return m, nil
}

// bitLength returns the bit length of a crypto public key.
// Returns 0 for unknown key types.
func bitLength(pub crypto.PublicKey) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(k) * 8
	default:
		return 0
	}
}
