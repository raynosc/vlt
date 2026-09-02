package parse

import (
	"fmt"

	"github.com/raynosc/vlt/internal/crypto"
	"software.sslmate.com/src/go-pkcs12"
)

// ParsePKCS12 decrypts and parses a PKCS#12/PFX bundle.
//
// Returns the certificate count and metadata from the bundle.
// Returns ErrEmptyInput for empty data and ErrWrongPassword for incorrect passwords.
func ParsePKCS12(data []byte, password string) (*Metadata, error) {
	if len(data) == 0 {
		return nil, ErrEmptyInput
	}

	privKey, _, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		if err == pkcs12.ErrIncorrectPassword {
			return nil, ErrWrongPassword
		}
		return nil, fmt.Errorf("corrupted PKCS12 data: %v", err)
	}
	defer crypto.ZeroizePrivateKey(privKey)

	// DecodeChain returns (privateKey, leafCert, caCerts, err).
	// caCerts includes all certificates except the leaf.
	certCount := 1 + len(caCerts)

	m := &Metadata{
		Format:    FormatPKCS12.String(),
		CertCount: certCount,
	}

	// Friendly names require lower-level parsing of the PKCS12 structure.
	// The go-pkcs12 library doesn't expose friendly names through DecodeChain.
	// FriendlyNames is left empty for now; a future enhancement could extract them.

	return m, nil
}
