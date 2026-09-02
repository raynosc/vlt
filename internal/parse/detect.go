package parse

import (
	"bytes"
	"encoding/pem"
	"strings"
)

// Format represents a detected certificate/key format.
type Format int

const (
	FormatUnknown    Format = iota
	FormatX509PEM           // PEM-encoded X.509 certificate
	FormatSSHPrivate        // PEM-encoded SSH private key (RSA/ECDSA/Ed25519)
	FormatSSHPublic         // SSH public key (authorized_keys format)
	FormatPKCS12            // PKCS#12/PFX binary bundle
)

func (f Format) String() string {
	switch f {
	case FormatX509PEM:
		return "x509"
	case FormatSSHPrivate:
		return "ssh_private"
	case FormatSSHPublic:
		return "ssh_public"
	case FormatPKCS12:
		return "pkcs12"
	default:
		return "unknown"
	}
}

// Detect identifies the format of certificate/key data from content alone.
// An empty slice returns FormatUnknown with ErrEmptyInput.
func Detect(data []byte) (Format, error) {
	if len(data) == 0 {
		return FormatUnknown, ErrEmptyInput
	}

	// Try PEM decode first
	block, _ := pem.Decode(data)
	if block != nil {
		switch block.Type {
		case "CERTIFICATE":
			return FormatX509PEM, nil
		case "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY":
			return FormatSSHPrivate, nil
		case "PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			return FormatSSHPrivate, nil
		case "DSA PRIVATE KEY":
			return FormatUnknown, ErrUnsupportedKeyType
		default:
			return FormatUnknown, nil
		}
	}

	// Try SSH public key format (starts with key type)
	if looksLikeSSHPublic(data) {
		return FormatSSHPublic, nil
	}

	// Try PKCS12 binary magic bytes
	if len(data) >= 4 && isPKCS12(data) {
		return FormatPKCS12, nil
	}

	// DER-encoded X.509 starts with ASN.1 SEQUENCE (0x30)
	if len(data) > 0 && data[0] == 0x30 {
		return FormatX509PEM, nil
	}

	return FormatUnknown, nil
}

func looksLikeSSHPublic(data []byte) bool {
	trimmed := strings.TrimSpace(string(bytes.Trim(data, "\x00")))
	prefixes := []string{
		"ssh-rsa ",
		"ssh-ed25519 ",
		"ecdsa-sha2-",
		"sk-ssh-ed25519",
		"sk-ecdsa-sha2-",
		"ssh-dss ",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

func isPKCS12(data []byte) bool {
	if data[0] != 0x30 {
		return false
	}
	// Skip ASN.1 SEQUENCE length (may be long-form)
	offset := 2
	if len(data) > 2 && data[1]&0x80 != 0 {
		n := int(data[1] & 0x7f)
		if n > 4 { // unusually long length
			return false
		}
		offset = 2 + n
	}
	// PKCS12 PFX PDU starts with INTEGER {3} for version
	return offset+2 < len(data) && data[offset] == 0x02 && data[offset+1] == 0x01 && data[offset+2] == 0x03
}
