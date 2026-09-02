package parse

import "time"

// Metadata holds parsed certificate/key information stored as JSON.
// Fields are format-specific; only relevant fields are populated for a given format.
type Metadata struct {
	Format string `json:"format,omitempty"`

	// X.509
	SubjectCN          string   `json:"subject_cn,omitempty"`
	IssuerCN           string   `json:"issuer_cn,omitempty"`
	NotBefore          string   `json:"not_before,omitempty"` // ISO 8601 / RFC 3339
	NotAfter           string   `json:"not_after,omitempty"`  // ISO 8601 / RFC 3339 — queryable
	SerialNumber       string   `json:"serial_number,omitempty"`
	FingerprintSHA1    string   `json:"fingerprint_sha1,omitempty"`
	FingerprintSHA256  string   `json:"fingerprint_sha256,omitempty"`
	SANs               []string `json:"sans,omitempty"`
	KeyUsage           []string `json:"key_usage,omitempty"`
	ExtKeyUsage        []string `json:"ext_key_usage,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	IsCA               bool     `json:"is_ca,omitempty"`

	// SSH
	KeyType   string `json:"key_type,omitempty"`
	BitLength int    `json:"bit_length,omitempty"`
	Comment   string `json:"comment,omitempty"`

	// PKCS12
	CertCount     int      `json:"cert_count,omitempty"`
	FriendlyNames []string `json:"friendly_names,omitempty"`
}

// IsExpired returns true if the certificate has expired.
func (m *Metadata) IsExpired() bool {
	if m.NotAfter == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, m.NotAfter)
	if err != nil {
		return false
	}
	return time.Now().After(t)
}

// DaysUntilExpiry returns the number of days until the certificate expires.
// Returns 0 if NotAfter is empty or unparseable. Returns a negative number
// if the certificate has already expired.
func (m *Metadata) DaysUntilExpiry() int {
	if m.NotAfter == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, m.NotAfter)
	if err != nil {
		return 0
	}
	return int(time.Until(t).Hours() / 24)
}
