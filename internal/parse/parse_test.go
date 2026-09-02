package parse

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	p12 "software.sslmate.com/src/go-pkcs12"
)

// ---------------------------------------------------------------------------
// Test fixture generation (programmatic, in-memory)
// ---------------------------------------------------------------------------

var (
	testX509Valid      []byte
	testX509Expired    []byte
	testX509WithSANs   []byte
	testSSHRSAPriv     []byte
	testSSHEd25519Priv []byte
	testSSHECDSAPriv   []byte
	testSSHRSAPub      []byte
	testSSHEd25519Pub  []byte
	testSSHECDSAPub    []byte
	testPKCS12Data     []byte
	testPKCS12Pwd      = "test123"
)

func init() { generateFixtures() }

func generateFixtures() {
	// X.509 certificates
	testX509Valid = mustGenCert("Test Root CA", "Test Root CA", 2048,
		time.Now().Add(-1*time.Hour), time.Now().Add(365*24*time.Hour), nil, true)
	testX509Expired = mustGenCert("Expired Cert", "Expired Issuer", 2048,
		time.Now().Add(-730*24*time.Hour), time.Now().Add(-48*time.Hour), nil, false)
	testX509WithSANs = mustGenCertWithSANs("SANs Cert", "SANs Issuer", 2048,
		time.Now().Add(-1*time.Hour), time.Now().Add(365*24*time.Hour),
		[]string{"example.com", "www.example.com", "mail.example.com"}, false)

	// SSH private keys
	var err error
	testSSHRSAPriv, err = marshalSSHPriv(generateRSA(2048), "rsa-comment")
	must(err)
	testSSHEd25519Priv, err = marshalSSHPriv(generateEd25519(), "ed25519-comment")
	must(err)
	testSSHECDSAPriv, err = marshalSSHPriv(generateECDSA(elliptic.P256()), "ecdsa-comment")
	must(err)

	// SSH public keys
	testSSHRSAPub = pubKeyLine(testSSHRSAPriv, "rsa-user@host")
	testSSHEd25519Pub = pubKeyLine(testSSHEd25519Priv, "ed25519-user@host")
	testSSHECDSAPub = pubKeyLine(testSSHECDSAPriv, "ecdsa-user@host")

	// PKCS12 bundle
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         false,
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caKey := generateRSA(2048)
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	must(err)
	caCert, err := x509.ParseCertificate(caDER)
	must(err)

	leafKey := generateRSA(2048)
	leafTmpl.Issuer = caTmpl.Subject
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	must(err)
	leafCert, err := x509.ParseCertificate(leafDER)
	must(err)

	//nolint:staticcheck
	testPKCS12Data, err = p12.Encode(rand.Reader, leafKey, leafCert, []*x509.Certificate{caCert}, testPKCS12Pwd)
	must(err)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// --- X.509 fixture helpers ---

func mustGenCert(subject, issuer string, bits int, notBefore, notAfter time.Time, dnsNames []string, isCA bool) []byte {
	return mustGenCertWithSANs(subject, issuer, bits, notBefore, notAfter, dnsNames, isCA)
}

func mustGenCertWithSANs(subject, issuer string, bits int, notBefore, notAfter time.Time, dnsNames []string, isCA bool) []byte {
	key := generateRSA(bits)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: subject},
		Issuer:                pkix.Name{CommonName: issuer},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent := tmpl
	if subject != issuer && !isCA {
		// For non-self-signed, we still self-sign (just testing parse, not chain validation)
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, key)
	must(err)
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return pem.EncodeToMemory(block)
}

// --- SSH fixture helpers ---

func generateRSA(bits int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	must(err)
	return k
}

func generateEd25519() ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	return priv
}

func generateECDSA(curve elliptic.Curve) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	must(err)
	return k
}

func marshalSSHPriv(key interface{}, comment string) ([]byte, error) {
	// ssh.MarshalPrivateKey expects crypto.PrivateKey
	priv, ok := key.(cryptoPrivateKey)
	if !ok {
		return nil, errors.New("key does not implement crypto.PrivateKey")
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// cryptoPrivateKey is satisfied by *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, etc.
type cryptoPrivateKey interface{}

func pubKeyLine(privPEM []byte, comment string) []byte {
	signer, err := ssh.ParsePrivateKey(privPEM)
	must(err)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if comment != "" {
		line += " " + comment
	}
	return []byte(line + "\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDetect(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    Format
		wantErr error
	}{
		{"PEM X.509 certificate", testX509Valid, FormatX509PEM, nil},
		{"PEM SSH RSA private key", testSSHRSAPriv, FormatSSHPrivate, nil},
		{"PEM SSH Ed25519 private key", testSSHEd25519Priv, FormatSSHPrivate, nil},
		{"PEM SSH ECDSA private key", testSSHECDSAPriv, FormatSSHPrivate, nil},
		{"SSH RSA public key", testSSHRSAPub, FormatSSHPublic, nil},
		{"SSH Ed25519 public key", testSSHEd25519Pub, FormatSSHPublic, nil},
		{"SSH ECDSA public key", testSSHECDSAPub, FormatSSHPublic, nil},
		{"PKCS12 binary", testPKCS12Data, FormatPKCS12, nil},
		{"empty input", []byte{}, FormatUnknown, ErrEmptyInput},
		{"random binary data", []byte{0x00, 0x01, 0x02, 0x03}, FormatUnknown, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Detect(tt.data)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Detect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseX509(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantCN  string
		wantErr error
		check   func(t *testing.T, m *Metadata)
	}{
		{
			name:    "valid PEM certificate",
			data:    testX509Valid,
			wantCN:  "Test Root CA",
			wantErr: nil,
			check: func(t *testing.T, m *Metadata) {
				if m.Format != "x509" {
					t.Errorf("Format = %q, want x509", m.Format)
				}
				if m.SubjectCN != "Test Root CA" {
					t.Errorf("SubjectCN = %q, want Test Root CA", m.SubjectCN)
				}
				if m.FingerprintSHA256 == "" {
					t.Error("FingerprintSHA256 is empty")
				}
				if m.FingerprintSHA1 == "" {
					t.Error("FingerprintSHA1 is empty")
				}
				if m.SerialNumber == "" {
					t.Error("SerialNumber is empty")
				}
				if m.NotBefore == "" || m.NotAfter == "" {
					t.Error("NotBefore/NotAfter is empty")
				}
				if len(m.KeyUsage) == 0 {
					t.Error("KeyUsage is empty")
				}
				if len(m.ExtKeyUsage) == 0 {
					t.Error("ExtKeyUsage is empty")
				}
				if m.SignatureAlgorithm == "" {
					t.Error("SignatureAlgorithm is empty")
				}
			},
		},
		{
			name:    "expired certificate",
			data:    testX509Expired,
			wantCN:  "Expired Cert",
			wantErr: nil,
			check: func(t *testing.T, m *Metadata) {
				if !m.IsExpired() {
					t.Error("IsExpired() = false, want true")
				}
				if m.DaysUntilExpiry() >= 0 {
					t.Errorf("DaysUntilExpiry() = %d, want negative", m.DaysUntilExpiry())
				}
			},
		},
		{
			name:    "certificate with SANs",
			data:    testX509WithSANs,
			wantCN:  "SANs Cert",
			wantErr: nil,
			check: func(t *testing.T, m *Metadata) {
				if len(m.SANs) != 3 {
					t.Errorf("len(SANs) = %d, want 3", len(m.SANs))
				}
				expected := []string{"example.com", "www.example.com", "mail.example.com"}
				for i, san := range expected {
					if m.SANs[i] != san {
						t.Errorf("SANs[%d] = %q, want %q", i, m.SANs[i], san)
					}
				}
			},
		},
		{
			name:    "empty input",
			data:    []byte{},
			wantErr: ErrEmptyInput,
		},
		{
			name:    "invalid PEM data",
			data:    []byte("not a certificate"),
			wantErr: ErrInvalidPEM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ParseX509(tt.data)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseX509() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if tt.check != nil {
				tt.check(t, m)
			}
		})
	}
}

func TestParseSSHPrivate(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantKey string
		wantErr error
		check   func(t *testing.T, m *Metadata)
	}{
		{
			name:    "RSA 2048 private key",
			data:    testSSHRSAPriv,
			wantKey: "ssh-rsa",
			wantErr: nil,
			check: func(t *testing.T, m *Metadata) {
				if m.BitLength != 2048 {
					t.Errorf("BitLength = %d, want 2048", m.BitLength)
				}
				if m.FingerprintSHA256 == "" {
					t.Error("FingerprintSHA256 is empty")
				}
			},
		},
		{
			name:    "Ed25519 private key",
			data:    testSSHEd25519Priv,
			wantKey: "ssh-ed25519",
			wantErr: nil,
			check: func(t *testing.T, m *Metadata) {
				if m.BitLength != 256 {
					t.Errorf("BitLength = %d, want 256", m.BitLength)
				}
			},
		},
		{
			name:    "ECDSA P-256 private key",
			data:    testSSHECDSAPriv,
			wantKey: "ecdsa-sha2-nistp256",
			wantErr: nil,
			check: func(t *testing.T, m *Metadata) {
				if m.BitLength != 256 {
					t.Errorf("BitLength = %d, want 256", m.BitLength)
				}
			},
		},
		{
			name:    "empty input",
			data:    []byte{},
			wantErr: ErrEmptyInput,
		},
		{
			name:    "invalid PEM data",
			data:    []byte("not a private key"),
			wantErr: ErrInvalidPEM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ParseSSHPrivate(tt.data)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseSSHPrivate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if m.Format != "ssh_private" {
				t.Errorf("Format = %q, want ssh_private", m.Format)
			}
			if m.KeyType != tt.wantKey {
				t.Errorf("KeyType = %q, want %q", m.KeyType, tt.wantKey)
			}
			if m.FingerprintSHA256 == "" {
				t.Error("FingerprintSHA256 is empty")
			}
			if tt.check != nil {
				tt.check(t, m)
			}
		})
	}
}

func TestParseSSHPublic(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		comment string
		wantErr error
	}{
		{
			name:    "RSA public key with comment",
			data:    testSSHRSAPub,
			want:    "ssh-rsa",
			comment: "rsa-user@host",
			wantErr: nil,
		},
		{
			name:    "Ed25519 public key with comment",
			data:    testSSHEd25519Pub,
			want:    "ssh-ed25519",
			comment: "ed25519-user@host",
			wantErr: nil,
		},
		{
			name:    "ECDSA P-256 public key with comment",
			data:    testSSHECDSAPub,
			want:    "ecdsa-sha2-nistp256",
			comment: "ecdsa-user@host",
			wantErr: nil,
		},
		{
			name:    "empty input",
			data:    []byte{},
			wantErr: ErrEmptyInput,
		},
		{
			name:    "invalid key data",
			data:    []byte("not-a-key"),
			wantErr: ErrNotSSH,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ParseSSHPublic(tt.data)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseSSHPublic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if m.Format != "ssh_public" {
				t.Errorf("Format = %q, want ssh_public", m.Format)
			}
			if m.KeyType != tt.want {
				t.Errorf("KeyType = %q, want %q", m.KeyType, tt.want)
			}
			if m.Comment != tt.comment {
				t.Errorf("Comment = %q, want %q", m.Comment, tt.comment)
			}
			if m.FingerprintSHA256 == "" {
				t.Error("FingerprintSHA256 is empty")
			}
		})
	}
}

func TestParsePKCS12(t *testing.T) {
	t.Run("valid bundle with correct password", func(t *testing.T) {
		m, err := ParsePKCS12(testPKCS12Data, testPKCS12Pwd)
		if err != nil {
			t.Fatalf("ParsePKCS12() error = %v", err)
		}
		if m.Format != "pkcs12" {
			t.Errorf("Format = %q, want pkcs12", m.Format)
		}
		if m.CertCount != 2 {
			t.Errorf("CertCount = %d, want 2", m.CertCount)
		}
	})

	// Regression: the deferred ZeroizePrivateKey in ParsePKCS12 must not
	// interfere with the returned Metadata or produce a panic.
	t.Run("key zeroized after return — metadata intact", func(t *testing.T) {
		m, err := ParsePKCS12(testPKCS12Data, testPKCS12Pwd)
		if err != nil {
			t.Fatalf("ParsePKCS12() unexpected error: %v", err)
		}
		if m == nil {
			t.Fatal("ParsePKCS12() returned nil Metadata")
			return
		}
		if m.CertCount != 2 {
			t.Errorf("CertCount = %d, want 2", m.CertCount)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		_, err := ParsePKCS12(testPKCS12Data, "wrong-password")
		if !errors.Is(err, ErrWrongPassword) {
			t.Errorf("ParsePKCS12() error = %v, want ErrWrongPassword", err)
		}
	})

	t.Run("corrupted data", func(t *testing.T) {
		_, err := ParsePKCS12([]byte{0x00, 0x01, 0x02}, testPKCS12Pwd)
		if err == nil {
			t.Fatal("ParsePKCS12() expected error, got nil")
		}
		if !strings.Contains(err.Error(), "corrupted PKCS12 data") {
			t.Errorf("ParsePKCS12() error = %q, want 'corrupted PKCS12 data'", err)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := ParsePKCS12([]byte{}, testPKCS12Pwd)
		if !errors.Is(err, ErrEmptyInput) {
			t.Errorf("ParsePKCS12() error = %v, want ErrEmptyInput", err)
		}
	})
}

func TestMetadataHelpers(t *testing.T) {
	t.Run("IsExpired on valid cert", func(t *testing.T) {
		m, err := ParseX509(testX509Valid)
		if err != nil {
			t.Fatal(err)
		}
		if m.IsExpired() {
			t.Error("IsExpired() = true, want false for valid cert")
		}
	})

	t.Run("IsExpired on expired cert", func(t *testing.T) {
		m, err := ParseX509(testX509Expired)
		if err != nil {
			t.Fatal(err)
		}
		if !m.IsExpired() {
			t.Error("IsExpired() = false, want true for expired cert")
		}
	})

	t.Run("DaysUntilExpiry on valid cert", func(t *testing.T) {
		m, err := ParseX509(testX509Valid)
		if err != nil {
			t.Fatal(err)
		}
		if m.DaysUntilExpiry() <= 0 {
			t.Errorf("DaysUntilExpiry() = %d, want > 0", m.DaysUntilExpiry())
		}
	})

	t.Run("DaysUntilExpiry on expired cert", func(t *testing.T) {
		m, err := ParseX509(testX509Expired)
		if err != nil {
			t.Fatal(err)
		}
		if m.DaysUntilExpiry() >= 0 {
			t.Errorf("DaysUntilExpiry() = %d, want < 0", m.DaysUntilExpiry())
		}
	})

	t.Run("helpers on non-X509 metadata", func(t *testing.T) {
		m := &Metadata{}
		if m.IsExpired() {
			t.Error("IsExpired() should be false on empty Metadata")
		}
		if m.DaysUntilExpiry() != 0 {
			t.Errorf("DaysUntilExpiry() = %d, want 0", m.DaysUntilExpiry())
		}
	})
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantFormat Format
		parseFn    func([]byte) (*Metadata, error)
	}{
		{"X.509 certificate → ParseX509", testX509Valid, FormatX509PEM, func(d []byte) (*Metadata, error) { return ParseX509(d) }},
		{"SSH RSA private → ParseSSHPrivate", testSSHRSAPriv, FormatSSHPrivate, func(d []byte) (*Metadata, error) { return ParseSSHPrivate(d) }},
		{"SSH Ed25519 private → ParseSSHPrivate", testSSHEd25519Priv, FormatSSHPrivate, func(d []byte) (*Metadata, error) { return ParseSSHPrivate(d) }},
		{"SSH ECDSA private → ParseSSHPrivate", testSSHECDSAPriv, FormatSSHPrivate, func(d []byte) (*Metadata, error) { return ParseSSHPrivate(d) }},
		{"SSH RSA public → ParseSSHPublic", testSSHRSAPub, FormatSSHPublic, func(d []byte) (*Metadata, error) { return ParseSSHPublic(d) }},
		{"SSH Ed25519 public → ParseSSHPublic", testSSHEd25519Pub, FormatSSHPublic, func(d []byte) (*Metadata, error) { return ParseSSHPublic(d) }},
		{"SSH ECDSA public → ParseSSHPublic", testSSHECDSAPub, FormatSSHPublic, func(d []byte) (*Metadata, error) { return ParseSSHPublic(d) }},
		{"PKCS12 → ParsePKCS12", testPKCS12Data, FormatPKCS12, func(d []byte) (*Metadata, error) { return ParsePKCS12(d, testPKCS12Pwd) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Detect first, then parse
			fmt_, err := Detect(tt.data)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if fmt_ != tt.wantFormat {
				t.Fatalf("Detect() = %v, want %v", fmt_, tt.wantFormat)
			}

			m, err := tt.parseFn(tt.data)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if m == nil {
				t.Fatal("Parse() returned nil Metadata")
			}
		})
	}
}
