package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PKIKeyPair holds PEM-encoded certificate and private key bytes.
type PKIKeyPair struct {
	CertPEM []byte
	KeyPEM  []byte
}

// GenerateCA creates a self-signed Root Certificate Authority (ECDSA P-256) valid for 10 years.
func GenerateCA(organization string) (*PKIKeyPair, *x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate CA private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate CA serial number: %w", err)
	}

	if organization == "" {
		organization = "vlt Zero-Knowledge Vault"
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   "vlt Root CA",
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return &PKIKeyPair{CertPEM: certPEM, KeyPEM: keyPEM}, &template, priv, nil
}

// GenerateServerCert issues a server TLS certificate signed by the CA, with IP and DNS Subject Alternative Names (SANs).
func GenerateServerCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, hosts []string) (*PKIKeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate server serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: caCert.Subject.Organization,
			CommonName:   "vlt-sync Server",
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year (Apple & RFC 5280 max 398 days)
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// Always ensure localhost / 127.0.0.1 are present
	template.DNSNames = append(template.DNSNames, "localhost")
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create server certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal server private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return &PKIKeyPair{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// GenerateClientCert issues a client TLS certificate signed by the CA for mTLS mutual authentication.
func GenerateClientCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, clientName string) (*PKIKeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate client private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate client serial number: %w", err)
	}

	if clientName == "" {
		clientName = "vlt-client"
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: caCert.Subject.Organization,
			CommonName:   clientName,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create client certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal client private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return &PKIKeyPair{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// GenerateFullPKISet generates a complete mTLS PKI set (CA, Server cert, and Client cert) and saves them to dir.
func GenerateFullPKISet(outDir string, hosts []string, clientName string) error {
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return fmt.Errorf("create output directory %q: %w", outDir, err)
	}

	caPair, caCert, caKey, err := GenerateCA("vlt Zero-Knowledge Vault")
	if err != nil {
		return err
	}

	serverPair, err := GenerateServerCert(caCert, caKey, hosts)
	if err != nil {
		return err
	}

	clientPair, err := GenerateClientCert(caCert, caKey, clientName)
	if err != nil {
		return err
	}

	files := map[string][]byte{
		"ca.pem":         caPair.CertPEM,
		"ca-key.pem":     caPair.KeyPEM,
		"server.pem":     serverPair.CertPEM,
		"server-key.pem": serverPair.KeyPEM,
		"client.pem":     clientPair.CertPEM,
		"client-key.pem": clientPair.KeyPEM,
	}

	for name, data := range files {
		path := filepath.Join(outDir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			return fmt.Errorf("write %q: %w", path, err)
		}
	}

	return nil
}
