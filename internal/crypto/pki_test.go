package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestPKIGeneration_ValidHierarchy(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	hosts := []string{"192.168.0.104", "vault.local"}
	err = GenerateFullPKISet(tmpDir, hosts, "test-client")
	if err != nil {
		t.Fatalf("GenerateFullPKISet failed: %v", err)
	}

	caCertPath := filepath.Join(tmpDir, "ca.pem")
	serverCertPath := filepath.Join(tmpDir, "server.pem")
	serverKeyPath := filepath.Join(tmpDir, "server-key.pem")
	clientCertPath := filepath.Join(tmpDir, "client.pem")
	clientKeyPath := filepath.Join(tmpDir, "client-key.pem")

	// Verify server cert can be loaded
	serverTLSCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatalf("load server key pair: %v", err)
	}
	if len(serverTLSCert.Certificate) == 0 {
		t.Fatalf("server cert empty")
	}

	// Verify client cert can be loaded
	clientTLSCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("load client key pair: %v", err)
	}
	if len(clientTLSCert.Certificate) == 0 {
		t.Fatalf("client cert empty")
	}

	// Verify CA parses and validates both certs
	caData, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read ca: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		t.Fatalf("failed to append ca cert")
	}

	serverCert, err := x509.ParseCertificate(serverTLSCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	_, err = serverCert.Verify(x509.VerifyOptions{
		Roots:   pool,
		DNSName: "vault.local",
	})
	if err != nil {
		t.Fatalf("server cert verify failed for vault.local: %v", err)
	}

	clientCert, err := x509.ParseCertificate(clientTLSCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	_, err = clientCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("client cert verify failed: %v", err)
	}
}
