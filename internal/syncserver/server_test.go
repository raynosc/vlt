package syncserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewServer_HealthzResponds(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "server-test.db")
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	generateTestCert(t, certPath, keyPath)

	s, err := NewServer(ServerConfig{
		Addr:    "localhost:0",
		DBPath:  dbPath,
		TLSCert: certPath,
		TLSKey:  keyPath,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Start server
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenAndServe()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Get the actual address
	actualAddr := s.Addr()
	if actualAddr == "" {
		t.Fatal("server addr is empty")
	}

	// Hit healthz endpoint via HTTPS
	client := testHTTPClient()
	baseURL := "https://" + actualAddr
	resp, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != `{"status":"ok"}` {
		t.Errorf("healthz body = %q, want %q", string(body), `{"status":"ok"}`)
	}

	// Shutdown
	if err := s.Shutdown(); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Check server stopped without error
	select {
	case err := <-errCh:
		if err != nil && err.Error() != "http: Server closed" {
			t.Errorf("server error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestNewServer_ReadyzResponds(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "readyz-test.db")
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	generateTestCert(t, certPath, keyPath)

	s, err := NewServer(ServerConfig{
		Addr:    "localhost:0",
		DBPath:  dbPath,
		TLSCert: certPath,
		TLSKey:  keyPath,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenAndServe()
	}()
	defer func() {
		_ = s.Shutdown()
		<-errCh
	}()

	time.Sleep(100 * time.Millisecond)

	client := testHTTPClient()
	baseURL := "https://" + s.Addr()
	resp, err := client.Get(baseURL + "/readyz")
	if err != nil {
		t.Fatalf("readyz request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("readyz expected 200, got %d", resp.StatusCode)
	}
}

func TestNewServer_TLSConfig(t *testing.T) {
	// Generate temporary self-signed cert for TLS test
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// Generate a simple self-signed cert
	generateTestCert(t, certPath, keyPath)

	dbPath := filepath.Join(tmpDir, "tls-test.db")

	s, err := NewServer(ServerConfig{
		Addr:    "localhost:0",
		DBPath:  dbPath,
		TLSCert: certPath,
		TLSKey:  keyPath,
	})
	if err != nil {
		t.Fatalf("NewServer with TLS failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenAndServe()
	}()
	defer func() {
		_ = s.Shutdown()
		<-errCh
	}()

	time.Sleep(100 * time.Millisecond)

	// TLS connection should work with self-signed cert
	client := testHTTPClient()

	baseURL := "https://" + s.Addr()
	resp, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("TLS healthz request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("TLS healthz expected 200, got %d", resp.StatusCode)
	}
}

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(t *testing.T, certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer certFile.Close()
	_ = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	defer keyFile.Close()
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	_ = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
}

// testHTTPClient returns an http.Client that accepts self-signed certs.
func testHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
}

func TestServerConfig_Defaults(t *testing.T) {
	cfg := DefaultServerConfig()
	if cfg.Addr != "localhost:8443" {
		t.Errorf("default addr = %q, want localhost:8443", cfg.Addr)
	}
	if cfg.DBPath == "" {
		t.Error("default DBPath should not be empty")
	}
}

func TestParseServerConfig_FlagDefaults(t *testing.T) {
	// Reset flags for this test
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)

	cfg := ParseServerConfig()
	if cfg.Addr != "localhost:8443" {
		t.Errorf("default addr = %q, want localhost:8443", cfg.Addr)
	}
	if cfg.DBPath != "sync-server.db" {
		t.Errorf("default DBPath = %q, want sync-server.db", cfg.DBPath)
	}
	if cfg.TLSCert != "" {
		t.Errorf("default TLSCert = %q, want empty", cfg.TLSCert)
	}
	if cfg.TLSKey != "" {
		t.Errorf("default TLSKey = %q, want empty", cfg.TLSKey)
	}
}

func TestParseServerConfig_EnvOverrides(t *testing.T) {
	// Reset flags for this test
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)

	t.Setenv("VLT_SYNC_ADDR", ":9090")
	t.Setenv("VLT_SYNC_DB_PATH", "/custom/path/db.sqlite")
	t.Setenv("VLT_SYNC_TLS_CERT", "/certs/cert.pem")
	t.Setenv("VLT_SYNC_TLS_KEY", "/certs/key.pem")

	cfg := ParseServerConfig()
	if cfg.Addr != ":9090" {
		t.Errorf("env ADDR = %q, want :9090", cfg.Addr)
	}
	if cfg.DBPath != "/custom/path/db.sqlite" {
		t.Errorf("env DB_PATH = %q, want /custom/path/db.sqlite", cfg.DBPath)
	}
	if cfg.TLSCert != "/certs/cert.pem" {
		t.Errorf("env TLS_CERT = %q, want /certs/cert.pem", cfg.TLSCert)
	}
	if cfg.TLSKey != "/certs/key.pem" {
		t.Errorf("env TLS_KEY = %q, want /certs/key.pem", cfg.TLSKey)
	}
}

func TestNewServer_DBPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "perms-test.db")

	s, err := NewServer(ServerConfig{
		Addr:   "localhost:0",
		DBPath: dbPath,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	_ = s.Shutdown()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("expected db permissions 0o600, got 0o%o", perm)
	}
}

func TestServer_ValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "valid.db")

	s, err := NewServer(ServerConfig{
		Addr:   "localhost:0",
		DBPath: dbPath,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	_ = s.Shutdown()
}
