package syncserver_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/syncserver"
)

func TestMTLS_MutualAuthentication(t *testing.T) {
	// 1. Generate PKI for test
	tmpDir, err := os.MkdirTemp("", "vlt-mtls-test-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	err = crypto.GenerateFullPKISet(tmpDir, []string{"127.0.0.1", "localhost"}, "test-client")
	if err != nil {
		t.Fatalf("GenerateFullPKISet: %v", err)
	}

	caCertPath := filepath.Join(tmpDir, "ca.pem")
	serverCertPath := filepath.Join(tmpDir, "server.pem")
	serverKeyPath := filepath.Join(tmpDir, "server-key.pem")
	clientCertPath := filepath.Join(tmpDir, "client.pem")
	clientKeyPath := filepath.Join(tmpDir, "client-key.pem")

	// 2. Start syncserver with mTLS enabled
	dbPath := filepath.Join(tmpDir, "server.db")
	cfg := syncserver.ServerConfig{
		Addr:        "127.0.0.1:0", // Random port
		DBPath:      dbPath,
		TLSCert:     serverCertPath,
		TLSKey:      serverKeyPath,
		TLSClientCA: caCertPath, // Enables mTLS
	}

	server, err := syncserver.NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go func() {
		_ = server.ListenAndServe()
	}()
	defer func() { _ = server.Shutdown() }()

	// Wait for server to bind listener
	var serverAddr string
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		if addr := server.Addr(); addr != "127.0.0.1:0" && addr != "" {
			serverAddr = addr
			break
		}
	}
	if serverAddr == "" {
		t.Fatalf("server failed to start listening")
	}

	baseURL := fmt.Sprintf("https://%s", serverAddr)

	// Load CA pool for client trust
	caData, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read ca: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	// Scenario A: Client WITHOUT client certificate -> MUST FAIL TLS handshake
	clientNoCert := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
		Timeout: 3 * time.Second,
	}

	_, err = clientNoCert.Get(baseURL + "/healthz")
	if err == nil {
		t.Fatalf("expected mTLS handshake failure for client without cert, but request succeeded")
	}

	// Scenario B: Client WITH VALID client certificate -> MUST SUCCEED
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}

	clientWithCert := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientCert},
			},
		},
		Timeout: 3 * time.Second,
	}

	resp, err := clientWithCert.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("mTLS request with valid client cert failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != `{"status":"ok"}` {
		t.Fatalf("unexpected healthz response: %s", string(body))
	}
}
