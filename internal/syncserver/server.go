package syncserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ServerConfig configures the sync server.
type ServerConfig struct {
	// Addr is the listen address, e.g. ":8443" or "localhost:8443".
	Addr string
	// DBPath is the path to the SQLite database file.
	DBPath string
	// TLSCert is the path to the TLS certificate PEM file.
	// If empty, the server runs without TLS (HTTP).
	TLSCert string
	// TLSKey is the path to the TLS private key PEM file.
	// If empty, the server runs without TLS (HTTP).
	TLSKey string
	// TLSClientCA is the path to the Client CA certificate PEM file for mTLS.
	// If set, the server requires and verifies client certificates (Zero-Trust mTLS).
	TLSClientCA string
}

// ParseServerConfig parses command-line flags and environment variables.
// Flags override defaults; environment variables override flags.
func ParseServerConfig() *ServerConfig {
	cfg := DefaultServerConfig()

	flag.StringVar(&cfg.Addr, "addr", cfg.Addr, "listen address")
	flag.StringVar(&cfg.DBPath, "db-path", cfg.DBPath, "SQLite database path")
	flag.StringVar(&cfg.TLSCert, "tls-cert", cfg.TLSCert, "TLS certificate PEM file")
	flag.StringVar(&cfg.TLSKey, "tls-key", cfg.TLSKey, "TLS private key PEM file")
	flag.StringVar(&cfg.TLSClientCA, "tls-client-ca", cfg.TLSClientCA, "Client CA certificate PEM file for mTLS")
	flag.Parse()

	// Environment variable overrides (after flags so env can override)
	if v := os.Getenv(envSyncAddr); v != "" {
		cfg.Addr = v
	}
	if v := os.Getenv(envSyncDBPath); v != "" {
		cfg.DBPath = v
	}
	if v := os.Getenv(envSyncTLSCert); v != "" {
		cfg.TLSCert = v
	}
	if v := os.Getenv(envSyncTLSKey); v != "" {
		cfg.TLSKey = v
	}
	if v := os.Getenv(envSyncTLSClientCA); v != "" {
		cfg.TLSClientCA = v
	}

	return cfg
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Addr:   "localhost:8443",
		DBPath: "sync-server.db",
	}
}

// Server wraps the HTTP server and store.
type Server struct {
	mu        sync.RWMutex
	http      *http.Server
	store     *ServerStore
	listener  net.Listener
	boundAddr string
	cfg       ServerConfig
	auth      *AuthMiddleware
}

// NewServer creates a new Server with the given config.
// It initializes the store and configures HTTP routes.
func NewServer(cfg ServerConfig) (*Server, error) {
	// Ensure DB directory exists
	dbDir := filepath.Dir(cfg.DBPath)
	if dbDir != "." && dbDir != "/" {
		if err := os.MkdirAll(dbDir, 0o700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}

	// Remember if the DB file existed before Init so we can chmod new files.
	_, dbExisted := os.Stat(cfg.DBPath)

	store := NewServerStore()
	if err := store.Init(cfg.DBPath); err != nil {
		return nil, fmt.Errorf("init store: %w", err)
	}

	// Restrict newly created database files to owner-only read/write.
	if dbExisted != nil {
		_ = os.Chmod(cfg.DBPath, 0o600)
	}

	auth := NewAuthMiddleware(store)
	auth.StartCleanup()
	mux := NewHandlerMux(store, auth)

	httpServer := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &Server{
		http:      httpServer,
		store:     store,
		cfg:       cfg,
		boundAddr: cfg.Addr,
		auth:      auth,
	}, nil
}

// ListenAndServe starts the HTTPS server and blocks until Shutdown is called.
// TLS is MANDATORY — returns an error if no cert and key are configured.
func (s *Server) ListenAndServe() error {
	if s.cfg.TLSCert == "" || s.cfg.TLSKey == "" {
		return fmt.Errorf("TLS is mandatory: provide --tls-cert and --tls-key or set VLT_SYNC_TLS_CERT / VLT_SYNC_TLS_KEY")
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if s.cfg.TLSClientCA != "" {
		caData, err := os.ReadFile(s.cfg.TLSClientCA)
		if err != nil {
			return fmt.Errorf("read client CA %q: %w", s.cfg.TLSClientCA, err)
		}
		clientCAPool := x509.NewCertPool()
		if !clientCAPool.AppendCertsFromPEM(caData) {
			return fmt.Errorf("failed to parse client CA from %q", s.cfg.TLSClientCA)
		}
		tlsConfig.ClientCAs = clientCAPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("load TLS cert/key: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	s.http.TLSConfig = tlsConfig

	listener, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	addrStr := listener.Addr().String()

	s.mu.Lock()
	s.listener = listener
	s.boundAddr = addrStr
	s.mu.Unlock()

	tlsListener := tls.NewListener(listener, tlsConfig)
	return s.http.Serve(tlsListener)
}

// Shutdown gracefully shuts down the server and closes the store.
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("http shutdown: %w", err)
	}

	s.mu.Lock()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.mu.Unlock()

	// Stop background goroutines
	if s.auth != nil {
		s.auth.StopCleanup()
	}

	if err := s.store.Close(); err != nil {
		return fmt.Errorf("store close: %w", err)
	}

	return nil
}

// Addr returns the address the server is listening on.
// Useful when using ":0" for random port assignment.
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.boundAddr
}
