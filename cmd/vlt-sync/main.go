// Command vlt-sync starts the sync protocol server.
//
// Usage:
//
//	vlt-sync --addr=:8443 --db-path=./sync.db
//	vlt-sync --addr=:8443 --db-path=./sync.db --tls-cert=./cert.pem --tls-key=./key.pem
//	vlt-sync --addr=:8443 --db-path=./sync.db --tls-cert=./server.pem --tls-key=./server-key.pem --tls-client-ca=./ca.pem
//
// Environment variables (overrides flags):
//
//	VLT_SYNC_ADDR           — listen address
//	VLT_SYNC_DB_PATH        — SQLite database path
//	VLT_SYNC_TLS_CERT       — TLS certificate PEM file
//	VLT_SYNC_TLS_KEY        — TLS private key PEM file
//	VLT_SYNC_TLS_CLIENT_CA  — Client CA PEM file for mTLS
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/raynosc/vlt/internal/cli"
	"github.com/raynosc/vlt/internal/syncserver"
)

func main() {
	cfg := syncserver.ParseServerConfig()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	server, err := syncserver.NewServer(*cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create server: %v\n", err)
		os.Exit(cli.ExitErr)
	}

	log.Printf("Starting sync server on %s", cfg.Addr)
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("TLS enabled: cert=%s", cfg.TLSCert)
	}
	if cfg.TLSClientCA != "" {
		log.Printf("🔒 Zero-Trust mTLS enabled: client_ca=%s (client certificates required)", cfg.TLSClientCA)
	}

	if err := server.ListenAndServe(); err != nil {
		log.Printf("Server stopped: %v", err)
	}
}
