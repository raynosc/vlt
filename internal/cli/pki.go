package cli

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
)

func newPKICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pki",
		Short: "Manage mTLS PKI certificates (CA, Server, Client)",
		Long: `Generate and manage Private Key Infrastructure (PKI) for Zero-Trust mTLS sync.
Creates self-signed root CA, server certificates with IP/DNS SANs, and client certificates.`,
	}

	cmd.AddCommand(newPKIGenerateCmd())
	cmd.AddCommand(newPKIClientCmd())

	return cmd
}

func newPKIGenerateCmd() *cobra.Command {
	var outDir string
	var hosts string
	var clientName string

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate complete mTLS PKI set (CA, Server, Client)",
		Example: `  vlt pki generate --out ~/.config/passwd/certs --hosts "192.168.0.104,localhost"
  vlt pki generate --out ./certs --hosts "10.0.0.5,sync.vault.internal" --client "macbook"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			hostList := strings.Split(hosts, ",")
			if err := crypto.GenerateFullPKISet(outDir, hostList, clientName); err != nil {
				return fmt.Errorf("generate PKI: %w", err)
			}

			fmt.Fprintf(os.Stderr, "✅ Full mTLS PKI generated successfully in: %s\n\n", outDir)
			fmt.Fprintf(os.Stderr, "Files generated:\n")
			fmt.Fprintf(os.Stderr, "  • ca.pem          — Root Certificate Authority (deploy to server & all clients)\n")
			fmt.Fprintf(os.Stderr, "  • ca-key.pem      — CA Private Key (KEEP SECURE / OFFLINE)\n")
			fmt.Fprintf(os.Stderr, "  • server.pem      — Server TLS Certificate\n")
			fmt.Fprintf(os.Stderr, "  • server-key.pem  — Server TLS Private Key\n")
			fmt.Fprintf(os.Stderr, "  • client.pem      — Client mTLS Certificate (%s)\n", clientName)
			fmt.Fprintf(os.Stderr, "  • client-key.pem  — Client mTLS Private Key\n\n")
			fmt.Fprintf(os.Stderr, "🚀 How to start vlt-sync with mTLS:\n")
			fmt.Fprintf(os.Stderr, "  vlt-sync --addr=:8443 \\\n")
			fmt.Fprintf(os.Stderr, "           --tls-cert=%s/server.pem \\\n", outDir)
			fmt.Fprintf(os.Stderr, "           --tls-key=%s/server-key.pem \\\n", outDir)
			fmt.Fprintf(os.Stderr, "           --tls-client-ca=%s/ca.pem\n\n", outDir)
			fmt.Fprintf(os.Stderr, "🔒 How to configure client with mTLS:\n")
			fmt.Fprintf(os.Stderr, "  export VLT_SYNC_CA_CERT=%s/ca.pem\n", outDir)
			fmt.Fprintf(os.Stderr, "  export VLT_SYNC_CLIENT_CERT=%s/client.pem\n", outDir)
			fmt.Fprintf(os.Stderr, "  export VLT_SYNC_CLIENT_KEY=%s/client-key.pem\n", outDir)
			fmt.Fprintf(os.Stderr, "  vlt sync init --server https://192.168.0.104:8443\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&outDir, "out", "./certs", "Output directory for generated PEM files")
	cmd.Flags().StringVar(&hosts, "hosts", "localhost,127.0.0.1", "Comma-separated list of hostnames and IP addresses for server SANs")
	cmd.Flags().StringVar(&clientName, "client", "client-default", "Name for initial client certificate")

	return cmd
}

func newPKIClientCmd() *cobra.Command {
	var caCertPath string
	var caKeyPath string
	var clientName string
	var outDir string

	cmd := &cobra.Command{
		Use:     "client",
		Short:   "Issue an additional client certificate signed by existing CA",
		Example: `  vlt pki client --ca ./certs/ca.pem --ca-key ./certs/ca-key.pem --name "windows-laptop" --out ./certs`,
		RunE: func(cmd *cobra.Command, args []string) error {
			caCertData, err := os.ReadFile(caCertPath)
			if err != nil {
				return fmt.Errorf("read CA cert: %w", err)
			}
			block, _ := pem.Decode(caCertData)
			if block == nil {
				return fmt.Errorf("invalid CA cert PEM format")
			}
			caCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("parse CA cert: %w", err)
			}

			caKeyData, err := os.ReadFile(caKeyPath)
			if err != nil {
				return fmt.Errorf("read CA key: %w", err)
			}
			keyBlock, _ := pem.Decode(caKeyData)
			if keyBlock == nil {
				return fmt.Errorf("invalid CA key PEM format")
			}
			var caKey *ecdsa.PrivateKey
			if keyBlock.Type == "EC PRIVATE KEY" {
				caKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
				if err != nil {
					return fmt.Errorf("parse EC CA key: %w", err)
				}
			} else {
				parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
				if err != nil {
					return fmt.Errorf("parse PKCS8 CA key: %w", err)
				}
				var ok bool
				caKey, ok = parsedKey.(*ecdsa.PrivateKey)
				if !ok {
					return fmt.Errorf("CA key must be ECDSA")
				}
			}

			clientPair, err := crypto.GenerateClientCert(caCert, caKey, clientName)
			if err != nil {
				return fmt.Errorf("generate client cert: %w", err)
			}

			if err := os.MkdirAll(outDir, 0700); err != nil {
				return fmt.Errorf("create out dir: %w", err)
			}

			certFile := filepath.Join(outDir, fmt.Sprintf("%s.pem", clientName))
			keyFile := filepath.Join(outDir, fmt.Sprintf("%s-key.pem", clientName))

			if err := os.WriteFile(certFile, clientPair.CertPEM, 0600); err != nil {
				return fmt.Errorf("write client cert: %w", err)
			}
			if err := os.WriteFile(keyFile, clientPair.KeyPEM, 0600); err != nil {
				return fmt.Errorf("write client key: %w", err)
			}

			fmt.Fprintf(os.Stderr, "✅ Issued client mTLS certificate: %s\n", certFile)
			fmt.Fprintf(os.Stderr, "   Private key: %s\n", keyFile)

			return nil
		},
	}

	cmd.Flags().StringVar(&caCertPath, "ca", "./certs/ca.pem", "Path to CA certificate PEM")
	cmd.Flags().StringVar(&caKeyPath, "ca-key", "./certs/ca-key.pem", "Path to CA private key PEM")
	cmd.Flags().StringVar(&clientName, "name", "client-device", "Name / Common Name for the client")
	cmd.Flags().StringVar(&outDir, "out", "./certs", "Output directory for client certificate")

	return cmd
}
