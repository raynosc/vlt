package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPKI_CLIGenerateAndClient(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vlt-cli-pki-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rootCmd := newRootCmd()

	// 1. Test generate
	rootCmd.SetArgs([]string{"pki", "generate", "--out", tmpDir, "--hosts", "192.168.0.104,vault.local", "--client", "mac-main"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("pki generate failed: %v", err)
	}

	expectedFiles := []string{
		"ca.pem", "ca-key.pem",
		"server.pem", "server-key.pem",
		"client.pem", "client-key.pem",
	}
	for _, f := range expectedFiles {
		p := filepath.Join(tmpDir, f)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file %s to exist: %v", f, err)
		}
	}

	// 2. Test client issuance
	caCert := filepath.Join(tmpDir, "ca.pem")
	caKey := filepath.Join(tmpDir, "ca-key.pem")
	rootCmd.SetArgs([]string{"pki", "client", "--ca", caCert, "--ca-key", caKey, "--name", "windows-pc", "--out", tmpDir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("pki client failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "windows-pc.pem")); err != nil {
		t.Errorf("expected windows-pc.pem to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "windows-pc-key.pem")); err != nil {
		t.Errorf("expected windows-pc-key.pem to exist: %v", err)
	}
}
