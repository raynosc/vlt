package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/config"
)

func newQuickCmd() *cobra.Command {
	var socketPath string

	cmd := &cobra.Command{
		Use:   "quick",
		Short: "Open floating search window to quickly copy a secret",
		Long: `Open a compact search-as-you-type window to quickly find and copy
a secret value to the clipboard.

Connects to the vlt daemon (auto-starting it if needed) and presents
an interactive TUI for searching and selecting secrets.

This is a lightweight alternative to the full TUI browser for
quick copy operations.

Examples:
  vlt quick                              # default socket /tmp/vlt.sock
  vlt quick --socket /tmp/myapp.sock     # custom socket path`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuick(socketPath)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", "", "Unix socket path")
	return cmd
}

func runQuick(socketPath string) error {
	if socketPath == "" {
		var err error
		socketPath, err = config.DefaultSocketPath()
		if err != nil {
			return fmt.Errorf("error: socket path: %w", err)
		}
	}
	// Find the vlt-quick binary
	binPath, err := findVltQuickBinary()
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	// Build args
	args := []string{"--socket", socketPath}

	// Create the command — inherit stdin/stdout/stderr for TUI
	qc := exec.Command(binPath, args...)
	qc.Stdin = os.Stdin
	qc.Stdout = os.Stdout
	qc.Stderr = os.Stderr

	if err := qc.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Pass through the exit code from vlt-quick
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("vlt-quick: %w", err)
	}

	return nil
}

const quickBinaryName = "vlt-quick"

// findVltQuickBinary locates the vlt-quick binary, checking next to vlt first,
// then the system PATH.
func findVltQuickBinary() (string, error) {
	// Check the same directory as the current vlt binary
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		candidate := filepath.Join(dir, quickBinaryName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		// macOS binaries sometimes end with no extension
		// Try without extension check
		if _, err := os.Stat(filepath.Join(dir, quickBinaryName)); err == nil {
			return filepath.Join(dir, quickBinaryName), nil
		}
	}

	// Fall back to PATH lookup
	path, err := exec.LookPath(quickBinaryName)
	if err != nil {
		return "", fmt.Errorf("vlt-quick not found (install vlt-quick or build it)")
	}
	return path, nil
}
