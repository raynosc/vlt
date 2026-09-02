package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/daemon"
)

func newDaemonCmd() *cobra.Command {
	var socketPath string
	var timeoutMinutes int

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Start the vlt daemon (Unix socket JSON listener)",
		Long: `Start the vlt daemon that listens on a Unix domain socket
for newline-delimited JSON command requests.

The daemon opens the vault and waits for commands over a Unix socket.
It auto-locks after a configurable inactivity timeout.

Commands:
  ping       {"cmd":"ping"}
  unlock     {"cmd":"unlock","password":"..."}
  lock       {"cmd":"lock"}
  list       {"cmd":"list"}
  get        {"cmd":"get","name":"..."}
  add        {"cmd":"add","name":"...","value":"...","kind":"password"}
  generate   {"cmd":"generate","length":24}
  shutdown   {"cmd":"shutdown"}

Examples:
  vlt daemon                              # default socket /tmp/vlt.sock
  vlt daemon --socket /tmp/myapp.sock     # custom socket path
  vlt daemon --timeout 10                 # 10 min inactivity timeout`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon(cmd, socketPath, timeoutMinutes)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", "", "Unix socket path")
	cmd.Flags().IntVar(&timeoutMinutes, "timeout", 5, "auto-lock inactivity timeout in minutes (0 = never)")

	return cmd
}

func runDaemon(cmd *cobra.Command, socketPath string, timeoutMinutes int) error {
	// Resolve default socket path if not specified
	if socketPath == "" {
		var err error
		socketPath, err = config.DefaultSocketPath()
		if err != nil {
			return fmt.Errorf("error: socket path: %w", err)
		}
	}
	// Resolve vault path using the same logic as other commands
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	if err := requireVaultExists(vaultPath); err != nil {
		return err
	}

	// Open store
	s, err := openStore(vaultPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = s.Close()
	}()

	// Read salt and verify hash
	salt, err := s.ConfigGet(configKeySalt)
	if err != nil {
		return vaultMissingHint(fmt.Errorf("read salt: %w", err))
	}

	verifyHash, err := s.ConfigGet(configKeyVerifyHash)
	if err != nil {
		return vaultMissingHint(fmt.Errorf("read verify hash: %w", err))
	}

	// Create daemon
	timeout := time.Duration(timeoutMinutes) * time.Minute
	d := daemon.New(s, engine, salt, verifyHash, socketPath, timeout)

	fmt.Fprintf(os.Stderr, "vlt daemon listening on %s (timeout: %dm)\n", socketPath, timeoutMinutes)
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop.\n")

	// Run daemon (blocks until shutdown)
	if err := d.Run(); err != nil {
		return fmt.Errorf("daemon: %w", err)
	}

	return nil
}
