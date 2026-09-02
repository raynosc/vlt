// Command passwd-tui is the Bubble Tea TUI entry point for the passwd secrets manager.
//
// It provides an interactive terminal UI for browsing, searching, and viewing secrets.
// This is a separate binary from the CLI (cmd/passwd).
//
// Usage:
//
//	passwd-tui [--timeout 10] [--vault <name>]
//
// The TUI reads the vault config from the default XDG path, prompts for the master
// password, and opens the secret list view.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/raynosc/vlt/internal/cli"
	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/store"
	"github.com/raynosc/vlt/internal/tui"
)

func main() {
	timeoutMinutes := flag.Int("timeout", 5, "auto-lock inactivity timeout in minutes (0 = never)")
	vaultName := flag.String("vault", "", "vault name (e.g. --vault work uses ~/.config/passwd/work.sqlite)")
	noKeychain := flag.Bool("no-keychain", false, "skip macOS Keychain for this session")
	flag.Parse()

	var vaultPath string

	if *vaultName != "" {
		var err error
		vaultPath, err = config.VaultPathForName(*vaultName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(cli.ExitErr)
		}
	} else {
		// Load vault configuration from XDG path.
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(cli.ExitErr)
		}

		// If config has an active vault name, resolve it
		if cfg.ActiveVault != "" {
			vaultPath, err = config.VaultPathForName(cfg.ActiveVault)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(cli.ExitErr)
			}
		} else {
			vaultPath = cfg.VaultPath
		}
	}

	// Verify the vault database exists.
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: vault not found at %s\n", vaultPath)
		fmt.Fprintf(os.Stderr, "Run 'passwd init' to create a new vault.\n")
		os.Exit(cli.ExitErr)
	}

	// Open the SQLite store.
	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
		os.Exit(cli.ExitErr)
	}
	defer func() {
		_ = st.Close()
	}()

	// Read salt and verify hash from the config table.
	salt, err := st.ConfigGet("salt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: vault does not appear initialized: %v\n", err)
		os.Exit(cli.ExitErr)
	}

	verifyHash, err := st.ConfigGet("verify_hash")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: vault does not appear initialized: %v\n", err)
		os.Exit(cli.ExitErr)
	}

	// Read stored Argon2id parameters from config, falling back to defaults.
	argon2Params := crypto.DefaultArgon2Params
	if timeBytes, err := st.ConfigGet("argon2_time"); err == nil && len(timeBytes) == 4 {
		argon2Params.Time = binary.BigEndian.Uint32(timeBytes)
	}
	if memBytes, err := st.ConfigGet("argon2_memory"); err == nil && len(memBytes) == 4 {
		argon2Params.Memory = binary.BigEndian.Uint32(memBytes)
	}
	if threadBytes, err := st.ConfigGet("argon2_threads"); err == nil && len(threadBytes) == 1 {
		argon2Params.Threads = threadBytes[0]
	}

	// Create the crypto engine with the resolved Argon2id parameters.
	eng := crypto.NewEngine(&argon2Params)

	// Create the TUI model with all dependencies injected.
	m := tui.NewModel(st, eng, salt, verifyHash, *timeoutMinutes, *noKeychain)

	// Set up signal handling for external SIGINT/SIGTERM.
	// Bubble Tea handles Ctrl+C internally, but we need to catch
	// signals sent from outside (e.g., kill, system shutdown).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Create the Bubble Tea program with alternate screen mode.
	p := tea.NewProgram(m, tea.WithAltScreen())

	// Forward external signals to the program for graceful shutdown.
	go func() {
		<-sigCh
		p.Quit()
	}()

	// Run the TUI program.
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(cli.ExitErr)
	}
}
