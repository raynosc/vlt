// Command vlt-gui provides a native desktop GUI for the vlt password manager.
//
// Built with Fyne v2 — a pure Go cross-platform GUI toolkit.
// Runs in the system tray with a main window for managing secrets.
//
// Usage:
//
//	vlt-gui [--vault <name>] [--no-keychain] [--socket /tmp/vlt.sock]
//
// Screens:
//   - Unlock: master password entry
//   - List: scrollable secret list with search
//   - Detail: view secret, reveal value, TOTP codes
//   - Add/Edit: create or modify secrets
//   - Settings: vault info, keychain status, discovered vaults
//
// Build:
//
//	go build -o vlt-gui ./cmd/vlt-gui
//
// Dependencies (installed automatically):
//   - fyne.io/fyne/v2
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/raynosc/vlt/internal/cli"
	"github.com/raynosc/vlt/internal/gui"
)

func main() {
	vaultName := flag.String("vault", "", "vault name (e.g. --vault work)")
	noKeychain := flag.Bool("no-keychain", false, "skip macOS Keychain auto-unlock")
	socketPath := flag.String("socket", "", "Unix socket path for daemon")
	quick := flag.Bool("quick", false, "launch in quick access popup mode")
	minimized := flag.Bool("minimized", false, "start minimized in system tray without opening window")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *version {
		fmt.Println("vlt-gui version", gui.Version)
		os.Exit(cli.ExitOK)
	}

	if *quick {
		gui.RunQuick(*vaultName, *noKeychain)
		return
	}

	gui.Run(*vaultName, *noKeychain, *socketPath, *minimized)
}
