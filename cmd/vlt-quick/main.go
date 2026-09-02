// Command vlt-quick provides a floating search window for the vlt secrets manager.
//
// It connects to the vlt daemon via Unix socket, presents a compact search-as-you-type
// TUI, and copies the selected secret value to the clipboard.
//
// Usage:
//
//	vlt-quick [--socket <path>]
//
// If --socket is not specified, config.DefaultSocketPath() is used.
// If the daemon is not running, vlt-quick auto-starts it in the background.
// If the daemon is locked, it prompts for the master password.
//
// Exit codes:
//   - 0: secret copied to clipboard
//   - 1: cancelled (Esc pressed)
//   - 2: error
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/raynosc/vlt/internal/cli"
	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/quick"
)

// ── JSON protocol types (subset of daemon.Request/Response) ──

type daemonRequest struct {
	Cmd      string `json:"cmd"`
	Password string `json:"password,omitempty"`
	Name     string `json:"name,omitempty"`
}

type daemonResponse struct {
	Status  string                   `json:"status"`
	Message string                   `json:"message,omitempty"`
	Version string                   `json:"version,omitempty"`
	Name    string                   `json:"name,omitempty"`
	Value   string                   `json:"value,omitempty"`
	Secrets []map[string]interface{} `json:"secrets,omitempty"`
}

// ── CLI flags ──

var (
	vaultFlag   = flag.String("vault", "", "vault name (e.g. --vault work)")
	socketFlag  = flag.String("socket", "", "Unix socket path for daemon")
	daemonPath  = flag.String("vlt-bin", "", "path to vlt binary (auto-detect if empty)")
	timeoutFlag = flag.Int("timeout", 2, "auto-close inactivity timeout in minutes (0 = never)")
)

func main() {
	flag.Parse()

	os.Exit(run())
}

func run() int {
	selectedVault := *vaultFlag

	// If no vault flag was passed, default to the configured active vault or default vault
	if selectedVault == "" {
		cfg, _ := config.Load()
		if cfg != nil && cfg.ActiveVault != "" {
			selectedVault = cfg.ActiveVault
		} else {
			selectedVault = "vault"
		}
	}

	socketPath := *socketFlag
	if socketPath == "" {
		if selectedVault != "" && selectedVault != "vault" {
			socketPath = fmt.Sprintf("/tmp/vlt-%s.sock", selectedVault)
		} else {
			var err error
			socketPath, err = config.DefaultSocketPath()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: socket path: %v\n", err)
				return cli.ExitQuickErr
			}
		}
	}

	// Resolve vlt binary path for daemon auto-start
	vltBin := *daemonPath
	if vltBin == "" {
		var err error
		vltBin, err = findVltBinary()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot find vlt binary: %v\n", err)
			return cli.ExitQuickErr
		}
	}

	// Connect to daemon (auto-start if not running)
	conn, err := connectOrStartDaemon(socketPath, vltBin, selectedVault)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}
	defer func() { _ = conn.Close() }()

	// Ping daemon to verify it's responsive
	if err := pingDaemon(conn); err != nil {
		fmt.Fprintf(os.Stderr, "Error: daemon not responding: %v\n", err)
		return 2
	}

	// List secrets — may need to unlock first
	secrets, err := listSecretsWithUnlock(conn, selectedVault)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}

	if len(secrets) == 0 {
		fmt.Fprintln(os.Stderr, "No secrets found in vault.")
		return cli.ExitErr
	}

	// Convert to quick.SecretInfo
	secretInfos := make([]quick.SecretInfo, len(secrets))
	for i, s := range secrets {
		name, _ := s["name"].(string)
		kind, _ := s["kind"].(string)
		secretInfos[i] = quick.SecretInfo{Name: name, Kind: kind}
	}

	// onSelect: get secret from daemon, copy to clipboard
	onSelect := func(name string) error {
		return getAndCopy(conn, name, vltBin)
	}

	// Create and run the Bubble Tea program
	m := quick.NewModelWithVaultAndTimeout(secretInfos, onSelect, selectedVault, *timeoutFlag)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}

	// Determine exit code from model state
	if m.Copied() {
		return cli.ExitOK
	}
	return 1
}

// ── Daemon connection ──

// connectOrStartDaemon tries to connect to the daemon socket.
// If the connection fails, it auto-starts the daemon and waits for it.
func connectOrStartDaemon(socketPath, vltBin, vaultName string) (net.Conn, error) {
	// First attempt: try connecting directly
	conn, err := dialSocket(socketPath, 200*time.Millisecond)
	if err == nil {
		return conn, nil
	}

	// Daemon not running — auto-start it
	fmt.Fprintf(os.Stderr, "Starting daemon...\n")
	if err := startDaemon(socketPath, vltBin, vaultName); err != nil {
		return nil, fmt.Errorf("start daemon: %w", err)
	}

	// Wait for daemon to be ready (poll socket)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		conn, err = dialSocket(socketPath, 200*time.Millisecond)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Daemon ready.\n")
			return conn, nil
		}
	}

	return nil, fmt.Errorf("daemon did not start: %w", err)
}

// dialSocket attempts to establish a Unix socket connection with a timeout.
func dialSocket(socketPath string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// startDaemon launches the vlt daemon as a background process.
// It removes any stale socket file first, then starts the daemon.
// startDaemon launches the vlt daemon as a background process.
// It removes any stale socket file first, then starts the daemon.
func startDaemon(socketPath, vltBin, vaultName string) error {
	// Remove stale socket if present
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	var args []string
	args = append(args, "daemon", "--socket", socketPath)
	if vaultName != "" {
		args = append(args, "--vault", vaultName)
	}

	cmd := exec.Command(vltBin, args...)

	// Capture stderr for diagnostics but don't wait for it
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch daemon: %w", err)
	}

	// Read stderr in background and reap the child process.
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			// Forward daemon log messages to our stderr
			fmt.Fprintf(os.Stderr, "daemon: %s\n", scanner.Text())
		}
		_ = cmd.Wait()
	}()

	return nil
}

// findVltBinary locates the vlt binary, checking the current directory
// and then the system PATH.
func findVltBinary() (string, error) {
	// Check the directory of the current executable first
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		candidate := filepath.Join(dir, "vlt")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		// Check for vlt.exe on Windows
		candidate = filepath.Join(dir, "vlt.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// Fall back to PATH lookup
	path, err := exec.LookPath("vlt")
	if err != nil {
		return "", fmt.Errorf("vlt not found on PATH (install vlt or set --vlt-bin)")
	}
	return path, nil
}

// ── Daemon protocol ──

// sendCommand writes a JSON command to the daemon and reads the response.
func sendCommand(conn net.Conn, req daemonRequest) (daemonResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return daemonResponse{}, fmt.Errorf("marshal request: %w", err)
	}

	// Set a write deadline
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return daemonResponse{}, fmt.Errorf("set write deadline: %w", err)
	}

	if _, err := conn.Write(append(data, '\n')); err != nil {
		return daemonResponse{}, fmt.Errorf("write: %w", err)
	}

	// Read response
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return daemonResponse{}, fmt.Errorf("set read deadline: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return daemonResponse{}, fmt.Errorf("read: %w", err)
		}
		return daemonResponse{}, errors.New("daemon closed connection")
	}

	var resp daemonResponse
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return daemonResponse{}, fmt.Errorf("parse response: %w", err)
	}

	return resp, nil
}

// requireOK checks that the daemon response has status "ok".
func requireOK(resp daemonResponse) error {
	if resp.Status != "ok" {
		msg := resp.Message
		if msg == "" {
			msg = "unknown daemon error"
		}
		return errors.New(msg)
	}
	return nil
}

// pingDaemon sends a ping command to verify the daemon is responsive.
func pingDaemon(conn net.Conn) error {
	resp, err := sendCommand(conn, daemonRequest{Cmd: "ping"})
	if err != nil {
		return err
	}
	return requireOK(resp)
}

// listSecretsWithUnlock tries to list secrets, and prompts for the master
// password if the daemon reports the vault is locked.
func listSecretsWithUnlock(conn net.Conn, vaultName string) ([]map[string]interface{}, error) {
	resp, err := sendCommand(conn, daemonRequest{Cmd: "list"})
	if err != nil {
		return nil, err
	}

	if resp.Status == "ok" {
		return resp.Secrets, nil
	}

	// If vault is locked, prompt for password and unlock
	if resp.Message == "vault is locked" {
		if err := unlockDaemon(conn, vaultName); err != nil {
			return nil, err
		}

		// Retry list after unlock
		resp, err = sendCommand(conn, daemonRequest{Cmd: "list"})
		if err != nil {
			return nil, err
		}
		if err := requireOK(resp); err != nil {
			return nil, fmt.Errorf("list after unlock: %w", err)
		}
		return resp.Secrets, nil
	}

	return nil, fmt.Errorf("list failed: %s", resp.Message)
}

// unlockDaemon prompts for the master password and sends the unlock command.
func unlockDaemon(conn net.Conn, vaultName string) error {
	if vaultName != "" {
		fmt.Fprintf(os.Stderr, "Unlock Vault: %s\n", vaultName)
	}
	fmt.Fprint(os.Stderr, "Master password: ")
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	if len(pw) == 0 {
		return errors.New("password cannot be empty")
	}

	resp, err := sendCommand(conn, daemonRequest{
		Cmd:      "unlock",
		Password: string(pw),
	})
	if err != nil {
		return err
	}
	if err := requireOK(resp); err != nil {
		return fmt.Errorf("unlock: %w", err)
	}

	return nil
}

// getAndCopy retrieves a secret value from the daemon and copies it to clipboard.
func getAndCopy(conn net.Conn, name string, vltBin string) error {
	resp, err := sendCommand(conn, daemonRequest{
		Cmd:  "get",
		Name: name,
	})
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}
	if err := requireOK(resp); err != nil {
		return fmt.Errorf("get secret %q: %w", name, err)
	}

	if resp.Value == "" {
		return fmt.Errorf("secret %q has empty value", name)
	}

	if err := clipboard.WriteAll(resp.Value); err != nil {
		return fmt.Errorf("clipboard: %w", err)
	}

	// Spawn the detached auto-clear subprocess of the vlt binary.
	// The secret is delivered via stdin (S-06), not argv.
	cli.StartClipboardAutoClearForBinary(vltBin, resp.Value)

	return nil
}
