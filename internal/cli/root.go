// Package cli provides the Cobra command-line interface for passwd.
//
// It wires together the crypto engine and secret storage layers.
// All master password input uses terminal.ReadPassword (never CLI args).
// The session key is cached per process and zeroized on command completion.
package cli

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/term"

	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/keychain"
	"github.com/raynosc/vlt/internal/store"
	"github.com/raynosc/vlt/internal/version"
)

// CLI rate limiting constants.
const (
	cliMaxAttempts    = 5
	cliBaseBackoff    = 1 * time.Second
	cliLockoutMessage = "too many failed attempts, vault locked for 60 seconds"
)

// Config key constants for the store's config table.
const (
	configKeySalt          = "salt"
	configKeyVerifyHash    = "verify_hash"
	configKeyArgon2Time    = "argon2_time"
	configKeyArgon2Memory  = "argon2_memory"
	configKeyArgon2Threads = "argon2_threads"
	configKeyRecoveryBlob  = "recovery_blob"
)

// Version is the current version of vlt. Set at build time with -ldflags.
// Defaults to the shared version constant from internal/version.
var Version = version.Version

// noEnv controls whether PASSWD_MASTER_PASSWORD env var is allowed.
// Set by the --no-env persistent flag on the root command.
var noEnv bool

// vaultName stores the --vault flag value for all subcommands.
var vaultName string

// noKeychain controls whether the macOS Keychain is used.
// Set by the --no-keychain persistent flag on the root command.
var noKeychain bool

// kc is the platform keychain implementation.
// Override in tests with a mock.
var kc keychain.Keychain = keychain.New()

var engine = crypto.NewEngine(nil)

// readArgon2Params reads stored Argon2 parameters from the store config.
// If any key is missing, it falls back to DefaultArgon2Params.
func readArgon2Params(s *store.SQLStore) (*crypto.Argon2Params, error) {
	params := crypto.DefaultArgon2Params

	if timeBytes, err := s.ConfigGet(configKeyArgon2Time); err == nil && len(timeBytes) == 4 {
		params.Time = binary.BigEndian.Uint32(timeBytes)
	}
	if memoryBytes, err := s.ConfigGet(configKeyArgon2Memory); err == nil && len(memoryBytes) == 4 {
		params.Memory = binary.BigEndian.Uint32(memoryBytes)
	}
	if threadsBytes, err := s.ConfigGet(configKeyArgon2Threads); err == nil && len(threadsBytes) == 1 {
		params.Threads = threadsBytes[0]
	}

	return &params, nil
}

// Execute runs the root CLI command.
func Execute() error {
	root := newRootCmd()
	return root.Execute()
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "vlt",
		Version: Version,
		Short:   "A secure, local-first secrets manager",
		Long: `vlt is a secure, local-first secrets manager.

It stores encrypted secrets in a local SQLite vault and provides
CLI and TUI interfaces for managing them.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Capture --no-env flag for master password functions
			if cmd.Flag("no-env") != nil {
				noEnv, _ = cmd.Flags().GetBool("no-env")
			}

			// Validate vault path early (don't open, just resolve)
			if cmd.Flag("vault-path").Changed || cmd.Flag("vault").Changed || vaultName != "" {
				_, err := resolveVaultPath(cmd)
				return err
			}
			return nil
		},
	}

	root.PersistentFlags().Bool("json", false, "output in JSON format")
	root.PersistentFlags().String("vault-path", "", "path to vault database (default: XDG config path)")
	root.PersistentFlags().StringVar(&vaultName, "vault", "", "vault name (e.g. --vault work uses ~/.config/passwd/work.sqlite)")
	root.PersistentFlags().BoolVar(&noEnv, "no-env", false, "ignore PASSWD_MASTER_PASSWORD env var (paranoid mode)")
	root.PersistentFlags().BoolVar(&noKeychain, "no-keychain", false, "skip macOS Keychain for this session")

	root.AddCommand(newInitCmd())
	root.AddCommand(newAddCmd())
	root.AddCommand(newGetCmd())
	root.AddCommand(newListCmd())
	root.AddCommand(newRmCmd())
	root.AddCommand(newSearchCmd())
	root.AddCommand(newInspectCmd())
	root.AddCommand(newEditCmd())
	root.AddCommand(newCheckCmd())
	root.AddCommand(newImportCmd())
	root.AddCommand(newExportCmd())
	root.AddCommand(newGenerateCmd())
	root.AddCommand(newVaultCmd())
	root.AddCommand(newAuditCmd())
	root.AddCommand(newDaemonCmd())
	root.AddCommand(newTotpCmd())
	root.AddCommand(newKeychainCmd())
	root.AddCommand(newLockCmd())
	root.AddCommand(newQuickCmd())
	root.AddCommand(newSyncCmd())
	root.AddCommand(newPINCmd())
	root.AddCommand(newRecoveryCmd())
	root.AddCommand(newDevicesCmd())
	root.AddCommand(newPKICmd())
	root.AddCommand(newClearClipboardCmd())

	return root
}

// resolveVaultPath resolves the vault path by checking flags and config in priority order:
//  1. --vault-path flag (explicit path)
//  2. --vault flag (named vault, resolves to <configdir>/<name>.sqlite)
//  3. Active vault from config file
//  4. Default vault path
//
// The vault name value may come from the persistent --vault flag (vaultName var)
// or from the command's --vault flag (for the vault subcommand which has its own).
func resolveVaultPath(cmd *cobra.Command) (string, error) {
	// --vault-path takes highest precedence
	if vp := cmd.Flag("vault-path"); vp != nil && vp.Changed {
		return vp.Value.String(), nil
	}

	// --vault flag resolves named vault
	vaultFlag := cmd.Flag("vault")
	if vaultFlag != nil && vaultFlag.Changed {
		name := vaultFlag.Value.String()
		if name != "" {
			return config.VaultPathForName(name)
		}
	}

	// Fallback: global vaultName var
	if vaultName != "" {
		return config.VaultPathForName(vaultName)
	}

	// Load config for active vault
	cfg, err := config.Load()
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}
	if cfg.ActiveVault != "" {
		return config.VaultPathForName(cfg.ActiveVault)
	}
	return cfg.VaultPath, nil
}

// openStore creates and initializes a store at the given path.
func openStore(vaultPath string) (*store.SQLStore, error) {
	s := store.NewSQLStore()
	if err := s.Init(vaultPath); err != nil {
		return nil, fmt.Errorf("init store: %w", err)
	}
	return s, nil
}

// readVaultConfig reads salt and verifyHash from the store's config table.
func readVaultConfig(s *store.SQLStore) (salt, verifyHash []byte, err error) {
	salt, err = s.ConfigGet(configKeySalt)
	if err != nil {
		return nil, nil, fmt.Errorf("read salt: %w", err)
	}
	verifyHash, err = s.ConfigGet(configKeyVerifyHash)
	if err != nil {
		return nil, nil, fmt.Errorf("read verify hash: %w", err)
	}
	return salt, verifyHash, nil
}

// generateSalt generates a random 16-byte salt using crypto/rand.
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// generateVerifyHash derives a 32-byte verification hash from a derived key using HKDF-SHA256.
func generateVerifyHash(key, salt []byte) []byte {
	kdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	hash := make([]byte, 32)
	if _, err := io.ReadFull(kdf, hash); err != nil {
		panic("hkdf read failed: " + err.Error())
	}
	return hash
}

// promptPassword prompts the user for a password without echoing to terminal.
func promptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	return pw, nil
}

const envMasterPassword = "PASSWD_MASTER_PASSWORD"

// readMasterPassword reads the master password from the PASSWD_MASTER_PASSWORD env var
// (unless --no-env is set) or prompts the user interactively.
// The env var path prints a prominent security warning.
func readMasterPassword() ([]byte, error) {
	if !noEnv {
		if pw := os.Getenv(envMasterPassword); pw != "" {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintf(os.Stderr, "WARNING: %s is set. This exposes your master password to process listings.\n", envMasterPassword)
			fmt.Fprintln(os.Stderr, "Use --no-env to disable env var reading for paranoid mode.")
			fmt.Fprintln(os.Stderr, "")
			return []byte(pw), nil
		}
	}
	return promptPassword("Master password: ")
}

// lockoutFilePath returns the path to the persistent lockout file for a vault.
func lockoutFilePath(vaultPath string) string {
	return filepath.Join(filepath.Dir(vaultPath), ".passwd.lockout")
}

// unlockVaultWithEngine prompts for the master password, verifies it against the stored
// verification hash, and returns the open store, crypto engine, and derived key.
// Implements rate limiting: max 5 attempts with exponential backoff.
// Rate limiting is bypassed when PASSWD_MASTER_PASSWORD env var is set.
func unlockVaultWithEngine(vaultPath string) (*store.SQLStore, *crypto.Engine, []byte, error) {
	if err := requireVaultExists(vaultPath); err != nil {
		return nil, nil, nil, err
	}

	// Check persistent lockout first
	lockoutPath := lockoutFilePath(vaultPath)
	locked, remaining, err := checkLockout(lockoutPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("check lockout: %w", err)
	}
	if locked {
		return nil, nil, nil, fmt.Errorf("too many failed attempts, vault locked for %v", remaining.Round(time.Second))
	}

	s, err := openStore(vaultPath)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, verifyHash, err := readVaultConfig(s)
	if err != nil {
		_ = s.Close()
		return nil, nil, nil, vaultMissingHint(err)
	}

	// Read stored Argon2 params and create engine with them
	params, err := readArgon2Params(s)
	if err != nil {
		_ = s.Close()
		return nil, nil, nil, fmt.Errorf("read argon2 params: %w", err)
	}
	eng := crypto.NewEngine(params)

	// Check Circuit Breaker state
	cbState, err := s.GetCircuitBreakerState()
	if err == nil && cbState.IsHardLockout {
		_ = s.Close()
		return nil, nil, nil, fmt.Errorf("vault is hard locked: run 'vlt recovery restore' with recovery phrase to rescue access")
	}

	if err == nil && cbState.IsPINChallenge {
		fmt.Fprintln(os.Stderr, "⚠️  CIRCUIT BREAKER: 3 failed master password attempts detected.")
		fmt.Fprint(os.Stderr, "Enter 8-digit PIN to unfreeze master password prompt: ")
		pinBytes, pErr := promptPassword("")
		if pErr != nil {
			_ = s.Close()
			return nil, nil, nil, pErr
		}
		defer crypto.Zeroize(pinBytes)

		pinHash, pinSalt, pCfgErr := s.GetPINConfig()
		if pCfgErr != nil || !eng.VerifyPIN(string(pinBytes), pinSalt, pinHash) {
			newSt, _ := s.RecordFailedPINAttempt()
			_ = s.Close()
			if newSt != nil && newSt.IsHardLockout {
				return nil, nil, nil, fmt.Errorf("3 failed PIN attempts: hard lockout engaged (run 'vlt recovery restore' to rescue vault)")
			}
			remaining := 3
			if newSt != nil {
				remaining = 3 - newSt.PINFailedAttempts
			}
			return nil, nil, nil, fmt.Errorf("invalid PIN: %d attempts remaining before hard lockout", remaining)
		}

		// PIN correct: unfreeze master password prompt
		_ = s.ResetMasterAttempts()
		fmt.Fprintln(os.Stderr, "✅ PIN verified. Master password prompt unfrozen.")
	}

	// Check if we should bypass rate limiting (env var = assumed controlled environment)
	// --no-env disables this bypass even if the env var is set
	bypassRateLimit := !noEnv && os.Getenv("PASSWD_MASTER_PASSWORD") != ""

	for attempt := 0; attempt < cliMaxAttempts; attempt++ {
		password, err := readMasterPassword()
		if err != nil {
			_ = s.Close()
			return nil, nil, nil, err
		}

		// HIGH-03: Use VerifyAndDeriveKey for single-pass Argon2id
		key, ok := eng.VerifyAndDeriveKey(password, salt, verifyHash)
		crypto.Zeroize(password)

		if ok {
			// Best-effort audit log for successful unlock and reset attempts
			_ = s.LogAction("vault_unlock", "", "")
			_ = s.ResetMasterAttempts()
			_ = clearLockout(lockoutPath)
			return s, eng, key, nil
		}

		// Record failed attempt in persistent circuit breaker
		newCb, _ := s.RecordFailedMasterAttempt()
		if newCb != nil && newCb.IsPINChallenge {
			_ = s.Close()
			return nil, nil, nil, fmt.Errorf("3 failed master password attempts: vault frozen (run command again to enter 8-digit PIN)")
		}

		if bypassRateLimit {
			_ = s.Close()
			return nil, nil, nil, fmt.Errorf("error: invalid master password")
		}

		_ = recordAttempt(lockoutPath)

		if attempt < cliMaxAttempts-1 {
			backoff := cliBaseBackoff * (1 << attempt) // exponential: 1s, 2s, 4s, 8s
			fmt.Fprintf(os.Stderr, "Invalid master password. Attempt %d/%d. Retrying in %v...\n", attempt+1, cliMaxAttempts, backoff)
			time.Sleep(backoff)
		}
	}

	_ = s.Close()
	return nil, nil, nil, errors.New(cliLockoutMessage)
}

// unlockVault prompts for the master password, verifies it against the stored
// verification hash, and returns the derived key.
// Implements rate limiting: max 5 attempts with exponential backoff.
// Rate limiting is bypassed when PASSWD_MASTER_PASSWORD env var is set.
// Returns the open store and the derived key.
func unlockVault(vaultPath string) (*store.SQLStore, []byte, error) {
	s, _, key, err := unlockVaultWithEngine(vaultPath)
	return s, key, err
}

// readMasterPasswordWithConfirm prompts for the master password twice and
// returns the password only if both entries match.
// If PASSWD_MASTER_PASSWORD env var is set (and --no-env is not used), uses it
// directly (skips prompts).
func readMasterPasswordWithConfirm() ([]byte, error) {
	if !noEnv {
		if pw := os.Getenv("PASSWD_MASTER_PASSWORD"); pw != "" {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "WARNING: PASSWD_MASTER_PASSWORD is set. This exposes your master password to process listings.")
			fmt.Fprintln(os.Stderr, "Use --no-env to disable env var reading for paranoid mode.")
			fmt.Fprintln(os.Stderr, "")
			return []byte(pw), nil
		}
	}

	pw1, err := promptPassword("Master password: ")
	if err != nil {
		return nil, err
	}
	defer crypto.Zeroize(pw1)

	pw2, err := promptPassword("Confirm master password: ")
	if err != nil {
		return nil, err
	}
	defer crypto.Zeroize(pw2)

	if !hmac.Equal(pw1, pw2) {
		return nil, fmt.Errorf("passwords do not match")
	}

	// Return a copy since we zeroize the originals
	result := make([]byte, len(pw1))
	copy(result, pw1)
	return result, nil
}

// packEnvelope combines nonce and ciphertext into a single blob: nonce (12B) || ciphertext.
func packEnvelope(nonce, ciphertext []byte) []byte {
	return crypto.PackEnvelope(nonce, ciphertext)
}

// unpackEnvelope splits a blob into nonce and ciphertext.
func unpackEnvelope(blob []byte) (nonce, ciphertext []byte, err error) {
	return crypto.UnpackEnvelope(blob)
}

// checkVaultExists returns true if a file exists at the given path.
func checkVaultExists(vaultPath string) (bool, error) {
	_, err := os.Stat(vaultPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("check vault: %w", err)
}

// vaultMissingHint wraps an error with a hint about running passwd init.
func vaultMissingHint(err error) error {
	return fmt.Errorf("error: vault not found or corrupt. Run 'passwd init' first: %w", err)
}

// promptConfirm prompts the user with a yes/no question and returns true for yes.
// defaultYes controls what happens on empty input (Enter).
func promptConfirm(prompt string, defaultYes bool) bool {
	fmt.Fprint(os.Stderr, prompt)
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		return defaultYes
	}
	response = strings.TrimSpace(strings.ToLower(response))
	switch response {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return defaultYes
	}
}

// requireVaultExists checks if a vault file exists at the given path.
// Returns an error if the vault does not exist.
func requireVaultExists(vaultPath string) error {
	exists, err := checkVaultExists(vaultPath)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	if !exists {
		return fmt.Errorf("error: vault not found at %s. Run 'passwd init' first", vaultPath)
	}
	return nil
}

// checkPasswordStrength returns a warning message if the password is weak.
// Returns empty string if the password is acceptable.
// This is advisory only — it does NOT block vault creation.
func checkPasswordStrength(password []byte) string {
	if len(password) < 8 {
		return "Master password is very short (less than 8 characters)."
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range string(password) {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	categories := 0
	if hasUpper {
		categories++
	}
	if hasLower {
		categories++
	}
	if hasDigit {
		categories++
	}
	if hasSymbol {
		categories++
	}

	if len(password) < 12 {
		return "Master password is short (less than 12 characters)."
	}
	if categories < 3 {
		return "Master password has low character diversity (use uppercase, lowercase, digits, and symbols)."
	}

	return ""
}

// clipboardClearDelay is the time the auto-clear subprocess waits before
// wiping the clipboard. Exposed for tests; do not change at runtime.
var clipboardClearDelay = 30 * time.Second

// newClearClipboardCmd reads the expected clipboard contents from STDIN and,
// after clipboardClearDelay, clears the clipboard only if it still matches.
//
// S-06: the expected value used to be passed as an argv argument, which leaked
// the secret to `ps` and /proc/<pid>/cmdline. It is now read from stdin and
// the buffer is zeroized as soon as possible.
func newClearClipboardCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "__clear-clipboard",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Read from the command's input (cobra falls back to os.Stdin for
			// the real subprocess, and tests inject via SetIn). Reading
			// os.Stdin directly broke the comparison under test — and any
			// caller that rewires stdin — so the clipboard was never cleared.
			data, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("read expected clipboard: %w", err)
			}
			// Trim a single trailing newline, if any, so callers can write
			// `text + "\n"` without altering the comparison.
			if n := len(data); n > 0 && data[n-1] == '\n' {
				data = data[:n-1]
			}
			expected := string(data)
			crypto.Zeroize(data)

			time.Sleep(clipboardClearDelay)
			current, err := clipboard.ReadAll()
			if err == nil && current == expected {
				_ = clipboard.WriteAll("")
			}
			return nil
		},
	}
}

// StartClipboardAutoClear spawns a detached background process of the current
// executable that clears the clipboard after clipboardClearDelay if the
// contents still match the secret just written.
//
// The expected value is delivered via STDIN (synchronously, before this
// function returns) instead of argv to avoid leaking it to process listings.
func StartClipboardAutoClear(text string) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	StartClipboardAutoClearForBinary(exe, text)
}

// StartClipboardAutoClearForBinary is like StartClipboardAutoClear but uses
// the given executable path. Used by sibling binaries (e.g. vlt-quick) that
// know where the main `vlt` binary lives.
func StartClipboardAutoClearForBinary(exe, text string) {
	cmd := exec.Command(exe, "__clear-clipboard")
	cmd.SysProcAttr = GetSysProcAttrDetached()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return
	}

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return
	}

	// Write synchronously from the parent — must happen before the parent
	// returns or the child may exit before reading.
	_, _ = io.WriteString(stdin, text)
	_ = stdin.Close()

	// Release the child handle so it does not become a zombie if the parent
	// stays alive (e.g. GUI mode). The detached SysProcAttr already
	// reparents it to init on supported platforms.
	go func() { _ = cmd.Wait() }()
}
