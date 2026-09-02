package cli

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/crypto"
)

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new vault",
		Long: `Initialize a new password vault.

Prompts for a master password (with confirmation), derives an encryption key
using Argon2id, creates the SQLite database, stores configuration, and
displays a recovery kit mnemonic phrase.

If a vault already exists, use --force to overwrite it.`,
		Args: cobra.NoArgs,
		RunE: runInit,
	}

	cmd.Flags().Bool("force", false, "overwrite existing vault")
	cmd.Flags().String("save-recovery", "", "save recovery kit to the given file path (SECURITY: plaintext on disk)")
	return cmd
}

func runInit(cmd *cobra.Command, _ []string) error {
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	force, _ := cmd.Flags().GetBool("force")
	saveRecovery, _ := cmd.Flags().GetString("save-recovery")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	// Check if vault already exists
	exists, err := checkVaultExists(vaultPath)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	if exists && !force {
		return fmt.Errorf("error: vault already exists at %s. Use --force to overwrite", vaultPath)
	}

	// Prompt for master password
	password, err := readMasterPasswordWithConfirm()
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	defer crypto.Zeroize(password)

	// Determine vault name for keychain and config
	vaultNameForConfig := ""
	if vn := cmd.Flag("vault"); vn != nil && vn.Changed {
		vaultNameForConfig = vn.Value.String()
	} else if vaultName != "" {
		vaultNameForConfig = vaultName
	}

	mnemonic, err := initializeVault(vaultPath, password, vaultNameForConfig, saveRecovery)
	if err != nil {
		return err
	}

	if jsonOutput {
		fmt.Printf(`{"status":"ok","vault_path":%q}`, vaultPath)
		fmt.Println()
		return nil
	}

	// CRIT-02: Recovery kit is SHOWN ONCE and must be saved by the user.
	fmt.Fprintln(os.Stderr, "Vault initialized successfully.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "╔══════════════════════════════════════════════════╗")
	fmt.Fprintln(os.Stderr, "║              RECOVERY KIT                        ║")
	fmt.Fprintln(os.Stderr, "╠══════════════════════════════════════════════════╣")
	fmt.Fprintln(os.Stderr, "║ Write down these words and store them offline.   ║")
	fmt.Fprintln(os.Stderr, "║ Anyone with this phrase can recover your vault.  ║")
	fmt.Fprintln(os.Stderr, "║ This phrase will NOT be shown again.             ║")
	fmt.Fprintln(os.Stderr, "╚══════════════════════════════════════════════════╝")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, mnemonic)
	fmt.Fprintln(os.Stderr)

	fmt.Fprintln(os.Stderr, "Vault location:", vaultPath)

	return nil
}

// initializeVault creates a new vault at the given path with the given password.
// It returns the recovery kit mnemonic. The caller must zeroize the password.
func initializeVault(vaultPath string, password []byte, vaultName, saveRecovery string) (string, error) {
	// Ensure vault directory exists
	cfg := &config.Config{VaultPath: vaultPath}
	if err := cfg.EnsureVaultDir(); err != nil {
		return "", fmt.Errorf("error: %w", err)
	}

	// Check if vault already exists and remove if force was implied (for re-init)
	exists, err := checkVaultExists(vaultPath)
	if err != nil {
		return "", fmt.Errorf("error: %w", err)
	}
	if exists {
		if err := os.Remove(vaultPath); err != nil {
			return "", fmt.Errorf("error: remove existing vault: %w", err)
		}
	}

	// Generate random salt
	salt, err := generateSalt()
	if err != nil {
		return "", fmt.Errorf("error: %w", err)
	}

	// INFO-04: Warn about weak master passwords (non-blocking)
	if warning := checkPasswordStrength(password); warning != "" {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "⚠️  WARNING: %s\n", warning)
		fmt.Fprintln(os.Stderr, "   A strong master password should be at least 12 characters")
		fmt.Fprintln(os.Stderr, "   with a mix of uppercase, lowercase, digits, and symbols.")
		fmt.Fprintln(os.Stderr, "")
	}

	// Derive the master key using Argon2id
	key, err := engine.DeriveKey(password, salt)
	if err != nil {
		return "", fmt.Errorf("error: %w", err)
	}
	defer crypto.Zeroize(key)

	// Generate verification hash
	verifyHash := generateVerifyHash(key, salt)

	// Generate recovery kit
	mnemonic, recoveryBlob, err := engine.GenerateRecoveryKit(key)
	if err != nil {
		return "", fmt.Errorf("error: generate recovery kit: %w", err)
	}

	// Create store and persist config
	s, err := openStore(vaultPath)
	if err != nil {
		return "", fmt.Errorf("error: %w", err)
	}
	defer func() { _ = s.Close() }()

	// Store vault configuration in store's config table
	if err := s.ConfigSet(configKeySalt, salt); err != nil {
		return "", fmt.Errorf("error: store salt: %w", err)
	}
	if err := s.ConfigSet(configKeyVerifyHash, verifyHash); err != nil {
		return "", fmt.Errorf("error: store verify hash: %w", err)
	}
	if err := s.ConfigSet(configKeyRecoveryBlob, recoveryBlob); err != nil {
		return "", fmt.Errorf("error: store recovery blob: %w", err)
	}

	// Store Argon2id parameters
	params := crypto.DefaultArgon2Params
	timeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBytes, params.Time)
	memoryBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(memoryBytes, params.Memory)
	threadsBytes := []byte{byte(params.Threads)}

	if err := s.ConfigSet(configKeyArgon2Time, timeBytes); err != nil {
		return "", fmt.Errorf("error: store argon2 time: %w", err)
	}
	if err := s.ConfigSet(configKeyArgon2Memory, memoryBytes); err != nil {
		return "", fmt.Errorf("error: store argon2 memory: %w", err)
	}
	if err := s.ConfigSet(configKeyArgon2Threads, threadsBytes); err != nil {
		return "", fmt.Errorf("error: store argon2 threads: %w", err)
	}

	// Set active vault name
	if vaultName != "" {
		cfg.ActiveVault = vaultName
	} else {
		cfg.ActiveVault = config.VaultNameFromPath(vaultPath)
	}

	// Save config file for vault path discovery
	if err := cfg.Save(); err != nil {
		return "", fmt.Errorf("error: save config: %w", err)
	}

	// Optional: save recovery kit to file
	if saveRecovery != "" {
		if saveRecovery == vaultPath {
			return "", fmt.Errorf("error: recovery kit path must not be the vault file itself")
		}
		recoveryDir := filepath.Dir(saveRecovery)
		if err := os.MkdirAll(recoveryDir, 0o700); err != nil {
			return "", fmt.Errorf("error: create recovery kit directory: %w", err)
		}
		if err := os.WriteFile(saveRecovery, []byte(mnemonic+"\n"), 0o600); err != nil {
			return "", fmt.Errorf("error: save recovery kit: %w", err)
		}
		fmt.Fprintln(os.Stderr, "⚠️  Recovery kit also saved to", saveRecovery)
		fmt.Fprintln(os.Stderr, "   Move this file to secure offline storage immediately.")
		fmt.Fprintln(os.Stderr)
	}

	// Log audit entry for vault initialization
	if err := s.LogAction("vault_init", "", ""); err != nil {
		return "", fmt.Errorf("error: log audit: %w", err)
	}

	return mnemonic, nil
}
