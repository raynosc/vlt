package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/keychain"
)

const vaultHelp = `Manage multiple encrypted vaults.

Commands:
  list        List all vaults with name, status, path, and creation date.
  create      Create a new named vault.
  switch      Set the active vault (alias for default).
  default     Set the default / active vault.
  enable      Enable a previously disabled vault.
  disable     Disable a vault from active discovery.
  remove      Delete a vault (irreversible).

Use --vault <name> to create or switch to a named vault:
  vlt --vault work init    Create a new vault named "work"
  vlt --vault personal ls  List secrets in the "personal" vault

Named vaults are stored as <name>.sqlite in the config directory.`

func newVaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage multiple vaults",
		Long:  vaultHelp,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newVaultListCmd())
	cmd.AddCommand(newVaultCreateCmd())
	cmd.AddCommand(newVaultRenameCmd())
	cmd.AddCommand(newVaultSwitchCmd())
	cmd.AddCommand(newVaultDefaultCmd())
	cmd.AddCommand(newVaultEnableCmd())
	cmd.AddCommand(newVaultDisableCmd())
	cmd.AddCommand(newVaultRemoveCmd())
	return cmd
}

// ── List ──

func newVaultListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all vaults",
		Long: `List all discovered vaults with name, status, path, and creation date.

The default vault (vault.sqlite) is listed first.`,
		Args: cobra.NoArgs,
		RunE: runVaultList,
	}
}

func runVaultList(cmd *cobra.Command, _ []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	vaults, err := config.ListVaults()
	if err != nil {
		return fmt.Errorf("error: list vaults: %w", err)
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(vaults); err != nil {
			return fmt.Errorf("error: encode JSON: %w", err)
		}
		return nil
	}

	if len(vaults) == 0 {
		fmt.Fprintln(os.Stderr, "No vaults found.")
		fmt.Fprintln(os.Stderr, "Run 'vlt init' to create a vault, or 'vlt vault create <name>' for a named vault.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "%-20s %-12s %-60s %s\n", "NAME", "STATUS", "PATH", "CREATED")
	fmt.Fprintln(os.Stderr, "-------------------- ------------ ------------------------------------------------------------ -------------------------")
	for _, v := range vaults {
		name := v.Name
		status := "enabled"
		if v.Disabled {
			status = "disabled"
		} else if v.IsActive {
			status = "active"
		}
		fmt.Fprintf(os.Stderr, "%-20s %-12s %-60s %s\n", name, status, v.Path, v.Created.Format("2006-01-02 15:04:05"))
	}

	return nil
}

// ── Create ──

func newVaultCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new named vault",
		Long: `Create a new vault with the given name.

Prompts for a master password, derives the key, and creates the SQLite vault.
The new vault is automatically set as the active vault.`,
		Args: cobra.ExactArgs(1),
		RunE: runVaultCreate,
	}
}

func runVaultCreate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if name == "" {
		return fmt.Errorf("error: vault name must not be empty")
	}
	if strings.ContainsAny(name, `/\<>:"|?*`) {
		return fmt.Errorf("error: vault name contains invalid characters")
	}

	vaultPath, err := config.VaultPathForName(name)
	if err != nil {
		return fmt.Errorf("error: resolve vault path: %w", err)
	}

	exists, err := checkVaultExists(vaultPath)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	if exists {
		return fmt.Errorf("error: vault %q already exists at %s", name, vaultPath)
	}

	// Prompt for master password
	password, err := readMasterPasswordWithConfirm()
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	defer crypto.Zeroize(password)

	mnemonic, err := initializeVault(vaultPath, password, name, "")
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Vault created:", vaultPath)
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

	return nil
}

// ── Rename ──

func newVaultRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old-name> <new-name>",
		Short: "Rename a vault",
		Long:  `Rename an existing vault and update references in the configuration.`,
		Args:  cobra.ExactArgs(2),
		RunE:  runVaultRename,
	}
}

func runVaultRename(cmd *cobra.Command, args []string) error {
	oldName := args[0]
	newName := args[1]

	if err := config.RenameVault(oldName, newName); err != nil {
		return fmt.Errorf("error: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Vault %q renamed to %q.\n", oldName, newName)
	return nil
}

// ── Switch & Default ──

func newVaultSwitchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "switch <name>",
		Short: "Set the active vault",
		Long: `Switch to the named vault by updating the active_vault config.

The vault must already exist. Use 'vlt vault create <name>' to create one.`,
		Args: cobra.ExactArgs(1),
		RunE: runVaultSwitch,
	}
}

func newVaultDefaultCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "default <name>",
		Aliases: []string{"set-default"},
		Short:   "Set the default vault",
		Long:    `Set the default vault by updating the active_vault config.`,
		Args:    cobra.ExactArgs(1),
		RunE:    runVaultSwitch,
	}
}

func runVaultSwitch(cmd *cobra.Command, args []string) error {
	name := args[0]

	vaultPath, err := config.VaultPathForName(name)
	if err != nil {
		return fmt.Errorf("error: resolve vault path: %w", err)
	}

	exists, err := checkVaultExists(vaultPath)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	if !exists {
		return fmt.Errorf("error: vault %q does not exist. Run 'vlt vault create %s' first", name, name)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("error: load config: %w", err)
	}

	if cfg.IsVaultDisabled(name) {
		return fmt.Errorf("error: vault %q is currently disabled. Run 'vlt vault enable %s' first", name, name)
	}

	if err := cfg.SetActiveVault(name); err != nil {
		return fmt.Errorf("error: save config: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Switched to vault %q (%s)\n", name, vaultPath)
	return nil
}

// ── Enable & Disable ──

func newVaultEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable <name>",
		Short: "Enable a disabled vault",
		Long:  `Enable a previously disabled vault so it appears in vault listings and login selectors.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runVaultEnable,
	}
}

func runVaultEnable(cmd *cobra.Command, args []string) error {
	name := args[0]

	vaultPath, err := config.VaultPathForName(name)
	if err != nil {
		return fmt.Errorf("error: resolve vault path: %w", err)
	}

	exists, err := checkVaultExists(vaultPath)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	if !exists {
		return fmt.Errorf("error: vault %q does not exist", name)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("error: load config: %w", err)
	}

	if !cfg.IsVaultDisabled(name) {
		fmt.Fprintf(os.Stderr, "Vault %q is already enabled.\n", name)
		return nil
	}

	if err := cfg.EnableVault(name); err != nil {
		return fmt.Errorf("error: enable vault: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Vault %q enabled.\n", name)
	return nil
}

func newVaultDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <name>",
		Short: "Disable a vault",
		Long:  `Disable a vault so it is hidden from standard discovery and login dropdowns without deleting its data.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runVaultDisable,
	}
}

func runVaultDisable(cmd *cobra.Command, args []string) error {
	name := args[0]

	vaultPath, err := config.VaultPathForName(name)
	if err != nil {
		return fmt.Errorf("error: resolve vault path: %w", err)
	}

	exists, err := checkVaultExists(vaultPath)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	if !exists {
		return fmt.Errorf("error: vault %q does not exist", name)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("error: load config: %w", err)
	}

	if cfg.IsVaultDisabled(name) {
		fmt.Fprintf(os.Stderr, "Vault %q is already disabled.\n", name)
		return nil
	}

	// If disabling the current active vault, switch active vault to another enabled vault if available
	if cfg.ActiveVault == name || (cfg.ActiveVault == "" && name == "vault") {
		vaults, _ := config.ListVaults()
		var fallbackName string
		for _, v := range vaults {
			if v.Name != name && !cfg.IsVaultDisabled(v.Name) {
				fallbackName = v.Name
				break
			}
		}
		if fallbackName != "" {
			_ = cfg.SetActiveVault(fallbackName)
		} else {
			cfg.ActiveVault = ""
		}
	}

	if err := cfg.DisableVault(name); err != nil {
		return fmt.Errorf("error: disable vault: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Vault %q disabled.\n", name)
	return nil
}

// ── Remove ──

func newVaultRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Delete a vault permanently",
		Long: `Delete the named vault file permanently.

This action is irreversible. The vault file is deleted from disk.
Use --force to skip the confirmation prompt.`,
		Args: cobra.ExactArgs(1),
		RunE: runVaultRemove,
	}

	cmd.Flags().Bool("force", false, "skip confirmation prompt")
	return cmd
}

func runVaultRemove(cmd *cobra.Command, args []string) error {
	name := args[0]
	if name == "" {
		return fmt.Errorf("error: vault name must not be empty")
	}

	force, _ := cmd.Flags().GetBool("force")

	vaultPath, err := config.VaultPathForName(name)
	if err != nil {
		return fmt.Errorf("error: resolve vault path: %w", err)
	}

	exists, err := checkVaultExists(vaultPath)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	if !exists {
		return fmt.Errorf("error: vault %q does not exist", name)
	}

	// Prevent deleting the active vault
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("error: load config: %w", err)
	}
	if cfg.ActiveVault == name {
		return fmt.Errorf("error: cannot remove the active vault. Switch to another vault first")
	}
	// Also prevent deleting the default vault if no active_vault is set
	if cfg.ActiveVault == "" && name == "vault" {
		return fmt.Errorf("error: cannot remove the default vault. Switch to another vault first")
	}

	if !force {
		confirmed := promptConfirm(fmt.Sprintf("Delete vault %q permanently? [y/N] ", name), false)
		if !confirmed {
			fmt.Fprintln(os.Stderr, "Cancelled.")
			return nil
		}
	}

	// Remove vault file
	if err := os.Remove(vaultPath); err != nil {
		return fmt.Errorf("error: delete vault file: %w", err)
	}

	// Clean up from disabled list if present
	_ = cfg.EnableVault(name)

	// Best-effort: remove from keychain
	_ = keychain.New().Delete(keychain.DefaultService, name)

	// Also try to clean up any WAL/SHM journal files
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(vaultPath + suffix)
	}

	fmt.Fprintf(os.Stderr, "Vault %q removed.\n", name)
	return nil
}
