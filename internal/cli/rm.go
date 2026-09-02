package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
)

func newRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a secret",
		Long: `Delete a secret from the vault by name.

Prompts for confirmation unless --force is specified.
No master password required for deletion.`,
		Args: cobra.ExactArgs(1),
		RunE: runRm,
	}

	cmd.Flags().Bool("force", false, "delete without confirmation prompt")
	return cmd
}

func runRm(cmd *cobra.Command, args []string) error {
	name := args[0]
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	// Unlock vault (prompt for master password, derive key)
	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	defer crypto.Zeroize(key)

	// Check if secret exists (for a better error message)
	_, err = getByName(s, key, name)
	if err != nil {
		return fmt.Errorf("error: secret %q not found", name)
	}

	// Confirm unless --force
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		confirmed, err := confirmDelete(name)
		if err != nil {
			return fmt.Errorf("error: %w", err)
		}
		if !confirmed {
			fmt.Fprintln(os.Stderr, "Deletion cancelled.")
			return nil
		}
	}

	if err := softDeleteByName(s, key, name); err != nil {
		return fmt.Errorf("error: delete: %w", err)
	}

	// Log audit entry
	if err := s.LogAction("secret_delete", name, ""); err != nil {
		return fmt.Errorf("error: log audit: %w", err)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		out := map[string]string{"status": "deleted", "name": name}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	} else {
		fmt.Fprintf(os.Stderr, "Secret %q deleted.\n", name)
	}

	return nil
}

// confirmDelete prompts the user for deletion confirmation. Returns true if confirmed.
func confirmDelete(name string) (bool, error) {
	fmt.Fprintf(os.Stderr, "Delete %q? [y/N]: ", name)
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes", nil
}
