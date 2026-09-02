package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/keychain"
)

func newLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Lock the vault and remove the Keychain key",
		Long: `Lock the vault by removing the master key from the macOS Keychain.
The next unlock will require the master password (or Touch ID if configured).

Use --no-keychain to skip Keychain removal.`,
		Args: cobra.NoArgs,
		RunE: runLock,
	}
}

func runLock(cmd *cobra.Command, _ []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	if noKeychain {
		if jsonOutput {
			fmt.Println(`{"status":"skipped","reason":"no-keychain"}`)
			return nil
		}
		fmt.Fprintln(os.Stderr, "Keychain is disabled (--no-keychain). Nothing to do.")
		return nil
	}

	if err := kc.Delete(keychain.DefaultService, keychain.DefaultAccount); err != nil {
		if err == keychain.ErrUnsupported {
			if jsonOutput {
				fmt.Println(`{"status":"unsupported"}`)
				return nil
			}
			fmt.Fprintln(os.Stderr, "Keychain is not supported on this platform.")
			return nil
		}
		return fmt.Errorf("error: lock: %w", err)
	}

	if jsonOutput {
		fmt.Println(`{"status":"locked"}`)
		return nil
	}

	fmt.Fprintln(os.Stderr, "🔒 Vault locked. Keychain key removed.")
	return nil
}
