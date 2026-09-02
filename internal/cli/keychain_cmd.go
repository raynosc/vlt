package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/keychain"
)

func newKeychainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keychain",
		Short: "Manage macOS Keychain integration",
		Long: `Manage the macOS Keychain integration.

Commands:
  status    Show whether the master key is stored in Keychain
  forget    Remove the master key from Keychain (forces password on next unlock)`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newKeychainStatusCmd())
	cmd.AddCommand(newKeychainForgetCmd())
	return cmd
}

func newKeychainStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show Keychain status",
		Long:  `Show whether the master key is stored in the macOS Keychain.`,
		Args:  cobra.NoArgs,
		RunE:  runKeychainStatus,
	}
}

func newKeychainForgetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "forget",
		Short: "Remove key from Keychain",
		Long:  `Remove the master key from the macOS Keychain. The password will be required on next unlock.`,
		Args:  cobra.NoArgs,
		RunE:  runKeychainForget,
	}
}

func runKeychainStatus(cmd *cobra.Command, _ []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	key, err := kc.Load(keychain.DefaultService, keychain.DefaultAccount)
	if err == keychain.ErrNotFound || err == keychain.ErrUnsupported {
		if jsonOutput {
			fmt.Println(`{"status":"not_stored"}`)
			return nil
		}
		fmt.Fprintln(os.Stderr, "Master key is not stored in Keychain.")
		if err == keychain.ErrUnsupported {
			fmt.Fprintln(os.Stderr, "Keychain is not supported on this platform.")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("error: keychain status: %w", err)
	}
	defer crypto.Zeroize(key)

	if jsonOutput {
		fmt.Printf(`{"status":"stored","key_length":%d}`, len(key))
		fmt.Println()
		return nil
	}

	fmt.Fprintln(os.Stderr, "✅ Master key is stored in Keychain.")
	if len(key) == 32 {
		fmt.Fprintln(os.Stderr, "Key length: 32 bytes (valid)")
	} else {
		fmt.Fprintf(os.Stderr, "Key length: %d bytes (unexpected)\n", len(key))
	}
	return nil
}

func runKeychainForget(cmd *cobra.Command, _ []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	if err := kc.Delete(keychain.DefaultService, keychain.DefaultAccount); err != nil {
		if err == keychain.ErrUnsupported {
			if jsonOutput {
				fmt.Println(`{"status":"unsupported"}`)
				return nil
			}
			fmt.Fprintln(os.Stderr, "Keychain is not supported on this platform.")
			return nil
		}
		return fmt.Errorf("error: keychain forget: %w", err)
	}

	if jsonOutput {
		fmt.Println(`{"status":"removed"}`)
		return nil
	}

	fmt.Fprintln(os.Stderr, "✅ Master key removed from Keychain.")
	fmt.Fprintln(os.Stderr, "You will need to enter your master password on next unlock.")
	return nil
}
