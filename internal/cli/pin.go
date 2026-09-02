package cli

import (
	"crypto/rand"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
)

func newPINCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Manage anti-brute force 8-digit PIN circuit breaker",
		Long: `Configure, test, or remove the 8-digit PIN protection.
When enabled, 3 consecutive failed master password attempts lock the vault and require the 8-digit PIN.`,
	}

	cmd.AddCommand(newPINSetCmd())
	cmd.AddCommand(newPINRemoveCmd())
	cmd.AddCommand(newPINStatusCmd())

	return cmd
}

func newPINSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set",
		Short: "Configure or update 8-digit PIN",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath, err := resolveVaultPath(cmd)
			if err != nil {
				return fmt.Errorf("resolve vault: %w", err)
			}

			s, key, err := unlockVault(vaultPath)
			if err != nil {
				return err
			}
			defer func() {
				crypto.Zeroize(key)
				_ = s.Close()
			}()

			fmt.Print("Enter new 8-digit PIN: ")
			pinBytes, err := promptPassword("")
			if err != nil {
				return err
			}
			defer crypto.Zeroize(pinBytes)

			pin := string(pinBytes)
			if err := crypto.ValidatePINFormat(pin); err != nil {
				return err
			}

			fmt.Print("Confirm 8-digit PIN: ")
			confirmBytes, err := promptPassword("")
			if err != nil {
				return err
			}
			defer crypto.Zeroize(confirmBytes)

			if pin != string(confirmBytes) {
				return fmt.Errorf("PINs do not match")
			}

			// Generate 16-byte salt and hash with Argon2id
			salt := make([]byte, 16)
			if _, err := rand.Read(salt); err != nil {
				return fmt.Errorf("generate salt: %w", err)
			}

			eng := crypto.NewEngine(nil)
			hash, err := eng.HashPIN(pin, salt)
			if err != nil {
				return fmt.Errorf("hash PIN: %w", err)
			}
			defer crypto.Zeroize(hash)

			if err := s.SetPIN(hash, salt); err != nil {
				return fmt.Errorf("save PIN: %w", err)
			}

			_ = s.LogAction("pin_configured", "", "8-digit anti-brute force PIN set")
			fmt.Println("✅ 8-digit PIN configured successfully.")
			return nil
		},
	}
}

func newPINRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "Remove PIN protection from vault",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath, err := resolveVaultPath(cmd)
			if err != nil {
				return fmt.Errorf("resolve vault: %w", err)
			}

			s, key, err := unlockVault(vaultPath)
			if err != nil {
				return err
			}
			defer func() {
				crypto.Zeroize(key)
				_ = s.Close()
			}()

			if err := s.RemovePIN(); err != nil {
				return fmt.Errorf("remove PIN: %w", err)
			}

			_ = s.LogAction("pin_removed", "", "PIN protection removed")
			fmt.Println("✅ PIN protection removed.")
			return nil
		},
	}
}

func newPINStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check PIN circuit breaker status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath, err := resolveVaultPath(cmd)
			if err != nil {
				return fmt.Errorf("resolve vault: %w", err)
			}

			s, err := openStore(vaultPath)
			if err != nil {
				return err
			}
			defer func() { _ = s.Close() }()

			state, err := s.GetCircuitBreakerState()
			if err != nil {
				return err
			}

			fmt.Printf("PIN Protection: ")
			if state.HasPIN {
				fmt.Println("Enabled (8 digits)")
			} else {
				fmt.Println("Disabled")
			}

			fmt.Printf("Failed Master Attempts: %d / 3\n", state.MasterFailedAttempts)
			fmt.Printf("Failed PIN Attempts:    %d / 3\n", state.PINFailedAttempts)
			fmt.Printf("PIN Challenge Active:   %t\n", state.IsPINChallenge)
			fmt.Printf("Hard Lockout Active:    %t\n", state.IsHardLockout)

			return nil
		},
	}
}
