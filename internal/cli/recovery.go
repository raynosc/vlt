package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/store"
)

func newRecoveryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recovery",
		Short: "Manage vault recovery phrase and rescue operations",
		Long:  `View the 24-word/36-word recovery phrase or restore access to a locked vault.`,
	}

	cmd.AddCommand(newRecoveryShowCmd())
	cmd.AddCommand(newRecoveryRestoreCmd())

	return cmd
}

func newRecoveryShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Display the BIP39/mnemonic recovery phrase",
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

			// Generate on-the-fly recovery kit for display
			eng := crypto.NewEngine(nil)
			mnemonic, _, err := eng.GenerateRecoveryKit(key)
			if err != nil {
				return fmt.Errorf("generate recovery phrase: %w", err)
			}

			fmt.Println("\n⚠️  KEEP THIS SECRET AND SAFE. NEVER SHARE IT.")
			fmt.Println("==================================================")
			fmt.Println(mnemonic)
			fmt.Println("==================================================")
			fmt.Println("You can use this phrase to rescue your vault if it enters Hard Lockout.")
			return nil
		},
	}
}

func newRecoveryRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restore",
		Short: "Rescue a locked vault using the recovery phrase",
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

			recoveryBlob, err := s.ConfigGet(store.ConfigKeyRecoveryBlob)
			if err != nil || len(recoveryBlob) == 0 {
				return fmt.Errorf("no recovery blob found in vault (vault might not have recovery enabled)")
			}

			salt, verifyHash, err := readVaultConfig(s)
			if err != nil {
				return err
			}

			fmt.Print("Enter your 36-word recovery phrase:\n> ")
			phraseBytes, err := promptPassword("")
			if err != nil {
				return err
			}
			defer crypto.Zeroize(phraseBytes)

			phrase := strings.TrimSpace(string(phraseBytes))
			eng := crypto.NewEngine(nil)

			valid, err := eng.VerifyRecoveryKit(phrase, recoveryBlob, salt, verifyHash)
			if err != nil || !valid {
				return fmt.Errorf("❌ Invalid recovery phrase: verification failed")
			}

			// Unlock & reset circuit breaker
			if err := s.ResetCircuitBreaker(); err != nil {
				return fmt.Errorf("reset circuit breaker: %w", err)
			}

			_ = s.LogAction("vault_rescued", "", "Vault unlocked via recovery kit")
			fmt.Println("✅ Recovery phrase verified! Circuit breaker and hard lockout reset.")
			fmt.Println("You can now unlock your vault with your master password.")
			return nil
		},
	}
}
