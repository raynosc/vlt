package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
)

func newGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Retrieve and decrypt a secret",
		Long: `Retrieve and decrypt a secret by name.

Prompts for the master password, retrieves the encrypted blob, decrypts it,
and displays the plaintext value.

Use --copy to copy the value to clipboard (requires xclip/pbcopy).
Use --json for machine-readable output.`,
		Args: cobra.ExactArgs(1),
		RunE: runGet,
	}

	cmd.Flags().Bool("copy", false, "copy value to clipboard")
	return cmd
}

func runGet(cmd *cobra.Command, args []string) error {
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

	// Retrieve the encrypted secret
	sec, err := getByName(s, key, name)
	if err != nil {
		return fmt.Errorf("error: secret %q not found", name)
	}

	if len(sec.EncryptedValue) == 0 {
		return fmt.Errorf("error: secret %q has no encrypted value", name)
	}

	// Unpack the envelope
	nonce, ciphertext, err := unpackEnvelope(sec.EncryptedValue)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	// Decrypt
	plaintext, err := engine.Decrypt(ciphertext, key, nonce)
	if err != nil {
		return fmt.Errorf("error: decryption failed")
	}
	defer crypto.Zeroize(plaintext)

	// Log audit entry
	details := fmt.Sprintf("kind=%s", sec.Kind)
	if err := s.LogAction("secret_get", name, details); err != nil {
		return fmt.Errorf("error: log audit: %w", err)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	copyToClip, _ := cmd.Flags().GetBool("copy")

	if jsonOutput {
		out := map[string]string{
			"name":  sec.Name,
			"value": string(plaintext),
			"kind":  string(sec.Kind),
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	} else {
		if copyToClip {
			if err := copyToClipboard(string(plaintext)); err != nil {
				return fmt.Errorf("error: clipboard: %w", err)
			}
			fmt.Fprintln(os.Stderr, "Value copied to clipboard.")
		} else {
			fmt.Println(string(plaintext))
			fmt.Fprintln(os.Stderr, "WARNING: secret value printed to stdout. It may be captured in shell history or logs.")
		}
	}

	return nil
}

// copyToClipboard copies text to the system clipboard and starts the auto-clear timer.
func copyToClipboard(text string) error {
	if err := clipboard.WriteAll(text); err != nil {
		return err
	}
	StartClipboardAutoClear(text)
	return nil
}
