package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/secret"
)

func newEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit an existing secret",
		Long: `Edit an existing secret in the vault.

Prompts for the master password, retrieves the secret, decrypts it, shows
the current value (masked), and prompts for a new value. Encrypts the new
value and updates the store.

Use --stdin to read the new value from standard input.
Use --name to rename the secret.
Use --notes to update the notes.
Use --type to change the secret kind.`,
		Args: cobra.ExactArgs(1),
		RunE: runEdit,
	}

	cmd.Flags().Bool("stdin", false, "read new secret value from stdin")
	cmd.Flags().String("name", "", "rename the secret")
	cmd.Flags().String("notes", "", "update notes")
	cmd.Flags().String("type", "", "change secret kind")
	return cmd
}

func runEdit(cmd *cobra.Command, args []string) error {
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

	// Retrieve the existing secret
	sec, err := getByName(s, key, name)
	if err != nil {
		return fmt.Errorf("error: secret %q not found", name)
	}

	if len(sec.EncryptedValue) == 0 {
		return fmt.Errorf("error: secret %q has no encrypted value", name)
	}

	// Unpack and decrypt existing value
	nonce, ciphertext, err := unpackEnvelope(sec.EncryptedValue)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	oldPlaintext, err := engine.Decrypt(ciphertext, key, nonce)
	if err != nil {
		return fmt.Errorf("error: decryption failed")
	}
	defer crypto.Zeroize(oldPlaintext)

	// Show current value (masked) on stderr — never expose full plaintext
	// to prevent capture in terminal scrollback, logs, or screen recording.
	valLen := len(oldPlaintext)
	if valLen <= 4 {
		fmt.Fprintf(os.Stderr, "Current value: %s [%d chars]\n", strings.Repeat("*", valLen), valLen)
	} else {
		preview := string(oldPlaintext[:4])
		fmt.Fprintf(os.Stderr, "Current value: %s%s [%d chars]\n", preview, strings.Repeat("*", valLen-4), valLen)
	}

	// Read new value — only prompt if neither --stdin nor metadata-only flags given
	hasStdinFlag, _ := cmd.Flags().GetBool("stdin")
	hasNotesFlag := cmd.Flag("notes").Changed
	hasNameFlag := cmd.Flag("name").Changed
	hasTypeFlag := cmd.Flag("type").Changed

	onlyNotesOrRename := (hasNotesFlag || hasNameFlag || hasTypeFlag) && !hasStdinFlag

	var newValue []byte
	if onlyNotesOrRename {
		// Keep old value — no prompt needed
		newValue = make([]byte, len(oldPlaintext))
		copy(newValue, oldPlaintext)
	} else {
		newValue, err = readSecretValue(cmd)
		if err != nil {
			return fmt.Errorf("error: %w", err)
		}
		defer crypto.Zeroize(newValue)

		// If no new value provided interactively, keep the old one
		if len(newValue) == 0 {
			newValue = make([]byte, len(oldPlaintext))
			copy(newValue, oldPlaintext)
		}
	}

	// Handle rename
	newName := name
	if rename, _ := cmd.Flags().GetString("name"); rename != "" {
		newName = rename
	}

	// Handle notes update
	notes := sec.Notes
	if cmdNotes, _ := cmd.Flags().GetString("notes"); cmd.Flag("notes").Changed {
		notes = cmdNotes
	}

	// Handle kind change
	kind := sec.Kind
	if kindStr, _ := cmd.Flags().GetString("type"); kindStr != "" {
		if !secret.IsValidKind(kindStr) {
			return fmt.Errorf("error: invalid type %q (valid: %v)", kindStr, secret.ValidKinds())
		}
		kind = secret.Kind(kindStr)
	}

	// Encrypt the new value
	ciphertext, nonce, err = engine.Encrypt(newValue, key)
	if err != nil {
		return fmt.Errorf("error: encrypt: %w", err)
	}

	encryptedBlob := packEnvelope(nonce, ciphertext)

	// Delete the old secret first, then store the updated one
	// (Store uses INSERT with UNIQUE constraint on name)
	if err := deleteByName(s, key, name); err != nil { // hard Delete: internal replace, not user deletion
		return fmt.Errorf("error: %w", err)
	}

	updatedSec := secret.NewSecret(sec.ID, newName, kind, encryptedBlob, notes, sec.Tags)
	updatedSec, err = encryptSecretMetadata(updatedSec, engine, key)
	if err != nil {
		return fmt.Errorf("error: encrypt metadata: %w", err)
	}
	if err := s.Store(updatedSec); err != nil {
		return fmt.Errorf("error: store: %w", err)
	}

	// Log audit entry
	details := fmt.Sprintf("kind=%s", kind)
	if newName != name {
		details += fmt.Sprintf(" renamed_from=%s", name)
	}
	if err := s.LogAction("secret_edit", newName, details); err != nil {
		return fmt.Errorf("error: log audit: %w", err)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		out := map[string]string{"status": "ok", "name": newName}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	} else {
		if newName != name {
			fmt.Fprintf(os.Stderr, "Secret %q updated (renamed to %q).\n", name, newName)
		} else {
			fmt.Fprintf(os.Stderr, "Secret %q updated.\n", name)
		}
	}

	return nil
}
