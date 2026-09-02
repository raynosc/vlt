package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/otp"
	"github.com/raynosc/vlt/internal/parse"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
)

func newAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add [name]",
		Short: "Add a new secret",
		Long: `Add a new encrypted secret to the vault.

Prompts for the master password and the secret value. The value is encrypted
with AES-256-GCM before storage.

Use --file <path> to import a certificate or SSH key from a file (auto-detects format).
When using --file, the name is optional — it defaults to the file basename.
Use --password <password> for PKCS12 decryption password.
Use --stdin to read the secret from standard input.
Use --tags to add comma-separated tags for searchability.
Use --overwrite to replace an existing secret with the same name.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runAdd,
	}

	cmd.Flags().String("file", "", "path to certificate/key file for import")
	cmd.Flags().String("password", "", "password for PKCS12 bundle decryption")
	cmd.Flags().Bool("stdin", false, "read secret value from stdin")
	cmd.Flags().String("tags", "", "comma-separated tags")
	cmd.Flags().String("notes", "", "optional notes")
	cmd.Flags().String("type", string(secret.KindOther), "secret type (password, api_key, certificate, ssh_key, note, other)")
	cmd.Flags().String("otp", "", "OTPAuth URI or base32 secret for TOTP 2FA code generation")
	cmd.Flags().Bool("overwrite", false, "overwrite existing secret with the same name")
	return cmd
}

func runAdd(cmd *cobra.Command, args []string) error {
	var name string
	if len(args) > 0 {
		name = args[0]
	}
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	filePath, _ := cmd.Flags().GetString("file")

	if filePath != "" {
		return runAddFromFile(cmd, name, vaultPath, filePath)
	}

	password, _ := cmd.Flags().GetString("password")
	if password != "" {
		return fmt.Errorf("error: --password is only valid with --file")
	}

	if name == "" {
		return fmt.Errorf("error: name is required (or use --file for auto-generated name)")
	}

	// Unlock vault (prompt for master password, derive key)
	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	defer crypto.Zeroize(key)

	// Get the secret value
	secretValue, err := readSecretValue(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	defer crypto.Zeroize(secretValue)

	if len(secretValue) == 0 {
		return fmt.Errorf("error: secret value must not be empty")
	}

	tags, _ := cmd.Flags().GetString("tags")
	notes, _ := cmd.Flags().GetString("notes")
	kind := secret.KindOther
	if kindStr, _ := cmd.Flags().GetString("type"); kindStr != "" {
		if !secret.IsValidKind(kindStr) {
			return fmt.Errorf("error: invalid type %q (valid: %v)", kindStr, secret.ValidKinds())
		}
		kind = secret.Kind(kindStr)
	}

	// Check for existing secret - delete first if --overwrite
	overwrite, _ := cmd.Flags().GetBool("overwrite")
	if overwrite {
		if err := deleteByName(s, key, name); err != nil && !errors.Is(err, store.ErrNotFound) { // hard Delete: internal replace, not user deletion
			return fmt.Errorf("error: %w", err)
		}
	} else {
		_, err := getByName(s, key, name)
		if err == nil {
			return fmt.Errorf("error: secret %q already exists. Use --overwrite to replace", name)
		}
		if !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("error: %w", err)
		}
	}

	// Encrypt the value
	ciphertext, nonce, err := engine.Encrypt(secretValue, key)
	if err != nil {
		return fmt.Errorf("error: encrypt: %w", err)
	}

	encryptedBlob := packEnvelope(nonce, ciphertext)

	otpFlag, _ := cmd.Flags().GetString("otp")
	var otpSeedBlob []byte
	var metadataStr string
	if otpFlag != "" {
		otpURI := otpFlag
		if !strings.HasPrefix(otpURI, "otpauth://") && !strings.HasPrefix(otpURI, "steam://") {
			otpURI = fmt.Sprintf("otpauth://totp/%s?secret=%s", name, strings.ToUpper(strings.TrimSpace(otpURI)))
		}
		var err error
		otpSeedBlob, err = encryptOTPSeed(otpURI, key)
		if err != nil {
			return fmt.Errorf("error: encrypt otp seed: %w", err)
		}
		meta := &secret.PasswordMetadata{
			OTPAuth: otp.RedactOTPAuth(otpURI),
		}
		metadataStr = secret.MarshalPasswordMetadata(meta)
	}

	sec := secret.NewSecret("", name, kind, encryptedBlob, notes, tags)
	sec.EncryptedOTPSeed = otpSeedBlob
	sec.Metadata = metadataStr
	sec, err = encryptSecretMetadata(sec, engine, key)
	if err != nil {
		return fmt.Errorf("error: encrypt metadata: %w", err)
	}
	if err := s.Store(sec); err != nil {
		return fmt.Errorf("error: store: %w", err)
	}

	// Log audit entry
	if err := s.LogAction("secret_add", name, string(kind)); err != nil {
		return fmt.Errorf("error: log audit: %w", err)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		out := map[string]string{"status": "ok", "name": name}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	} else {
		fmt.Fprintf(os.Stderr, "Secret %q stored successfully.\n", name)
	}

	return nil
}

// runAddFromFile handles importing a certificate/key file.
func runAddFromFile(cmd *cobra.Command, name, vaultPath, filePath string) error {
	// Auto-generate name from file basename if not provided
	if name == "" {
		name = autoGenerateName(filePath)
	}

	// Read file bytes
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("error: file not found: %s", filePath)
		}
		return fmt.Errorf("error: read file: %w", err)
	}
	defer crypto.Zeroize(data)

	// Detect format
	format, err := parse.Detect(data)
	if err != nil {
		if errors.Is(err, parse.ErrUnsupportedKeyType) {
			return fmt.Errorf("error: %v", err)
		}
		return fmt.Errorf("error: %v", err)
	}

	// Get optional PKCS12 password
	p12Password, _ := cmd.Flags().GetString("password")

	// Parse based on detected format
	var meta *parse.Metadata
	var kind secret.Kind

	switch format {
	case parse.FormatX509PEM:
		meta, err = parse.ParseX509(data)
		kind = secret.KindCertificate
	case parse.FormatSSHPrivate:
		meta, err = parse.ParseSSHPrivate(data)
		kind = secret.KindSSHKey
	case parse.FormatSSHPublic:
		meta, err = parse.ParseSSHPublic(data)
		kind = secret.KindSSHKey
	case parse.FormatPKCS12:
		if p12Password == "" {
			return fmt.Errorf("error: PKCS12 file requires --password flag")
		}
		meta, err = parse.ParsePKCS12(data, p12Password)
		kind = secret.KindCertificate
	default:
		return fmt.Errorf("error: unsupported file format: %s", filePath)
	}
	if err != nil {
		if errors.Is(err, parse.ErrWrongPassword) {
			return fmt.Errorf("error: %v (wrong --password?)", err)
		}
		return fmt.Errorf("error: parse: %v", err)
	}

	// Auto-generate name from file basename if --name not provided (name is arg[0])
	// name is already the first arg — use it as-is

	// Marshal metadata to JSON
	var metadataStr string
	if meta != nil {
		metaBytes, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("error: marshal metadata: %w", err)
		}
		metadataStr = string(metaBytes)
	}

	// Override kind if --type was explicitly provided
	if kindStr, _ := cmd.Flags().GetString("type"); kindStr != "" && cmd.Flag("type").Changed {
		if !secret.IsValidKind(kindStr) {
			return fmt.Errorf("error: invalid type %q (valid: %v)", kindStr, secret.ValidKinds())
		}
		kind = secret.Kind(kindStr)
	}

	tags, _ := cmd.Flags().GetString("tags")
	notes, _ := cmd.Flags().GetString("notes")

	// Unlock vault
	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	defer crypto.Zeroize(key)

	// Check for existing secret
	overwrite, _ := cmd.Flags().GetBool("overwrite")
	if overwrite {
		if err := deleteByName(s, key, name); err != nil && !errors.Is(err, store.ErrNotFound) { // hard Delete: internal replace, not user deletion
			return fmt.Errorf("error: %w", err)
		}
	} else {
		_, err := getByName(s, key, name)
		if err == nil {
			return fmt.Errorf("error: secret %q already exists. Use --overwrite to replace", name)
		}
		if !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("error: %w", err)
		}
	}

	// Encrypt the original file bytes
	ciphertext, nonce, err := engine.Encrypt(data, key)
	if err != nil {
		return fmt.Errorf("error: encrypt: %w", err)
	}
	encryptedBlob := packEnvelope(nonce, ciphertext)

	// Create and store the secret
	sec := secret.Secret{
		Name:           name,
		Kind:           kind,
		EncryptedValue: encryptedBlob,
		Notes:          notes,
		Tags:           tags,
		Metadata:       metadataStr,
	}
	sec, err = encryptSecretMetadata(sec, engine, key)
	if err != nil {
		return fmt.Errorf("error: encrypt metadata: %w", err)
	}

	if err := s.Store(sec); err != nil {
		return fmt.Errorf("error: store: %w", err)
	}

	// Log audit entry
	details := fmt.Sprintf("file=%s kind=%s", filepath.Base(filePath), kind)
	if err := s.LogAction("secret_add", name, details); err != nil {
		return fmt.Errorf("error: log audit: %w", err)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		out := map[string]string{"status": "ok", "name": name, "kind": string(kind)}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	} else {
		fmt.Fprintf(os.Stderr, "Imported %q as %s (kind=%s).\n", name, filepath.Base(filePath), kind)
	}

	return nil
}

// readSecretValue reads the secret value from --stdin or prompts interactively.
// The interactive prompt uses hidden input to avoid exposing the secret in
// terminal output, shell history, or screen recordings.
func readSecretValue(cmd *cobra.Command) ([]byte, error) {
	if stdin, _ := cmd.Flags().GetBool("stdin"); stdin {
		reader := bufio.NewReader(os.Stdin)
		val, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		// Trim trailing newline if present
		if len(val) > 0 && val[len(val)-1] == '\n' {
			val = val[:len(val)-1]
		}
		return []byte(val), nil
	}

	// Prompt interactively (hidden input)
	pw, err := promptPassword("Secret value: ")
	if err != nil {
		return nil, err
	}
	return pw, nil
}

// autoGenerateName extracts a name from the file path (basename without extension).
func autoGenerateName(filePath string) string {
	base := filepath.Base(filePath)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}
