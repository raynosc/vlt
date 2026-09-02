package cli

import (
	"encoding/json"
	"fmt"
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

func newImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import secrets from a CSV/JSON export file or QR code",
		Long: `Import secrets from a CSV or JSON export file,
or from a QR code image using the --qr flag.

Supports CSV files (comma/semicolon-delimited) and JSON files.
The format is auto-detected from the file extension (.csv or .json).

CSV format example:
  Title;Url;Username;Password;OTPAuth;Favorite;Archived;Tags;Notes

JSON format example:
  [{"Title":"...","Url":"...","Username":"...","Password":"...","OTPAuth":"...","Tags":"...","Notes":"..."}]

QR import (--qr flag):
  Decodes a QR code image containing an otpauth:// URI and stores it as a
  new secret with the OTPAuth metadata.

Use --dry-run to parse and validate without storing anything.
Use --overwrite to replace existing secrets with the same name.`,
		Args: cobra.ExactArgs(1),
		RunE: runImport,
	}

	cmd.Flags().Bool("dry-run", false, "parse and validate only — do not store")
	cmd.Flags().Bool("overwrite", false, "overwrite existing secrets with the same name")
	cmd.Flags().Bool("qr", false, "import from a QR code image containing an otpauth:// URI")
	return cmd
}

func runImport(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")
	overwrite, _ := cmd.Flags().GetBool("overwrite")
	qrFlag, _ := cmd.Flags().GetBool("qr")

	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("error: file not found: %s", filePath)
		}
		return fmt.Errorf("error: read file: %w", err)
	}

	// QR import path
	if qrFlag {
		return runQRImport(cmd, filePath, data, vaultPath, dryRun, overwrite)
	}

	// Detect format from extension
	ext := strings.ToLower(filepath.Ext(filePath))
	var records []parse.Record
	switch ext {
	case ".csv":
		records, err = parse.ParsePasswordCSV(data)
	case ".json":
		records, err = parseOPJSON(data)
	default:
		return fmt.Errorf("error: unsupported file format %q (use .csv or .json)", ext)
	}
	if err != nil {
		return fmt.Errorf("error: parse %s: %w", filePath, err)
	}

	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "No records found in import file.")
		return nil
	}

	// Unlock vault (skip for dry-run if we just want to validate parsing)
	var s *store.SQLStore
	var key []byte
	if !dryRun {
		var err error
		s, key, err = unlockVault(vaultPath)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()
		defer crypto.Zeroize(key)
	}

	imported := 0
	skipped := 0
	errCount := 0

	for _, rec := range records {
		if rec.Title == "" {
			errCount++
			continue
		}
		if rec.Password == "" {
			errCount++
			continue
		}

		// HIGH-01: Redact OTP secret from plaintext metadata.
		// The full OTP URI is encrypted as the secret value.
		meta := &secret.PasswordMetadata{
			URL:      rec.URL,
			Username: rec.Username,
			OTPAuth:  otp.RedactOTPAuth(rec.OTPAuth),
		}
		metadataStr := secret.MarshalPasswordMetadata(meta)

		if dryRun {
			imported++
			continue
		}

		// Check for existing secret
		if !overwrite {
			_, err := getByName(s, key, rec.Title)
			if err == nil {
				skipped++
				continue
			}
		} else {
			_ = deleteByName(s, key, rec.Title) // hard Delete: internal replace, not user deletion
		}

		// Encrypt the password value
		ciphertext, nonce, err := engine.Encrypt([]byte(rec.Password), key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting %q: %v\n", rec.Title, err)
			errCount++
			continue
		}
		encryptedBlob := packEnvelope(nonce, ciphertext)

		// S-02: persist the OTP seed encrypted in its own column instead of
		// leaving it in the (now redacted) plaintext metadata.
		otpSeedBlob, err := encryptOTPSeed(rec.OTPAuth, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting OTP seed for %q: %v\n", rec.Title, err)
			errCount++
			continue
		}
		// Warn on silent seed loss: a non-empty OTPAuth that produced no seed
		// means the URI was unparseable. The record still imports, but the user
		// must know OTP won't work for it rather than discovering it later.
		if rec.OTPAuth != "" && otpSeedBlob == nil {
			fmt.Fprintf(os.Stderr, "Warning: OTP for %q could not be parsed; imported without a working OTP seed\n", rec.Title)
		}

		// Create and store the secret
		sec := secret.Secret{
			Name:             rec.Title,
			Kind:             secret.KindPassword,
			EncryptedValue:   encryptedBlob,
			EncryptedOTPSeed: otpSeedBlob,
			Notes:            rec.Notes,
			Tags:             rec.Tags,
			Metadata:         metadataStr,
		}
		sec, err = encryptSecretMetadata(sec, engine, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting metadata for %q: %v\n", rec.Title, err)
			errCount++
			continue
		}
		if err := s.Store(sec); err != nil {
			fmt.Fprintf(os.Stderr, "Error storing %q: %v\n", rec.Title, err)
			errCount++
			continue
		}
		imported++
	}

	// Log audit entry
	if !dryRun {
		details := fmt.Sprintf("imported=%d skipped=%d errors=%d", imported, skipped, errCount)
		if err := s.LogAction("secret_import", "", details); err != nil {
			return fmt.Errorf("error: log audit: %w", err)
		}
	}

	// Print summary
	if dryRun {
		fmt.Fprintf(os.Stderr, "Dry run: parsed %d records, %d would be imported, %d errors\n",
			len(records), imported, errCount)
	} else {
		fmt.Fprintf(os.Stderr, "Imported %d secrets, skipped %d duplicates, %d errors\n",
			imported, skipped, errCount)
	}

	return nil
}

// parseOPJSON parses a JSON export (array of objects).
func parseOPJSON(data []byte) ([]parse.Record, error) {
	var rawRecords []map[string]interface{}
	if err := json.Unmarshal(data, &rawRecords); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}

	var records []parse.Record
	for _, raw := range rawRecords {
		rec := parse.Record{
			Title:    stringField(raw, "Title"),
			URL:      stringField(raw, "Url"),
			Username: stringField(raw, "Username"),
			Password: stringField(raw, "Password"),
			OTPAuth:  stringField(raw, "OTPAuth"),
			Tags:     stringField(raw, "Tags"),
			Notes:    stringField(raw, "Notes"),
		}
		records = append(records, rec)
	}

	return records, nil
}

// encryptOTPSeed extracts the base32 secret= value from an otpauth:// URI,
// encrypts it with the session key, and returns the nonce||ciphertext envelope
// to store in the encrypted_otp_seed column. Returns (nil, nil) when the URI is
// empty or carries no secret, which callers treat as "no OTP seed".
//
// S-02: the seed must never live in the plaintext metadata column. This is the
// single seal-the-seed path shared by every CLI import route (JSON, CSV, QR).
func encryptOTPSeed(otpauthURI string, key []byte) ([]byte, error) {
	if strings.TrimSpace(otpauthURI) == "" {
		return nil, nil
	}
	uri, err := otp.ParseOTPURI(otpauthURI)
	if err != nil || uri.Secret == "" {
		// Not a parseable OTP URI (e.g. a placeholder value) — nothing to seal.
		return nil, nil
	}
	ciphertext, nonce, err := engine.Encrypt([]byte(uri.Secret), key)
	if err != nil {
		return nil, fmt.Errorf("encrypt otp seed: %w", err)
	}
	return packEnvelope(nonce, ciphertext), nil
}

// runQRImport handles the --qr import path.
// It decodes a QR code image, extracts the OTP URI, parses it,
// and stores the secret with OTPAuth metadata.
func runQRImport(cmd *cobra.Command, filePath string, data []byte, vaultPath string, dryRun, overwrite bool) error {
	// Decode the QR code
	uriStr, err := otp.DecodeQR(data)
	if err != nil {
		return fmt.Errorf("error: decode QR: %w", err)
	}

	// Parse the OTP URI
	uri, err := otp.ParseOTPURI(uriStr)
	if err != nil {
		return fmt.Errorf("error: parse OTP URI: %w", err)
	}

	// Determine the name: issuer:account or just account
	name := uri.Account
	if uri.Issuer != "" {
		name = uri.Issuer + ":" + uri.Account
	}
	if name == "" {
		return fmt.Errorf("error: could not determine secret name from URI")
	}

	if dryRun {
		fmt.Fprintf(os.Stderr, "Would import %q from QR code\n", name)
		return nil
	}

	// Unlock vault
	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	defer crypto.Zeroize(key)

	// Check for existing secret
	if !overwrite {
		_, err := getByName(s, key, name)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Skipped %q (already exists, use --overwrite to replace)\n", name)
			return nil
		}
	} else {
		_ = deleteByName(s, key, name) // hard Delete: internal replace, not user deletion
	}

	// Encrypt the OTP URI as the secret value
	ciphertext, nonce, err := engine.Encrypt([]byte(uriStr), key)
	if err != nil {
		return fmt.Errorf("error: encrypt: %w", err)
	}
	encryptedBlob := packEnvelope(nonce, ciphertext)

	// S-02: keep the seed encrypted in its own column. The seed comes from the
	// already-parsed URI, so reuse uri.Secret instead of re-parsing.
	otpSeedBlob, err := encryptOTPSeed(uriStr, key)
	if err != nil {
		return fmt.Errorf("error: encrypt OTP seed: %w", err)
	}

	// Build metadata with redacted OTPAuth (HIGH-01)
	meta := &secret.PasswordMetadata{
		OTPAuth: otp.RedactOTPAuth(uriStr),
	}
	metaJSON := secret.MarshalPasswordMetadata(meta)

	// Store the secret
	sec := secret.Secret{
		Name:             name,
		Kind:             secret.KindPassword,
		EncryptedValue:   encryptedBlob,
		EncryptedOTPSeed: otpSeedBlob,
		Metadata:         metaJSON,
	}
	sec, err = encryptSecretMetadata(sec, engine, key)
	if err != nil {
		return fmt.Errorf("error: encrypt metadata: %w", err)
	}
	if err := s.Store(sec); err != nil {
		return fmt.Errorf("error: store secret: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Imported %q from QR code\n", name)

	// Log audit
	if err := s.LogAction("secret_import", name, "qr"); err != nil {
		return fmt.Errorf("error: log audit: %w", err)
	}

	return nil
}

// stringField extracts a string from a map, returning empty string if missing.
func stringField(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	val, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := val.(string)
	if !ok {
		return ""
	}
	return s
}
