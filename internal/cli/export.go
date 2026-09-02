package cli

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
)

// passwordExportRecord is the standard export format.
type passwordExportRecord struct {
	Title    string `json:"Title"`
	URL      string `json:"Url,omitempty"`
	Username string `json:"Username,omitempty"`
	Password string `json:"Password"`
	OTPAuth  string `json:"OTPAuth,omitempty"`
	Tags     string `json:"Tags,omitempty"`
	Notes    string `json:"Notes,omitempty"`
}

func newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export secrets from the vault",
		Long: `Export secrets from the vault.

Exports all secrets as CSV (semicolon-delimited) or JSON in standard portable format.
Exports certificates and SSH keys as files (decrypted) when --kind is specified.

By default, exports all secrets regardless of kind.
Use --format json for JSON output.
Use --kind to filter by a specific secret kind (password, certificate, ssh_key).
Use --output to specify a directory for file exports (certificates, SSH keys).`,
		Args: cobra.NoArgs,
		RunE: runExport,
	}

	cmd.Flags().String("format", "csv", "export format: csv or json (for password kind)")
	cmd.Flags().String("kind", "", "secret kind to export (password, certificate, ssh_key, ...); empty = all kinds")
	cmd.Flags().String("output", ".", "output directory for file exports (certificates/keys)")
	cmd.Flags().Bool("force", false, "skip confirmation prompt (required for non-interactive use)")
	return cmd
}

func runExport(cmd *cobra.Command, _ []string) error {
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	format, _ := cmd.Flags().GetString("format")
	kindFilter, _ := cmd.Flags().GetString("kind")
	outputDir, _ := cmd.Flags().GetString("output")

	// Unlock vault
	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	// List all secrets
	all, err := s.List()
	if err != nil {
		return fmt.Errorf("error: list: %w", err)
	}

	// Decrypt metadata so we can filter by kind and use names
	for i := range all {
		if err := decryptSecretMetadata(&all[i], key); err != nil {
			return fmt.Errorf("error: decrypt metadata: %w", err)
		}
	}

	// Filter by kind
	var filtered []secret.Secret
	for _, sec := range all {
		if kindFilter != "" && string(sec.Kind) != kindFilter {
			continue
		}
		filtered = append(filtered, sec)
	}

	if len(filtered) == 0 {
		fmt.Fprintf(os.Stderr, "No secrets found matching kind %q.\n", kindFilter)
		return nil
	}

	// Confirmation prompt before exporting decrypted secrets
	force, _ := cmd.Flags().GetBool("force")
	if err := confirmExport(len(filtered), force); err != nil {
		return err
	}

	// Log audit entry for the export
	details := fmt.Sprintf("kind=%s count=%d", kindFilter, len(filtered))
	if err := s.LogAction("secret_export", "", details); err != nil {
		return fmt.Errorf("error: log audit: %w", err)
	}

	// Route to the right export handler based on kind
	switch secret.Kind(kindFilter) {
	case secret.KindPassword:
		return exportPasswords(filtered, s, key, format, outputDir)
	case secret.KindCertificate, secret.KindSSHKey:
		return exportFiles(filtered, s, key, outputDir)
	default:
		return exportPasswords(filtered, s, key, format, outputDir)
	}
}

// exportPasswords exports password secrets as CSV or JSON to a file.
func exportPasswords(secrets []secret.Secret, st *store.SQLStore, key []byte, format, outputDir string) error {
	// Get full secret data (with encrypted values)
	fullSecrets := make([]secret.Secret, 0, len(secrets))
	for _, sec := range secrets {
		full, err := getByName(st, key, sec.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not load %q: %v\n", sec.Name, err)
			continue
		}
		fullSecrets = append(fullSecrets, full)
	}

	// Decrypt and build export records
	var records []passwordExportRecord
	for _, sec := range fullSecrets {
		if len(sec.EncryptedValue) == 0 {
			continue
		}
		nonce, ciphertext, err := unpackEnvelope(sec.EncryptedValue)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: invalid envelope for %q: %v\n", sec.Name, err)
			continue
		}
		plaintext, err := engine.Decrypt(ciphertext, key, nonce)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: decryption failed for %q: %v\n", sec.Name, err)
			continue
		}
		// MED-04: Do NOT use defer inside loops — it accumulates all plaintexts
		// in memory until function return. Zeroize manually at end of iteration.

		// Extract metadata
		meta := secret.UnmarshalPasswordMetadata(sec.Metadata)

		rec := passwordExportRecord{
			Title:    sec.Name,
			Password: string(plaintext),
			Tags:     sec.Tags,
			Notes:    sec.Notes,
		}
		if meta != nil {
			rec.URL = meta.URL
			rec.Username = meta.Username
			rec.OTPAuth = meta.OTPAuth
		}
		records = append(records, rec)
		crypto.Zeroize(plaintext)
	}

	switch strings.ToLower(format) {
	case "json":
		return encodeJSONExport(records, outputDir)
	default:
		return encodeCSVExport(records, outputDir)
	}
}

// encodeCSVExport writes export records as semicolon-delimited CSV to a file.
func encodeCSVExport(records []passwordExportRecord, outputDir string) error {
	outPath := filepath.Join(outputDir, "vlt-export.csv")
	// HIGH-05: Use restrictive permissions — export contains plaintext secrets
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer func() { _ = f.Close() }()

	w := csv.NewWriter(f)
	w.Comma = ';'

	if err := w.Write([]string{"Title", "Url", "Username", "Password", "OTPAuth", "Tags", "Notes"}); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}
	for _, rec := range records {
		row := []string{rec.Title, rec.URL, rec.Username, rec.Password, rec.OTPAuth, rec.Tags, rec.Notes}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("csv flush: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Exported %d secrets to %s\n", len(records), outPath)
	return nil
}

// encodeJSONExport writes export records as JSON array to a file.
func encodeJSONExport(records []passwordExportRecord, outputDir string) error {
	outPath := filepath.Join(outputDir, "vlt-export.json")
	// HIGH-05: Use restrictive permissions — export contains plaintext secrets
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(records); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Exported %d secrets to %s\n", len(records), outPath)
	return nil
}

// exportFiles exports non-password secrets (certificates, SSH keys) as files.
func exportFiles(secrets []secret.Secret, st *store.SQLStore, key []byte, outputDir string) error {
	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	count := 0
	for _, sec := range secrets {
		full, err := getByName(st, key, sec.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not load %q: %v\n", sec.Name, err)
			continue
		}
		if len(full.EncryptedValue) == 0 {
			continue
		}

		nonce, ciphertext, err := unpackEnvelope(full.EncryptedValue)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: invalid envelope for %q: %v\n", full.Name, err)
			continue
		}
		plaintext, err := engine.Decrypt(ciphertext, key, nonce)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: decryption failed for %q: %v\n", full.Name, err)
			continue
		}
		// MED-04: Manual zeroize instead of defer in loop

		// Determine file extension based on kind
		ext := fileExtensionForKind(full.Kind, plaintext)
		outPath := filepath.Join(outputDir, full.Name+ext)

		if err := os.WriteFile(outPath, plaintext, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not write %q: %v\n", outPath, err)
			continue
		}
		count++
		crypto.Zeroize(plaintext)
	}

	fmt.Fprintf(os.Stderr, "Exported %d secrets to %s\n", count, outputDir)
	return nil
}

// confirmExport prompts the user to confirm export of N plaintext secrets.
// If force is true, skips the prompt.
// If the terminal is not interactive, force must be true.
func confirmExport(count int, force bool) error {
	if force {
		return nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("non-interactive mode requires --force to export %d plaintext secrets", count)
	}

	fmt.Fprintf(os.Stderr, "Export %d plaintext secret(s)? This will write decrypted values to disk. [y/N] ", count)
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read confirmation: %w", err)
	}
	response = strings.TrimSpace(strings.ToLower(response))
	if response != "y" && response != "yes" {
		return fmt.Errorf("export cancelled")
	}
	return nil
}

// fileExtensionForKind returns the appropriate file extension for a secret kind.
func fileExtensionForKind(kind secret.Kind, data []byte) string {
	switch kind {
	case secret.KindCertificate:
		return ".pem"
	case secret.KindSSHKey:
		dataStr := string(data)
		if strings.Contains(dataStr, "PUBLIC KEY") || strings.Contains(dataStr, "ssh-") {
			return ".pub"
		}
		return ".key"
	case secret.KindNote:
		return ".txt"
	default:
		return ".bin"
	}
}
