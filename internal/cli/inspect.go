package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/parse"
)

func newInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <file>",
		Short: "Parse and display certificate/key metadata (read-only)",
		Long: `Parse and display certificate or key metadata from a file.

Reads a certificate or key file, detects its format, parses it, and displays
all metadata fields. This command does NOT require a master password and does
NOT store anything in the vault — it is purely a read-only analysis tool.

Use --password <password> for PKCS12 bundle decryption.
Use --json for machine-readable output (JSON dump of the Metadata struct).`,
		Args: cobra.ExactArgs(1),
		RunE: runInspect,
	}

	cmd.Flags().String("password", "", "password for PKCS12 bundle decryption")
	return cmd
}

func runInspect(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// Read file bytes
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("error: file not found: %s", filePath)
		}
		return fmt.Errorf("error: read file: %w", err)
	}

	// Detect format
	format, err := parse.Detect(data)
	if err != nil {
		if errors.Is(err, parse.ErrUnsupportedKeyType) {
			return fmt.Errorf("error: %v", err)
		}
		return fmt.Errorf("error: %v", err)
	}

	// Get optional password
	password, _ := cmd.Flags().GetString("password")

	// Parse based on detected format
	var meta *parse.Metadata
	switch format {
	case parse.FormatX509PEM:
		meta, err = parse.ParseX509(data)
	case parse.FormatSSHPrivate:
		meta, err = parse.ParseSSHPrivate(data)
	case parse.FormatSSHPublic:
		meta, err = parse.ParseSSHPublic(data)
	case parse.FormatPKCS12:
		if password == "" {
			return fmt.Errorf("error: PKCS12 file requires --password flag")
		}
		meta, err = parse.ParsePKCS12(data, password)
	default:
		return fmt.Errorf("error: unsupported file format: %s", filePath)
	}
	if err != nil {
		if errors.Is(err, parse.ErrWrongPassword) {
			return fmt.Errorf("error: %v (wrong --password?)", err)
		}
		return fmt.Errorf("error: parse: %v", err)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		b, _ := json.MarshalIndent(meta, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	// Human-readable output
	printInspectHuman(format, meta)
	return nil
}

// printInspectHuman prints metadata in human-readable format.
func printInspectHuman(format parse.Format, meta *parse.Metadata) {
	switch format {
	case parse.FormatX509PEM:
		fmt.Println("Format:        X.509 Certificate")
		if meta.SubjectCN != "" {
			fmt.Println("Subject:       " + formatDN(meta.SubjectCN))
		}
		if meta.IssuerCN != "" {
			fmt.Println("Issuer:        " + formatDN(meta.IssuerCN))
		}
		if meta.NotBefore != "" && meta.NotAfter != "" {
			fmt.Printf("Valid:         %s to %s", meta.NotBefore[:10], meta.NotAfter[:10])
			if !meta.IsExpired() {
				fmt.Printf(" (expires in %d days)", meta.DaysUntilExpiry())
			} else {
				fmt.Print(" (EXPIRED)")
			}
			fmt.Println()
		}
		if meta.FingerprintSHA1 != "" {
			fmt.Println("Fingerprints:  SHA-1:  " + formatFingerprint(meta.FingerprintSHA1))
		}
		if meta.FingerprintSHA256 != "" {
			fmt.Println("               SHA-256: " + formatFingerprint(meta.FingerprintSHA256))
		}
		if len(meta.SANs) > 0 {
			fmt.Println("SANs:          " + strings.Join(meta.SANs, ", "))
		}
		if len(meta.KeyUsage) > 0 {
			fmt.Println("Key Usage:     " + strings.Join(meta.KeyUsage, ", "))
		}
		if len(meta.ExtKeyUsage) > 0 {
			fmt.Println("Ext Key Usage: " + strings.Join(meta.ExtKeyUsage, ", "))
		}
		if meta.SerialNumber != "" {
			fmt.Println("Serial:        " + meta.SerialNumber)
		}
		if meta.SignatureAlgorithm != "" {
			fmt.Println("Sig Algorithm: " + meta.SignatureAlgorithm)
		}
		if meta.IsCA {
			fmt.Println("CA:            true")
		}

	case parse.FormatSSHPrivate, parse.FormatSSHPublic:
		if format == parse.FormatSSHPrivate {
			fmt.Println("Format:        SSH Private Key")
		} else {
			fmt.Println("Format:        SSH Public Key")
		}
		if meta.KeyType != "" {
			fmt.Println("Key Type:      " + meta.KeyType)
		}
		if meta.BitLength > 0 {
			fmt.Printf("Bit Length:    %d\n", meta.BitLength)
		}
		if meta.FingerprintSHA256 != "" {
			fmt.Println("Fingerprint:   SHA256:" + meta.FingerprintSHA256)
		}
		if meta.Comment != "" {
			fmt.Println("Comment:       " + meta.Comment)
		}

	case parse.FormatPKCS12:
		fmt.Println("Format:        PKCS#12 Bundle")
		if meta.CertCount > 0 {
			fmt.Printf("Certificates:  %d\n", meta.CertCount)
		}
		if len(meta.FriendlyNames) > 0 {
			fmt.Println("Friendly Names: " + strings.Join(meta.FriendlyNames, ", "))
		}
		// Also show the parsed cert metadata if available
		if meta.SubjectCN != "" {
			fmt.Println("Subject:       " + formatDN(meta.SubjectCN))
		}
		if meta.NotBefore != "" && meta.NotAfter != "" {
			fmt.Printf("Valid:         %s to %s", meta.NotBefore[:10], meta.NotAfter[:10])
			if !meta.IsExpired() {
				fmt.Printf(" (expires in %d days)", meta.DaysUntilExpiry())
			} else {
				fmt.Print(" (EXPIRED)")
			}
			fmt.Println()
		}
	}
}

// formatFingerprint formats a hex fingerprint with colons for readability.
func formatFingerprint(hex string) string {
	if len(hex) == 0 {
		return ""
	}
	var parts []string
	for i := 0; i < len(hex); i += 2 {
		if i+2 <= len(hex) {
			parts = append(parts, strings.ToUpper(hex[i:i+2]))
		}
	}
	return strings.Join(parts, ":")
}

// formatDN provides a simple display format for a common name.
func formatDN(cn string) string {
	return cn
}
