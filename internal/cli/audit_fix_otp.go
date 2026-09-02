package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/otp"
	"github.com/raynosc/vlt/internal/secret"
)

// newAuditFixOTPLeakCmd builds `vlt audit fix-otp-leak`, the migration that
// closes S-02 for vaults created before the fix. Those vaults still hold the
// real TOTP/HOTP seed in the plaintext metadata column. This command unlocks
// the vault, re-encrypts each leaked seed into the dedicated encrypted_otp_seed
// column, and redacts the metadata URI — exactly what fresh imports now do.
func newAuditFixOTPLeakCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fix-otp-leak",
		Short: "Re-encrypt OTP seeds left in plaintext metadata by older vaults (S-02)",
		Long: `Scan the vault for secrets whose OTP seed is still stored in the
plaintext metadata column (vaults created before the S-02 fix) and move each
seed into the encrypted_otp_seed column, redacting the metadata.

Requires unlocking the vault. Use --dry-run to report what would change without
modifying anything.`,
		Args: cobra.NoArgs,
		RunE: runAuditFixOTPLeak,
	}
	cmd.Flags().Bool("dry-run", false, "report leaked seeds without modifying the vault")
	return cmd
}

func runAuditFixOTPLeak(cmd *cobra.Command, _ []string) error {
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	if err := requireVaultExists(vaultPath); err != nil {
		return err
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")

	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	defer crypto.Zeroize(key)

	// List returns metadata only (EncryptedValue is nil), which is all we need
	// to find leaks; the full record is fetched per-secret before re-storing.
	secrets, err := s.List()
	if err != nil {
		return fmt.Errorf("error: list secrets: %w", err)
	}

	fixed := 0
	for _, listed := range secrets {
		if err := decryptSecretMetadata(&listed, key); err != nil {
			continue
		}
		meta := secret.UnmarshalPasswordMetadata(listed.Metadata)
		if meta == nil || meta.OTPAuth == "" {
			continue
		}
		// A leak is a parseable URI whose secret is present and not already
		// redacted. Anything else (no secret, already REDACTED) is skipped.
		uri, perr := otp.ParseOTPURI(meta.OTPAuth)
		if perr != nil || uri.Secret == "" || uri.Secret == secret.OTPAuthRedactedMarker {
			continue
		}

		if dryRun {
			fmt.Fprintf(os.Stderr, "Would fix: %q (OTP seed in plaintext metadata)\n", listed.Name)
			fixed++
			continue
		}

		// Fetch the full record so re-storing preserves EncryptedValue.
		lookup := crypto.ComputeNameLookup(key, listed.Name)
		full, err := s.GetByNameLookup(lookup)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %q: %v\n", listed.Name, err)
			continue
		}
		// Already migrated (seed lives in the encrypted column) — only the stale
		// plaintext metadata needs scrubbing, never a re-encrypt.
		seedBlob := full.EncryptedOTPSeed
		if len(seedBlob) == 0 {
			seedBlob, err = encryptOTPSeed(meta.OTPAuth, key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error encrypting seed for %q: %v\n", listed.Name, err)
				continue
			}
		}
		// Redact the metadata URI. MarshalPasswordMetadata also scrubs as a
		// defence-in-depth measure, but redact explicitly so intent is clear.
		meta.OTPAuth = otp.RedactOTPAuth(meta.OTPAuth)
		newMetadata := secret.MarshalPasswordMetadata(meta)

		// Encrypt the new metadata before storing.
		ct, nonce, err := engine.Encrypt([]byte(newMetadata), key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting metadata for %q: %v\n", listed.Name, err)
			continue
		}
		encryptedMetadata := crypto.PackEnvelope(nonce, ct)

		// Atomic single-statement update: a crash can never leave the secret
		// missing (delete-then-insert had a data-loss window).
		if err := s.UpdateOTPSeedAndMetadata(lookup, seedBlob, encryptedMetadata); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating %q: %v\n", listed.Name, err)
			continue
		}
		fixed++
	}

	if dryRun {
		fmt.Fprintf(os.Stderr, "Dry run: %d secret(s) have OTP seeds in plaintext metadata\n", fixed)
		return nil
	}

	if fixed > 0 {
		if err := s.LogAction("otp_leak_fixed", "", fmt.Sprintf("migrated=%d", fixed)); err != nil {
			return fmt.Errorf("error: log audit: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "Fixed %d secret(s) with OTP seeds in plaintext metadata\n", fixed)
	return nil
}
