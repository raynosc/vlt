package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/watchtower"
)

func newCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Validate vault integrity",
		Long: `Check the vault for integrity issues.

Validates the vault for:
  - Duplicate names (data corruption)
  - Expiring certificates (within 30 days)

Use --passwords to also analyze password security (requires master password).`,
		Args: cobra.NoArgs,
		RunE: runCheck,
	}

	cmd.Flags().Int("expiring", 30, "show certificates expiring within N days (0 to disable)")
	cmd.Flags().Bool("passwords", false, "analyze password security (weak, reused, compromised, missing 2FA)")
	cmd.Flags().Bool("offline", false, "disable external API checks (100% offline analysis)")
	cmd.Flags().Duration("pwned-cooldown", watchtower.DefaultPwnedCooldown, "cooldown duration after API connection failure")
	return cmd
}

func runCheck(cmd *cobra.Command, _ []string) error {
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	if err := requireVaultExists(vaultPath); err != nil {
		return err
	}

	checkPasswords, _ := cmd.Flags().GetBool("passwords")
	offlineMode, _ := cmd.Flags().GetBool("offline")
	cooldown, _ := cmd.Flags().GetDuration("pwned-cooldown")

	s, eng, key, err := unlockVaultWithEngine(vaultPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	defer crypto.Zeroize(key)

	all, err := s.List()
	if err != nil {
		return fmt.Errorf("error: list: %w", err)
	}
	for i := range all {
		if err := decryptSecretMetadata(&all[i], key); err != nil {
			return fmt.Errorf("error: decrypt metadata: %w", err)
		}
	}

	issuesFound := 0

	// Check for duplicate names
	seen := make(map[string]int)
	for _, sec := range all {
		seen[sec.Name]++
	}
	for name, count := range seen {
		if count > 1 {
			fmt.Fprintf(os.Stderr, "WARNING: duplicate name %q found (%d occurrences) — data may be corrupted\n", name, count)
			issuesFound++
		}
	}

	// Check for expiring certificates
	expiringDays, _ := cmd.Flags().GetInt("expiring")
	if expiringDays > 0 {
		expiring, err := listExpiring(s, key, expiringDays)
		if err != nil {
			return fmt.Errorf("error: list expiring: %w", err)
		}
		if len(expiring) > 0 {
			fmt.Fprintf(os.Stderr, "⚠️  %d certificate(s) expiring within %d days:\n", len(expiring), expiringDays)
			for _, sec := range expiring {
				fmt.Fprintf(os.Stderr, "  - %s\n", sec.Name)
			}
			issuesFound++
		}
	}

	// Password security analysis
	if checkPasswords {
		pwnedMgr := watchtower.NewPwnedManager(cooldown)
		if offlineMode {
			pwnedMgr.SetDisabled(true)
		}

		result, err := watchtower.AnalyzeWithPwned(s, eng, key, pwnedMgr)
		if err != nil {
			return fmt.Errorf("error: password analysis: %w", err)
		}

		if len(result.CompromisedPasswords) > 0 {
			fmt.Fprintf(os.Stderr, "\n🚨 COMPROMISED PASSWORDS IN KNOWN BREACHES (%d):\n", len(result.CompromisedPasswords))
			for _, c := range result.CompromisedPasswords {
				itemText := c.SecretName
				if c.Username != "" {
					itemText += " — " + c.Username
				}
				fmt.Fprintf(os.Stderr, "  - %s (found %d times in public data breaches)\n", itemText, c.BreachCount)
			}
			issuesFound += len(result.CompromisedPasswords)
		}

		if result.SecretsWithWeakPass > 0 {
			fmt.Fprintf(os.Stderr, "\n⚠️  WEAK PASSWORDS (%d):\n", result.SecretsWithWeakPass)
			for _, w := range result.WeakPasswords {
				itemText := w.SecretName
				if w.Username != "" {
					itemText += " — " + w.Username
				}
				fmt.Fprintf(os.Stderr, "  - %s: %s\n", itemText, w.Reason)
			}
			issuesFound += result.SecretsWithWeakPass
		}

		if len(result.DuplicatePasswords) > 0 {
			fmt.Fprintf(os.Stderr, "\n⚠️  REUSED PASSWORDS (%d):\n", len(result.DuplicatePasswords))
			for _, d := range result.DuplicatePasswords {
				fmt.Fprintf(os.Stderr, "  - Same password used across: %s\n", strings.Join(d.SecretNames, ", "))
			}
			issuesFound += len(result.DuplicatePasswords)
		}

		if result.SecretsWithNoOTP > 0 {
			fmt.Fprintf(os.Stderr, "\n⚠️  MISSING TWO-FACTOR AUTH (%d):\n", result.SecretsWithNoOTP)
			for _, m := range result.Missing2FA {
				itemText := m.SecretName
				if m.Username != "" {
					itemText += " — " + m.Username
				}
				fmt.Fprintf(os.Stderr, "  - %s (%s)\n", itemText, m.URL)
			}
			issuesFound += result.SecretsWithNoOTP
		}

		if result.IsOfflineMode {
			fmt.Fprintf(os.Stderr, "\nℹ️  Pwned Passwords API check was skipped: %s\n", result.OfflineReason)
		}

		if result.AnalyzedPasswordCount > 0 && issuesFound == 0 {
			fmt.Fprintf(os.Stderr, "%d password(s) analyzed — no issues found.\n", result.AnalyzedPasswordCount)
		}
	}

	// Log audit entry
	details := fmt.Sprintf("issues=%d", issuesFound)
	if expiringDays > 0 {
		details += fmt.Sprintf(" expiring_window=%d", expiringDays)
	}
	if checkPasswords {
		details += " passwords=true"
	}
	if err := s.LogAction("vault_check", "", details); err != nil {
		return fmt.Errorf("error: log audit: %w", err)
	}

	if issuesFound == 0 {
		fmt.Fprintf(os.Stderr, "Vault check passed — no issues found.\n")
	} else {
		fmt.Fprintf(os.Stderr, "\n%d issue(s) found.\n", issuesFound)
		if expiringDays == 0 {
			fmt.Fprintf(os.Stderr, "Use --expiring <days> to check for expiring certificates.\n")
		}
	}

	return nil
}
