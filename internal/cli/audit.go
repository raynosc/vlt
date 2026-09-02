package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show recent vault activity",
		Long: `Display recent audit log entries showing vault activity.

Actions are logged for: vault_init, vault_unlock, secret_add, secret_get,
secret_edit, secret_delete, secret_export, secret_import, vault_check.

Use --limit to control how many entries are shown (default: 50).
Use --json for machine-readable output.`,
		Args: cobra.NoArgs,
		RunE: runAudit,
	}

	cmd.Flags().Int("limit", 50, "number of recent entries to show")
	cmd.AddCommand(newAuditFixOTPLeakCmd())
	return cmd
}

func runAudit(cmd *cobra.Command, _ []string) error {
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	if err := requireVaultExists(vaultPath); err != nil {
		return err
	}

	s, err := openStore(vaultPath)
	if err != nil {
		return vaultMissingHint(err)
	}
	defer func() { _ = s.Close() }()

	limit, _ := cmd.Flags().GetInt("limit")
	if limit <= 0 {
		limit = 50
	}

	entries, err := s.GetAuditLog(limit)
	if err != nil {
		return fmt.Errorf("error: read audit log: %w", err)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return fmt.Errorf("error: encode JSON: %w", err)
		}
		return nil
	}

	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "No audit log entries found.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "%-20s %-20s %-20s %s\n", "TIMESTAMP", "ACTION", "SECRET", "DETAILS")
	fmt.Fprintln(os.Stderr, "-------------------- -------------------- -------------------- ----------------------------------------")
	for _, e := range entries {
		ts := e.Timestamp.Format("2006-01-02 15:04:05")
		fmt.Fprintf(os.Stderr, "%-20s %-20s %-20s %s\n", ts, e.Action, e.SecretName, e.Details)
	}

	return nil
}
