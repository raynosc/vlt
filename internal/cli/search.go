package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
)

func newSearchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search secrets by name or tags",
		Long: `Search secrets by name or tags.

Searches the plaintext metadata (name, tags) for the given query string.
No master password required since only metadata is searched.

Use --json for machine-readable output.`,
		Args: cobra.ExactArgs(1),
		RunE: runSearch,
	}

	return cmd
}

func runSearch(cmd *cobra.Command, args []string) error {
	query := args[0]
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	// Unlock vault (search now requires decryption of metadata)
	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	defer crypto.Zeroize(key)

	results, err := searchSecrets(s, key, query)
	if err != nil {
		return fmt.Errorf("error: search: %w", err)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		summaries := toSummaries(results)
		b, _ := json.Marshal(summaries)
		fmt.Println(string(b))
		return nil
	}

	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "No secrets matching %q.\n", query)
		return nil
	}

	fmt.Fprintf(os.Stderr, "Found %d secret(s) matching %q:\n", len(results), query)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "%-30s %-12s %s\n", "NAME", "KIND", "UPDATED")
	fmt.Fprintln(os.Stderr, "------------------------------ ------------ -------------------------")
	for _, sec := range results {
		fmt.Fprintf(os.Stderr, "%-30s %-12s %s\n",
			sec.Name, sec.Kind, sec.UpdatedAt.Format("2006-01-02 15:04:05"))
	}

	return nil
}
