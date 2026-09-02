package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/parse"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
)

const (
	displayTimeFormat = "2006-01-02 15:04:05"
	jsonTimeFormat    = "2006-01-02T15:04:05Z"
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all secrets",
		Long: `List all secrets in the vault.

Displays name, kind, and last updated time for each secret.
No master password required since only metadata is shown.

Use --kind to filter by secret type (certificate, ssh_key, password, etc.).
Use --tag to filter by tag (e.g. --tag production).
Use --tags to list all unique tags with their counts.
Use --expiring <days> to show certificates expiring within N days.
Use --json for machine-readable output.`,
		Args: cobra.NoArgs,
		RunE: runList,
	}

	cmd.Flags().String("kind", "", "filter by secret kind (certificate, ssh_key, password, etc.)")
	cmd.Flags().String("type", "", "filter by secret type (deprecated: use --kind)")
	cmd.Flags().Int("expiring", 0, "show secrets expiring within N days")
	cmd.Flags().String("tag", "", "filter by tag (e.g. --tag production)")
	cmd.Flags().Bool("tags", false, "list all unique tags with counts")
	return cmd
}

func runList(cmd *cobra.Command, _ []string) error {
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	// Unlock vault (list now requires decryption of metadata)
	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	defer crypto.Zeroize(key)

	// Handle --tags flag (show unique tags with counts)
	listTags, _ := cmd.Flags().GetBool("tags")
	if listTags {
		return runListTags(s, key)
	}

	// Parse filters
	kindFilter, _ := cmd.Flags().GetString("kind")
	if kindFilter == "" {
		kindFilter, _ = cmd.Flags().GetString("type") // fallback to deprecated --type
	}
	tagFilter, _ := cmd.Flags().GetString("tag")
	expiringDays, _ := cmd.Flags().GetInt("expiring")

	var all []secret.Secret

	if expiringDays > 0 {
		// Use listExpiring helper when --expiring is set
		all, err = listExpiring(s, key, expiringDays)
		if err != nil {
			return fmt.Errorf("error: list expiring: %w", err)
		}
	} else {
		all, err = s.List()
		if err != nil {
			return fmt.Errorf("error: list: %w", err)
		}
		for i := range all {
			if err := decryptSecretMetadata(&all[i], key); err != nil {
				return fmt.Errorf("error: decrypt metadata: %w", err)
			}
		}
	}

	// Apply client-side filters (kind, tag)
	var filtered []secret.Secret
	for _, sec := range all {
		if kindFilter != "" && string(sec.Kind) != kindFilter {
			continue
		}
		if tagFilter != "" && !containsTag(sec.Tags, tagFilter) {
			continue
		}
		filtered = append(filtered, sec)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		summaries := toSummaries(filtered)
		b, _ := json.Marshal(summaries)
		fmt.Println(string(b))
		return nil
	}

	if len(filtered) == 0 {
		if expiringDays > 0 {
			fmt.Fprintf(os.Stderr, "No certificates expiring within %d days.\n", expiringDays)
		} else {
			fmt.Fprintln(os.Stderr, "No secrets stored.")
		}
		return nil
	}

	// Human-readable output
	fmt.Fprintf(os.Stderr, "%-30s %-14s %-10s %s\n", "NAME", "KIND", "EXPIRY", "UPDATED")
	fmt.Fprintln(os.Stderr, "------------------------------ -------------- ---------- -------------------------")
	for _, sec := range filtered {
		expiryStr := formatExpiry(sec.Metadata)
		fmt.Fprintf(os.Stderr, "%-30s %-14s %-10s %s\n",
			sec.Name, sec.Kind, expiryStr, sec.UpdatedAt.Format(displayTimeFormat))
	}

	return nil
}

// runListTags collects all unique tags across all secrets and prints them with counts.
func runListTags(s store.Store, key []byte) error {
	all, err := s.List()
	if err != nil {
		return fmt.Errorf("error: list: %w", err)
	}

	tagCounts := make(map[string]int)
	for _, sec := range all {
		if err := decryptSecretMetadata(&sec, key); err != nil {
			return fmt.Errorf("error: decrypt metadata: %w", err)
		}
		if sec.Tags == "" {
			continue
		}
		for _, tag := range strings.Split(sec.Tags, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				tagCounts[tag]++
			}
		}
	}

	if len(tagCounts) == 0 {
		fmt.Fprintln(os.Stderr, "No tags found.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "%-20s %s\n", "TAG", "COUNT")
	fmt.Fprintln(os.Stderr, "------------------- -----")
	for tag, count := range tagCounts {
		fmt.Fprintf(os.Stderr, "%-20s %d\n", tag, count)
	}

	return nil
}

// formatExpiry returns a human-readable expiry status from metadata JSON.
func formatExpiry(metadata string) string {
	if metadata == "" {
		return ""
	}

	var meta parse.Metadata
	if err := json.Unmarshal([]byte(metadata), &meta); err != nil {
		return ""
	}

	if meta.NotAfter == "" {
		return ""
	}

	if meta.IsExpired() {
		return "⚠️ EXPIRED"
	}

	days := meta.DaysUntilExpiry()
	if days < 0 {
		return "⚠️ EXPIRED"
	}
	return fmt.Sprintf("⏰ %dd", days)
}

// secretSummary is a lightweight representation for list/search JSON output.
type secretSummary struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Tags      string `json:"tags,omitempty"`
	Notes     string `json:"notes,omitempty"`
	Metadata  string `json:"metadata,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func toSummary(sec secret.Secret) secretSummary {
	return secretSummary{
		Name:      sec.Name,
		Kind:      string(sec.Kind),
		Tags:      sec.Tags,
		Notes:     sec.Notes,
		Metadata:  sec.Metadata,
		CreatedAt: sec.CreatedAt.Format(jsonTimeFormat),
		UpdatedAt: sec.UpdatedAt.Format(jsonTimeFormat),
	}
}

func toSummaries(secs []secret.Secret) []secretSummary {
	if secs == nil {
		return []secretSummary{}
	}
	summaries := make([]secretSummary, len(secs))
	for i, sec := range secs {
		summaries[i] = toSummary(sec)
	}
	return summaries
}

// containsTag checks if a comma-separated tag string contains the given tag.
func containsTag(tags, tag string) bool {
	if tags == "" || tag == "" {
		return false
	}
	n := len(tags)
	m := len(tag)
	for i := 0; i <= n-m; i++ {
		match := true
		for j := 0; j < m; j++ {
			if tags[i+j] != tag[j] {
				match = false
				break
			}
		}
		if match {
			leftOk := i == 0 || tags[i-1] == ','
			rightOk := i+m >= n || tags[i+m] == ','
			if leftOk && rightOk {
				return true
			}
		}
	}
	return false
}
