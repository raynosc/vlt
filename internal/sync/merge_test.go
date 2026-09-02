package sync

import (
	"testing"
	"time"

	"github.com/raynosc/vlt/internal/secret"
)

// testSec creates a secret with a given name and UpdatedAt for testing.
func testSec(name string, updatedAt time.Time) secret.Secret {
	return secret.Secret{
		Name:      name,
		Kind:      secret.KindPassword,
		UpdatedAt: updatedAt,
	}
}

func TestMergeSecrets_LocalNewer(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	older := now.Add(-1 * time.Hour)

	local := []secret.Secret{testSec("key-a", now)}
	remote := []secret.Secret{testSec("key-a", older)}

	merged, conflicts := mergeSecrets(local, remote)

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged secret, got %d", len(merged))
	}
	if merged[0].Name != "key-a" {
		t.Errorf("Name = %q, want key-a", merged[0].Name)
	}
	if !merged[0].UpdatedAt.Equal(now) {
		t.Errorf("expected local (newer) timestamp, got %v", merged[0].UpdatedAt)
	}

	if len(conflicts) != 0 {
		t.Errorf("expected 0 conflicts for local-newer, got %d", len(conflicts))
	}
}

func TestMergeSecrets_RemoteNewer(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	older := now.Add(-1 * time.Hour)

	local := []secret.Secret{testSec("key-a", older)}
	remote := []secret.Secret{testSec("key-a", now)}

	merged, conflicts := mergeSecrets(local, remote)

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged secret, got %d", len(merged))
	}
	if merged[0].Name != "key-a" {
		t.Errorf("Name = %q, want key-a", merged[0].Name)
	}
	if !merged[0].UpdatedAt.Equal(now) {
		t.Errorf("expected remote (newer) timestamp, got %v", merged[0].UpdatedAt)
	}

	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict for remote-newer, got %d", len(conflicts))
	}
	if conflicts[0].Name != "key-a" {
		t.Errorf("conflict Name = %q, want key-a", conflicts[0].Name)
	}
	if conflicts[0].Resolved != "remote_wins" {
		t.Errorf("conflict Resolved = %q, want remote_wins", conflicts[0].Resolved)
	}
}

func TestMergeSecrets_SameTimestamp(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	local := []secret.Secret{testSec("key-a", now)}
	remote := []secret.Secret{testSec("key-a", now)}

	merged, conflicts := mergeSecrets(local, remote)

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged secret, got %d", len(merged))
	}
	// Same timestamp: local wins (LWW with local preference on tie)
	if !merged[0].UpdatedAt.Equal(now) {
		t.Errorf("expected timestamp preserved, got %v", merged[0].UpdatedAt)
	}

	if len(conflicts) != 0 {
		t.Errorf("expected 0 conflicts for same ts, got %d", len(conflicts))
	}
}

func TestMergeSecrets_NewSecretInRemote(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	local := []secret.Secret{testSec("key-a", now)}
	remote := []secret.Secret{testSec("key-b", now)}

	merged, conflicts := mergeSecrets(local, remote)

	if len(merged) != 2 {
		t.Fatalf("expected 2 merged secrets, got %d", len(merged))
	}
	// Both secrets should be present
	names := make(map[string]bool)
	for _, s := range merged {
		names[s.Name] = true
	}
	if !names["key-a"] {
		t.Error("key-a should be in merged")
	}
	if !names["key-b"] {
		t.Error("key-b should be in merged")
	}

	if len(conflicts) != 0 {
		t.Errorf("expected 0 conflicts for new remote secret, got %d", len(conflicts))
	}
}

func TestMergeSecrets_EmptyVault(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	local := []secret.Secret{}
	remote := []secret.Secret{testSec("key-a", now)}

	merged, conflicts := mergeSecrets(local, remote)

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged secret from empty vault, got %d", len(merged))
	}
	if merged[0].Name != "key-a" {
		t.Errorf("Name = %q, want key-a", merged[0].Name)
	}
	if len(conflicts) != 0 {
		t.Errorf("expected 0 conflicts for empty vault, got %d", len(conflicts))
	}
}

func TestMergeSecrets_BothEmpty(t *testing.T) {
	merged, conflicts := mergeSecrets(nil, nil)

	if len(merged) != 0 {
		t.Errorf("expected 0 merged for both empty, got %d", len(merged))
	}
	if len(conflicts) != 0 {
		t.Errorf("expected 0 conflicts for both empty, got %d", len(conflicts))
	}
}

func TestMergeSecrets_MultipleConflicts(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	older := now.Add(-2 * time.Hour)

	local := []secret.Secret{
		testSec("key-a", older), // remote wins
		testSec("key-b", now),   // local wins
		testSec("key-c", now),   // only in local
	}
	remote := []secret.Secret{
		testSec("key-a", now),   // newer
		testSec("key-b", older), // older
		testSec("key-d", now),   // only in remote
	}

	merged, conflicts := mergeSecrets(local, remote)

	if len(merged) != 4 {
		t.Fatalf("expected 4 merged secrets, got %d: %+v", len(merged), merged)
	}

	// key-a should use remote (newer)
	// key-b should use local (newer)
	// key-c is local-only
	// key-d is remote-only

	names := make(map[string]time.Time)
	for _, s := range merged {
		names[s.Name] = s.UpdatedAt
	}

	if names["key-a"] != now {
		t.Error("key-a should use remote (newer) timestamp")
	}
	if names["key-b"] != now {
		t.Error("key-b should use local (newer) timestamp")
	}
	if _, ok := names["key-c"]; !ok {
		t.Error("key-c should be present (local-only)")
	}
	if _, ok := names["key-d"]; !ok {
		t.Error("key-d should be present (remote-only)")
	}

	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].Name != "key-a" {
		t.Errorf("conflict Name = %q, want key-a", conflicts[0].Name)
	}
	if conflicts[0].Resolved != "remote_wins" {
		t.Errorf("conflict Resolved = %q, want remote_wins", conflicts[0].Resolved)
	}
}
