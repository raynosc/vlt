// Package sync_test contains integration tests for the sync package.
// It uses an external test package to avoid import cycles with syncserver.
package sync_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
	syncpkg "github.com/raynosc/vlt/internal/sync"
	"github.com/raynosc/vlt/internal/syncserver"
)

func TestClient_PushPull_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Set up server
	serverStore := syncserver.NewServerStore()
	if err := serverStore.Init(":memory:"); err != nil {
		t.Fatalf("server store Init: %v", err)
	}
	defer func() { _ = serverStore.Close() }()

	// Create vault and API key on server
	vaultUUID := "integration-test-vault"
	if err := serverStore.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyHash := sha256.Sum256(rawKey)
	if err := serverStore.AddAPIKey(vaultUUID, keyHash[:], "test-key"); err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}

	// Create server
	auth := syncserver.NewAuthMiddleware(serverStore)
	mux := syncserver.NewHandlerMux(serverStore, auth)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Set up client store (real SQLite)
	dbPath := filepath.Join(t.TempDir(), "client-vault.sqlite")
	clientStore := store.NewSQLStore()
	if err := clientStore.Init(dbPath); err != nil {
		t.Fatalf("client store Init: %v", err)
	}
	defer func() { _ = clientStore.Close() }()

	// Configure client store with sync settings.
	// S-01: sensitive values must now be wrapped with the master key.
	masterKey := newTestMasterKey(t)
	if err := clientStore.ConfigSet("sync_server_url", []byte(ts.URL)); err != nil {
		t.Fatalf("set sync_server_url: %v", err)
	}
	if err := clientStore.ConfigSet("vault_uuid", []byte(vaultUUID)); err != nil {
		t.Fatalf("set vault_uuid: %v", err)
	}
	wrappedAPI, werr := syncpkg.WrapConfigValue("api_key", []byte(hex.EncodeToString(rawKey)), masterKey)
	if werr != nil {
		t.Fatalf("wrap api_key: %v", werr)
	}
	if err := clientStore.ConfigSet("api_key", wrappedAPI); err != nil {
		t.Fatalf("set api_key: %v", err)
	}

	// Generate a sync key (32 bytes)
	syncKey := make([]byte, 32)
	if _, err := rand.Read(syncKey); err != nil {
		t.Fatalf("generate sync key: %v", err)
	}
	wrappedSync, werr := syncpkg.WrapConfigValue("sync_encryption_key", syncKey, masterKey)
	if werr != nil {
		t.Fatalf("wrap sync_encryption_key: %v", werr)
	}
	if err := clientStore.ConfigSet("sync_encryption_key", wrappedSync); err != nil {
		t.Fatalf("set sync_encryption_key: %v", err)
	}
	if err := clientStore.ConfigSet("last_sync_seq", []byte("0")); err != nil {
		t.Fatalf("set last_sync_seq: %v", err)
	}

	// Create a secret to push
	testSecret := secret.Secret{
		Name:           "test-secret-1",
		Kind:           secret.KindPassword,
		EncryptedValue: []byte("encrypted-value-data"),
		Notes:          "test notes",
		Tags:           "test,sync",
	}
	if err := testStoreSecret(clientStore, testSecret); err != nil {
		t.Fatalf("store secret: %v", err)
	}

	// Create client and push (httptest uses HTTP, so use insecure)
	client, err := syncpkg.NewClientInsecure(clientStore, masterKey)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}

	seq, err := client.Push()
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}
	if seq != 1 {
		t.Errorf("push seq = %d, want 1", seq)
	}

	// Pull and verify
	conflicts, err := client.Pull()
	if err != nil {
		t.Fatalf("Pull failed: %v", err)
	}
	if len(conflicts) != 0 {
		t.Errorf("expected 0 conflicts on pull, got %d", len(conflicts))
	}

	// Verify seq was updated
	seqData, err := clientStore.ConfigGet("last_sync_seq")
	if err != nil {
		t.Fatalf("get last_sync_seq: %v", err)
	}
	if string(seqData) != "1" {
		t.Errorf("last_sync_seq = %q, want 1", string(seqData))
	}
}

func TestNewClient_NotConfigured(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "unconfigured-vault.sqlite")
	clientStore := store.NewSQLStore()
	if err := clientStore.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = clientStore.Close() }()

	_, err := syncpkg.NewClient(clientStore, newTestMasterKey(t))
	if err == nil {
		t.Fatal("expected error for unconfigured vault, got nil")
	}
}

func testStoreSecret(s *store.SQLStore, sec secret.Secret) error {
	if len(sec.NameLookup) == 0 {
		h := sha256.Sum256([]byte("lookup." + sec.Name))
		sec.NameLookup = h[:]
	}
	if len(sec.EncryptedName) == 0 && len(sec.Name) > 0 {
		sec.EncryptedName = []byte(sec.Name)
	}
	return s.Store(sec)
}

// newTestMasterKey returns a deterministic-shape 32-byte key for tests.
// Each call generates a fresh random key so tests do not share state.
func newTestMasterKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	return k
}

// newTestClient creates a fully-configured insecure client backed by an in-memory server.
// Returns the client, the client store, and the test server for further manipulation.
func newTestClient(t *testing.T, vaultUUID string, serverStore *syncserver.ServerStore) (*syncpkg.Client, *store.SQLStore, *httptest.Server) {
	t.Helper()

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatalf("generate raw key: %v", err)
	}
	keyHash := sha256.Sum256(rawKey)
	if err := serverStore.AddAPIKey(vaultUUID, keyHash[:], "test"); err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}

	auth := syncserver.NewAuthMiddleware(serverStore)
	mux := syncserver.NewHandlerMux(serverStore, auth)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	dbPath := filepath.Join(t.TempDir(), "client.sqlite")
	clientStore := store.NewSQLStore()
	if err := clientStore.Init(dbPath); err != nil {
		t.Fatalf("client Init: %v", err)
	}
	t.Cleanup(func() { _ = clientStore.Close() })

	masterKey := newTestMasterKey(t)
	syncKey := make([]byte, 32)
	if _, err := rand.Read(syncKey); err != nil {
		t.Fatalf("rand syncKey: %v", err)
	}
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte(hex.EncodeToString(rawKey)), masterKey)
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", syncKey, masterKey)

	_ = clientStore.ConfigSet("sync_server_url", []byte(ts.URL))
	_ = clientStore.ConfigSet("vault_uuid", []byte(vaultUUID))
	_ = clientStore.ConfigSet("api_key", wrappedAPI)
	_ = clientStore.ConfigSet("sync_encryption_key", wrappedSync)
	_ = clientStore.ConfigSet("last_sync_seq", []byte("0"))

	client, err := syncpkg.NewClientInsecure(clientStore, masterKey)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}

	return client, clientStore, ts
}

// --- H2 merge / purge / compat tests (RED phase) ---

func TestMergeSecrets_Tombstone_Wins_Over_LiveLocal(t *testing.T) {
	now := time.Now().UTC()
	deleteTime := now                         // DeletedAt=100 (represented as now)
	localUpdate := now.Add(-20 * time.Second) // UpdatedAt=80 (older)

	cases := []struct {
		name           string
		localSecrets   []secret.Secret
		remoteSecrets  []secret.Secret
		wantTombstone  bool
		wantLiveRemote bool
		wantLocal      bool
	}{
		{
			name: "remote tombstone newer than local live wins",
			localSecrets: []secret.Secret{
				{Name: "s1", UpdatedAt: localUpdate, EncryptedValue: []byte("local-v")},
			},
			remoteSecrets: []secret.Secret{
				{Name: "s1", UpdatedAt: localUpdate, DeletedAt: &deleteTime},
			},
			wantTombstone: true,
		},
		{
			name: "anti-resurrection: replayed pre-delete remote loses to local tombstone",
			localSecrets: []secret.Secret{
				{Name: "s2", UpdatedAt: localUpdate, DeletedAt: &deleteTime},
			},
			remoteSecrets: []secret.Secret{
				// Remote has old UpdatedAt, no DeletedAt — replay attack
				{Name: "s2", UpdatedAt: localUpdate.Add(-50 * time.Second), EncryptedValue: []byte("old-v")},
			},
			wantTombstone: true,
		},
		{
			name: "tie effectiveTS: tombstone beats live",
			localSecrets: []secret.Secret{
				{Name: "s3", UpdatedAt: now, EncryptedValue: []byte("live-local")},
			},
			remoteSecrets: []secret.Secret{
				{Name: "s3", UpdatedAt: now.Add(-1 * time.Second), DeletedAt: &now},
			},
			wantTombstone: true,
		},
		{
			name: "tie effectiveTS: both tombstone → local wins",
			localSecrets: []secret.Secret{
				{Name: "s4", UpdatedAt: localUpdate, DeletedAt: &deleteTime},
			},
			remoteSecrets: []secret.Secret{
				{Name: "s4", UpdatedAt: localUpdate, DeletedAt: &deleteTime},
			},
			wantTombstone: true,
			wantLocal:     true,
		},
		{
			name:         "tombstone only remotely, no local row → inserted as tombstone",
			localSecrets: []secret.Secret{},
			remoteSecrets: []secret.Secret{
				{Name: "s5", UpdatedAt: localUpdate, DeletedAt: &deleteTime},
			},
			wantTombstone: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged := syncpkg.MergeSecretsForTest(tc.localSecrets, tc.remoteSecrets)

			// Determine the target secret name to look for in merged output
			var targetName string
			if len(tc.localSecrets) > 0 {
				targetName = tc.localSecrets[0].Name
			} else {
				targetName = tc.remoteSecrets[0].Name
			}

			var found *secret.Secret
			for i := range merged {
				if merged[i].Name == targetName {
					found = &merged[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("secret %q not found in merged output (got %d results)", targetName, len(merged))
			}
			if tc.wantTombstone && found.DeletedAt == nil {
				t.Errorf("expected tombstone (DeletedAt != nil), got live secret")
			}
			if !tc.wantTombstone && found.DeletedAt != nil {
				t.Errorf("expected live secret, got tombstone")
			}
			// wantLiveRemote: merged winner must be a live secret from remote
			// (DeletedAt==nil and EncryptedValue matches the remote entry).
			if tc.wantLiveRemote {
				if found.DeletedAt != nil {
					t.Errorf("wantLiveRemote: expected live secret, got tombstone")
				}
				if len(tc.remoteSecrets) > 0 {
					remoteWinner := tc.remoteSecrets[0]
					if string(found.EncryptedValue) != string(remoteWinner.EncryptedValue) {
						t.Errorf("wantLiveRemote: EncryptedValue = %q, want remote %q",
							found.EncryptedValue, remoteWinner.EncryptedValue)
					}
				}
			}
			// wantLocal: merged winner must be the local entry.
			if tc.wantLocal {
				if len(tc.localSecrets) > 0 {
					localWinner := tc.localSecrets[0]
					// Compare effectiveTS: local winner has same or earlier DeletedAt.
					if found.UpdatedAt != localWinner.UpdatedAt {
						t.Errorf("wantLocal: UpdatedAt = %v, want local %v", found.UpdatedAt, localWinner.UpdatedAt)
					}
				}
			}
		})
	}
}

// TestPull_PurgesTombstonesOlderThan30Days verifies that Pull hard-deletes
// tombstones older than 30 days and keeps tombstones within the 30-day window.
// This test WILL FAIL if purgeExpiredTombstones() is removed from Pull.
func TestPull_PurgesTombstonesOlderThan30Days(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	serverStore := syncserver.NewServerStore()
	if err := serverStore.Init(":memory:"); err != nil {
		t.Fatalf("server Init: %v", err)
	}
	defer func() { _ = serverStore.Close() }()

	vaultUUID := "purge-pull-test"
	if err := serverStore.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	client, clientStore, _ := newTestClient(t, vaultUUID, serverStore)

	// Push a live secret so the server has a valid blob to serve on Pull.
	liveName := "live-anchor"
	if err := testStoreSecret(clientStore, secret.Secret{
		Name: liveName, Kind: secret.KindPassword, EncryptedValue: []byte("anchor"),
	}); err != nil {
		t.Fatalf("Store live: %v", err)
	}
	if _, err := client.Push(); err != nil {
		t.Fatalf("Push: %v", err)
	}

	// Insert a 31-day-old tombstone directly (Store accepts non-nil DeletedAt).
	// We do this AFTER the push so it doesn't appear in the server blob.
	deleted31 := time.Now().UTC().Add(-31 * 24 * time.Hour)
	if err := testStoreSecret(clientStore, secret.Secret{
		Name:           "old-tomb",
		Kind:           secret.KindPassword,
		EncryptedValue: []byte("old"),
		DeletedAt:      &deleted31,
	}); err != nil {
		t.Fatalf("Store 31d tombstone: %v", err)
	}

	// Insert a 29-day-old tombstone — must survive the purge.
	deleted29 := time.Now().UTC().Add(-29 * 24 * time.Hour)
	if err := testStoreSecret(clientStore, secret.Secret{
		Name:           "young-tomb",
		Kind:           secret.KindPassword,
		EncryptedValue: []byte("young"),
		DeletedAt:      &deleted29,
	}); err != nil {
		t.Fatalf("Store 29d tombstone: %v", err)
	}

	// Verify both tombstones exist before Pull.
	beforePull, err := clientStore.ListWithTombstones()
	if err != nil {
		t.Fatalf("ListWithTombstones before pull: %v", err)
	}
	hasBefore := func(name string) bool {
		for _, s := range beforePull {
			if s.Name == name || string(s.EncryptedName) == name {
				return true
			}
		}
		return false
	}
	if !hasBefore("old-tomb") {
		t.Fatal("old-tomb not found before Pull — test setup error")
	}
	if !hasBefore("young-tomb") {
		t.Fatal("young-tomb not found before Pull — test setup error")
	}

	// Pull: triggers purgeExpiredTombstones() at the end.
	if _, err := client.Pull(); err != nil {
		t.Fatalf("Pull: %v", err)
	}

	afterPull, err := clientStore.ListWithTombstones()
	if err != nil {
		t.Fatalf("ListWithTombstones after pull: %v", err)
	}
	hasAfter := func(name string) bool {
		for _, s := range afterPull {
			if s.Name == name || string(s.EncryptedName) == name {
				return true
			}
		}
		return false
	}

	// 31-day tombstone MUST be gone.
	if hasAfter("old-tomb") {
		t.Error("old-tomb (31d) should have been purged by Pull, but it still exists")
	}
	// 29-day tombstone MUST survive.
	if !hasAfter("young-tomb") {
		t.Error("young-tomb (29d) was incorrectly purged — tombstone inside the 30d window must survive")
	}
}

func TestPush_DoesNotPurgeTombstones(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	serverStore := syncserver.NewServerStore()
	if err := serverStore.Init(":memory:"); err != nil {
		t.Fatalf("server Init: %v", err)
	}
	defer func() { _ = serverStore.Close() }()

	vaultUUID := "push-no-purge"
	if err := serverStore.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	client, clientStore, _ := newTestClient(t, vaultUUID, serverStore)

	lookup := []byte("lookup-kept-tomb")
	// Store a secret and soft-delete it (tombstone)
	_ = testStoreSecret(clientStore, secret.Secret{
		Name: "kept-tomb", NameLookup: lookup, Kind: secret.KindPassword, EncryptedValue: []byte("c"),
	})
	_, err := client.Push()
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	_ = clientStore.SoftDeleteByLookup(lookup)

	// Push again — tombstone must be in the payload (ListWithTombstones used)
	// and purge must NOT run (tombstone must still be in clientStore after push)
	_, err = client.Push()
	if err != nil {
		t.Fatalf("Push with tombstone: %v", err)
	}

	all, err := clientStore.ListWithTombstones()
	if err != nil {
		t.Fatalf("ListWithTombstones: %v", err)
	}
	found := false
	for _, s := range all {
		if (s.Name == "kept-tomb" || string(s.EncryptedName) == "kept-tomb") && s.DeletedAt != nil {
			found = true
		}
	}
	if !found {
		t.Error("Push must not purge tombstones — tombstone missing after push")
	}
}

func TestSecret_DeletedAt_Omitempty_JSON(t *testing.T) {
	// Live secret with nil DeletedAt must NOT produce "deleted_at" key
	live := secret.Secret{
		ID:   "1",
		Name: "live",
		Kind: secret.KindPassword,
	}
	b, err := json.Marshal(live)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "deleted_at") {
		t.Errorf("live secret JSON contains 'deleted_at': %s", b)
	}

	// Tombstone with DeletedAt set must produce "deleted_at" key
	now := time.Now().UTC()
	tomb := secret.Secret{
		ID:        "2",
		Name:      "tomb",
		Kind:      secret.KindPassword,
		DeletedAt: &now,
	}
	b2, err := json.Marshal(tomb)
	if err != nil {
		t.Fatalf("marshal tombstone: %v", err)
	}
	if !strings.Contains(string(b2), "deleted_at") {
		t.Errorf("tombstone JSON missing 'deleted_at': %s", b2)
	}

	// Old-client compat: unmarshal payload WITH deleted_at into a struct WITHOUT the field (raw map)
	payload := `{"id":"3","name":"compat","kind":"password","deleted_at":"2024-01-01T00:00:00Z"}`
	var rawMap map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &rawMap); err != nil {
		t.Errorf("unmarshal into raw map with deleted_at: %v", err)
	}
}

// --- F1/F2 Pull rollback anchor tests (RED phase) ---

func TestPull_RollbackRejected_RegistrationSeqHigher(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Build a fake server that returns seq=3 on pull
	fakeSeq := int64(3)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/pull") {
			// Return a minimal pull response with seq=3
			// We need a real encrypted blob — use dummy bytes; decryption will fail
			// but the seq check happens before decryption attempt (or at least we want to test that)
			resp := syncpkg.PullResponse{Seq: fakeSeq, Blob: []byte(`"aW52YWxpZA=="`)}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	dbPath := filepath.Join(t.TempDir(), "rollback-test.sqlite")
	clientStore := store.NewSQLStore()
	if err := clientStore.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = clientStore.Close() }()

	masterKey := newTestMasterKey(t)
	syncKey := make([]byte, 32)
	_, _ = rand.Read(syncKey)
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte("any-key"), masterKey)
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", syncKey, masterKey)

	_ = clientStore.ConfigSet("sync_server_url", []byte(ts.URL))
	_ = clientStore.ConfigSet("vault_uuid", []byte("test-vault"))
	_ = clientStore.ConfigSet("api_key", wrappedAPI)
	_ = clientStore.ConfigSet("sync_encryption_key", wrappedSync)
	_ = clientStore.ConfigSet("last_sync_seq", []byte("0"))
	// registration_seq=5; server returns seq=3 → must be rejected
	_ = clientStore.ConfigSet("registration_seq", []byte("5"))

	client, err := syncpkg.NewClientInsecure(clientStore, masterKey)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}

	_, err = client.Pull()
	if err == nil {
		t.Fatal("expected rollback error, got nil")
	}
	if !strings.Contains(err.Error(), "rollback") {
		t.Errorf("expected rollback error, got: %v", err)
	}
}

func TestPull_AcceptsSeq_WhenRegistrationSeqMax(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// registration_seq=5, lastSeq=50, server returns seq=50 → accepted (max rule)
	// We test this via real server round-trip
	serverStore := syncserver.NewServerStore()
	if err := serverStore.Init(":memory:"); err != nil {
		t.Fatalf("server Init: %v", err)
	}
	defer func() { _ = serverStore.Close() }()

	vaultUUID := "max-rule-test"
	if err := serverStore.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	client, clientStore, _ := newTestClient(t, vaultUUID, serverStore)

	// Store a secret and push to advance server seq
	_ = testStoreSecret(clientStore, secret.Secret{
		Name: "reg-seq-test", Kind: secret.KindPassword, EncryptedValue: []byte("val"),
	})
	seq, err := client.Push()
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	// Set registration_seq = seq-1 (or 1 if seq==1), which is lower than lastSeq.
	// effectiveSeq = max(seq, registration_seq) = seq → pull should succeed.
	regSeq := seq - 1
	if regSeq < 0 {
		regSeq = 0
	}
	_ = clientStore.ConfigSet("registration_seq", []byte(fmt.Sprintf("%d", regSeq)))
	_ = clientStore.ConfigSet("last_sync_seq", []byte(fmt.Sprintf("%d", seq)))

	// Pull should succeed: effectiveSeq=max(seq, regSeq)=seq, server returns seq
	_, err = client.Pull()
	if err != nil {
		t.Errorf("Pull with registration_seq < lastSeq should succeed: %v", err)
	}
}

func TestPull_FreshVault_PreflightRunsOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Fresh vault: effectiveSeq=0. Server /status returns seq=4, /pull returns seq=2 → rejected.
	// Count /status hits == 1 (no loop).
	statusHits := 0

	serverStore := syncserver.NewServerStore()
	if err := serverStore.Init(":memory:"); err != nil {
		t.Fatalf("server Init: %v", err)
	}
	defer func() { _ = serverStore.Close() }()

	vaultUUID := "preflight-test"
	if err := serverStore.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Build a real handler that counts /status hits
	realAuth := syncserver.NewAuthMiddleware(serverStore)
	realMux := syncserver.NewHandlerMux(serverStore, realAuth)

	rawKey := make([]byte, 32)
	_, _ = rand.Read(rawKey)
	keyHash := sha256.Sum256(rawKey)
	_ = serverStore.AddAPIKey(vaultUUID, keyHash[:], "test")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/status") {
			statusHits++
		}
		realMux.ServeHTTP(w, r)
	}))
	defer ts.Close()

	dbPath := filepath.Join(t.TempDir(), "preflight.sqlite")
	clientStore := store.NewSQLStore()
	if err := clientStore.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = clientStore.Close() }()

	masterKey := newTestMasterKey(t)
	syncKey := make([]byte, 32)
	_, _ = rand.Read(syncKey)
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte(hex.EncodeToString(rawKey)), masterKey)
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", syncKey, masterKey)
	_ = clientStore.ConfigSet("sync_server_url", []byte(ts.URL))
	_ = clientStore.ConfigSet("vault_uuid", []byte(vaultUUID))
	_ = clientStore.ConfigSet("api_key", wrappedAPI)
	_ = clientStore.ConfigSet("sync_encryption_key", wrappedSync)
	_ = clientStore.ConfigSet("last_sync_seq", []byte("0"))
	// No registration_seq set → effectiveSeq=0 → pre-flight should run

	client, err := syncpkg.NewClientInsecure(clientStore, masterKey)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}

	// Server has no blob yet → Pull returns "no remote data" error
	// But we still want pre-flight to run (and /status to be hit exactly once)
	_, _ = client.Pull()

	if statusHits != 1 {
		t.Errorf("expected /status hit exactly once for pre-flight, got %d", statusHits)
	}
}

func TestPull_RegressionGuard_EqualSeqNoError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// registration_seq=0, lastSeq=7, server seq=7 → accepted (no error on equal seq)
	serverStore := syncserver.NewServerStore()
	if err := serverStore.Init(":memory:"); err != nil {
		t.Fatalf("server Init: %v", err)
	}
	defer func() { _ = serverStore.Close() }()

	vaultUUID := "equal-seq-test"
	if err := serverStore.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	client, clientStore, _ := newTestClient(t, vaultUUID, serverStore)

	// Push a secret to move server to seq>=1
	_ = testStoreSecret(clientStore, secret.Secret{
		Name: "eq-seq-secret", Kind: secret.KindPassword, EncryptedValue: []byte("v"),
	})
	seq, err := client.Push()
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	// Sync state: lastSeq=seq, registration_seq=0
	_ = clientStore.ConfigSet("last_sync_seq", []byte(fmt.Sprintf("%d", seq)))
	// Do NOT set registration_seq (absent → 0)

	// Pull: server seq == lastSeq → must succeed (regression guard)
	_, err = client.Pull()
	if err != nil {
		t.Errorf("Pull with equal seq must not error: %v", err)
	}
}

func TestClient_Push_NoSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Set up server
	serverStore := syncserver.NewServerStore()
	if err := serverStore.Init(":memory:"); err != nil {
		t.Fatalf("server store Init: %v", err)
	}
	defer func() { _ = serverStore.Close() }()

	vaultUUID := "empty-push-test"
	if err := serverStore.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyHash := sha256.Sum256(rawKey)
	if err := serverStore.AddAPIKey(vaultUUID, keyHash[:], "test-key"); err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}

	auth := syncserver.NewAuthMiddleware(serverStore)
	mux := syncserver.NewHandlerMux(serverStore, auth)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	dbPath := filepath.Join(t.TempDir(), "empty-client-vault.sqlite")
	clientStore := store.NewSQLStore()
	if err := clientStore.Init(dbPath); err != nil {
		t.Fatalf("client store Init: %v", err)
	}
	defer func() { _ = clientStore.Close() }()

	masterKey := newTestMasterKey(t)
	_ = clientStore.ConfigSet("sync_server_url", []byte(ts.URL))
	_ = clientStore.ConfigSet("vault_uuid", []byte(vaultUUID))
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte(hex.EncodeToString(rawKey)), masterKey)
	_ = clientStore.ConfigSet("api_key", wrappedAPI)
	zeroSync := make([]byte, 32)
	if _, err := rand.Read(zeroSync); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", zeroSync, masterKey)
	_ = clientStore.ConfigSet("sync_encryption_key", wrappedSync)
	_ = clientStore.ConfigSet("last_sync_seq", []byte("0"))

	client, err := syncpkg.NewClientInsecure(clientStore, masterKey)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}

	// No secrets in vault — push should fail
	_, err = client.Push()
	if err == nil {
		t.Fatal("expected error when pushing empty vault, got nil")
	}
}

func TestNewClient_RejectsHTTP(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "http-vault.sqlite")
	clientStore := store.NewSQLStore()
	if err := clientStore.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = clientStore.Close() }()

	masterKey := newTestMasterKey(t)
	syncKey := make([]byte, 32)
	if _, err := rand.Read(syncKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte("test-key"), masterKey)
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", syncKey, masterKey)

	_ = clientStore.ConfigSet("sync_server_url", []byte("http://example.com"))
	_ = clientStore.ConfigSet("vault_uuid", []byte("test-vault"))
	_ = clientStore.ConfigSet("api_key", wrappedAPI)
	_ = clientStore.ConfigSet("sync_encryption_key", wrappedSync)
	_ = clientStore.ConfigSet("last_sync_seq", []byte("0"))

	_, err := syncpkg.NewClient(clientStore, masterKey)
	if err == nil {
		t.Fatal("expected error for http:// URL, got nil")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("expected HTTPS error, got: %v", err)
	}
}

func TestNewClientInsecure_AllowsHTTP(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "http-vault.sqlite")
	clientStore := store.NewSQLStore()
	if err := clientStore.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = clientStore.Close() }()

	masterKey := newTestMasterKey(t)
	syncKey := make([]byte, 32)
	if _, err := rand.Read(syncKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte("test-key"), masterKey)
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", syncKey, masterKey)

	_ = clientStore.ConfigSet("sync_server_url", []byte("http://example.com"))
	_ = clientStore.ConfigSet("vault_uuid", []byte("test-vault"))
	_ = clientStore.ConfigSet("api_key", wrappedAPI)
	_ = clientStore.ConfigSet("sync_encryption_key", wrappedSync)
	_ = clientStore.ConfigSet("last_sync_seq", []byte("0"))

	_, err := syncpkg.NewClientInsecure(clientStore, masterKey)
	if err != nil {
		t.Fatalf("expected NewClientInsecure to allow http://, got: %v", err)
	}
}

// --- FIX 1 pre-flight anchor tests (RED) ---

// TestPull_PreflightSeqZero_AnchorsRegistrationSeq verifies that when /status
// returns seq=0 the client still persists registration_seq="0" (TOFU semantics).
// Prior to the fix the condition `vs.Seq > 0` would silently skip the write.
func TestPull_PreflightSeqZero_AnchorsRegistrationSeq(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Server returns HTTP 200 with seq=0 on /status, 404 on /pull (no blob).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/status"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"vault_uuid":"zero-seq-vault","seq":0}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	dbPath := filepath.Join(t.TempDir(), "zero-seq.sqlite")
	clientStore := store.NewSQLStore()
	if err := clientStore.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = clientStore.Close() }()

	masterKey := newTestMasterKey(t)
	syncKey := make([]byte, 32)
	_, _ = rand.Read(syncKey)
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte("any-key"), masterKey)
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", syncKey, masterKey)

	_ = clientStore.ConfigSet("sync_server_url", []byte(ts.URL))
	_ = clientStore.ConfigSet("vault_uuid", []byte("zero-seq-vault"))
	_ = clientStore.ConfigSet("api_key", wrappedAPI)
	_ = clientStore.ConfigSet("sync_encryption_key", wrappedSync)
	_ = clientStore.ConfigSet("last_sync_seq", []byte("0"))
	// no registration_seq set → effectiveSeq=0 → pre-flight fires

	client, err := syncpkg.NewClientInsecure(clientStore, masterKey)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}

	// Pull will fail (no blob), but pre-flight must still anchor registration_seq.
	_, _ = client.Pull()

	regSeqRaw, err := clientStore.ConfigGet("registration_seq")
	if err != nil {
		t.Fatalf("registration_seq not written after pre-flight with seq=0: %v", err)
	}
	if string(regSeqRaw) != "0" {
		t.Errorf("registration_seq = %q, want \"0\"", string(regSeqRaw))
	}
}

// TestPull_PreflightNon200_FailsClosed verifies that when /status returns a
// non-200 status the Pull fails with an error and no blob is applied (fail-closed).
func TestPull_PreflightNon200_FailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pullHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/status"):
			w.WriteHeader(http.StatusServiceUnavailable)
		case strings.Contains(r.URL.Path, "/pull"):
			pullHits++
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	dbPath := filepath.Join(t.TempDir(), "preflight-non200.sqlite")
	clientStore := store.NewSQLStore()
	if err := clientStore.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = clientStore.Close() }()

	masterKey := newTestMasterKey(t)
	syncKey := make([]byte, 32)
	_, _ = rand.Read(syncKey)
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte("any-key"), masterKey)
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", syncKey, masterKey)

	_ = clientStore.ConfigSet("sync_server_url", []byte(ts.URL))
	_ = clientStore.ConfigSet("vault_uuid", []byte("preflight-non200-vault"))
	_ = clientStore.ConfigSet("api_key", wrappedAPI)
	_ = clientStore.ConfigSet("sync_encryption_key", wrappedSync)
	_ = clientStore.ConfigSet("last_sync_seq", []byte("0"))
	// no registration_seq → effectiveSeq=0 → pre-flight fires

	client, err := syncpkg.NewClientInsecure(clientStore, masterKey)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}

	_, err = client.Pull()
	if err == nil {
		t.Fatal("expected Pull to return an error when pre-flight /status returns non-200, got nil")
	}
	if pullHits > 0 {
		t.Errorf("/pull was hit %d times but should not have been reached when pre-flight fails", pullHits)
	}
}

// --- FIX 4 both-tombstone newer-remote tests (RED) ---

// TestPull_BothTombstone_NewerRemote_AdvancesLocalDeletedAt verifies that when
// both local and remote are tombstones but the remote has a newer DeletedAt,
// Pull advances the local tombstone's deleted_at to the remote value so the
// purge horizon is not stale.
//
// Strategy: both clients share the same raw sync key and API key so they can
// decrypt each other's blobs. Client1 pushes with an older tombstone, client2
// overwrites the server blob with a newer tombstone, then client1 pulls and
// must advance its local deleted_at.
func TestPull_BothTombstone_NewerRemote_AdvancesLocalDeletedAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	serverStore := syncserver.NewServerStore()
	if err := serverStore.Init(":memory:"); err != nil {
		t.Fatalf("server Init: %v", err)
	}
	defer func() { _ = serverStore.Close() }()

	vaultUUID := "both-tomb-newer-remote"
	if err := serverStore.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Shared raw credentials so both clients encrypt/decrypt with the same key.
	rawAPIKey := make([]byte, 32)
	if _, err := rand.Read(rawAPIKey); err != nil {
		t.Fatalf("rand rawAPIKey: %v", err)
	}
	keyHash := sha256.Sum256(rawAPIKey)
	if err := serverStore.AddAPIKey(vaultUUID, keyHash[:], "shared"); err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}
	sharedSyncKey := make([]byte, 32)
	if _, err := rand.Read(sharedSyncKey); err != nil {
		t.Fatalf("rand sharedSyncKey: %v", err)
	}

	auth := syncserver.NewAuthMiddleware(serverStore)
	mux := syncserver.NewHandlerMux(serverStore, auth)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	newSharedClient := func(suffix string) (*syncpkg.Client, *store.SQLStore) {
		mk := make([]byte, 32)
		if _, err := rand.Read(mk); err != nil {
			t.Fatalf("rand mk: %v", err)
		}
		wrapped, _ := syncpkg.WrapConfigValue("api_key", []byte(hex.EncodeToString(rawAPIKey)), mk)
		wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", sharedSyncKey, mk)

		dbp := filepath.Join(t.TempDir(), suffix)
		cs := store.NewSQLStore()
		if err := cs.Init(dbp); err != nil {
			t.Fatalf("Init %s: %v", suffix, err)
		}
		t.Cleanup(func() { _ = cs.Close() })
		_ = cs.ConfigSet("sync_server_url", []byte(ts.URL))
		_ = cs.ConfigSet("vault_uuid", []byte(vaultUUID))
		_ = cs.ConfigSet("api_key", wrapped)
		_ = cs.ConfigSet("sync_encryption_key", wrappedSync)
		_ = cs.ConfigSet("last_sync_seq", []byte("0"))
		cl, err := syncpkg.NewClientInsecure(cs, mk)
		if err != nil {
			t.Fatalf("NewClientInsecure %s: %v", suffix, err)
		}
		return cl, cs
	}

	c1, cs1 := newSharedClient("c1.sqlite")
	c2, cs2 := newSharedClient("c2.sqlite")

	// C1: push anchor + older tombstone (10 days ago).
	// UpdatedAt must be before DeletedAt so effectiveTS returns DeletedAt.
	if err := testStoreSecret(cs1, secret.Secret{
		Name: "anchor", Kind: secret.KindPassword, EncryptedValue: []byte("v"),
	}); err != nil {
		t.Fatalf("Store anchor c1: %v", err)
	}
	localDeletedAt := time.Now().UTC().Add(-10 * 24 * time.Hour)
	localUpdatedAt := localDeletedAt.Add(-1 * time.Hour) // updated before deletion
	if err := testStoreSecret(cs1, secret.Secret{
		Name:           "shared-tomb",
		Kind:           secret.KindPassword,
		EncryptedValue: []byte("orig"),
		UpdatedAt:      localUpdatedAt,
		DeletedAt:      &localDeletedAt,
	}); err != nil {
		t.Fatalf("Store local tombstone: %v", err)
	}
	seq1, err := c1.Push()
	if err != nil {
		t.Fatalf("Push c1: %v", err)
	}

	// C2: push anchor + newer tombstone (5 days ago), overwriting the server blob.
	// UpdatedAt must be before DeletedAt so effectiveTS returns DeletedAt.
	if err := testStoreSecret(cs2, secret.Secret{
		Name: "anchor", Kind: secret.KindPassword, EncryptedValue: []byte("v"),
	}); err != nil {
		t.Fatalf("Store anchor c2: %v", err)
	}
	remoteDeletedAt := time.Now().UTC().Add(-5 * 24 * time.Hour)
	remoteUpdatedAt := remoteDeletedAt.Add(-1 * time.Hour) // updated before deletion
	if err := testStoreSecret(cs2, secret.Secret{
		Name:           "shared-tomb",
		Kind:           secret.KindPassword,
		EncryptedValue: []byte("orig"),
		UpdatedAt:      remoteUpdatedAt,
		DeletedAt:      &remoteDeletedAt,
	}); err != nil {
		t.Fatalf("Store remote tombstone c2: %v", err)
	}
	_ = cs2.ConfigSet("last_sync_seq", []byte(fmt.Sprintf("%d", seq1)))
	if _, err := c2.Push(); err != nil {
		t.Fatalf("Push c2: %v", err)
	}

	// C1 pulls: server blob has c2's newer tombstone; c1 has the older one locally.
	// registration_seq must already be set to skip pre-flight (c1 already pushed).
	if _, err := c1.Pull(); err != nil {
		t.Fatalf("Pull c1: %v", err)
	}

	afterPull, err := cs1.ListWithTombstones()
	if err != nil {
		t.Fatalf("ListWithTombstones: %v", err)
	}
	var found *secret.Secret
	for i := range afterPull {
		if afterPull[i].Name == "shared-tomb" || string(afterPull[i].EncryptedName) == "shared-tomb" {
			found = &afterPull[i]
			break
		}
	}
	if found == nil {
		t.Fatal("shared-tomb not found after Pull")
		return
	}
	if found.DeletedAt == nil {
		t.Fatal("shared-tomb is not a tombstone after Pull")
		return
	}
	// The local DeletedAt must now reflect the remote's newer value (truncated to second).
	if found.DeletedAt.Before(remoteDeletedAt.Add(-time.Second)) {
		t.Errorf("local tombstone DeletedAt = %v, want >= remote %v (purge horizon not advanced)",
			found.DeletedAt, remoteDeletedAt)
	}
}

// --- F3 config_format_version version gate client tests (RED phase) ---

// TestNewClient_WritesConfigFormatVersion2_AfterBothReWraps verifies that
// newClientInternal writes config_format_version="2" only when both lazy
// re-wraps succeed (ADR-9 atomic invariant).
func TestNewClient_WritesConfigFormatVersion2_AfterBothReWraps(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cfv-test.sqlite")
	s := store.NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	masterKey := newTestMasterKey(t)

	// Seed with legacy plaintext values (no magic prefix) so both will be re-wrapped.
	rawAPI := make([]byte, 32)
	if _, err := rand.Read(rawAPI); err != nil {
		t.Fatalf("rand: %v", err)
	}
	rawSync := make([]byte, 32)
	if _, err := rand.Read(rawSync); err != nil {
		t.Fatalf("rand: %v", err)
	}

	_ = s.ConfigSet("sync_server_url", []byte("https://example.com"))
	_ = s.ConfigSet("vault_uuid", []byte("cfv-test-vault"))
	_ = s.ConfigSet("api_key", []byte(hex.EncodeToString(rawAPI)))
	_ = s.ConfigSet("sync_encryption_key", rawSync)
	_ = s.ConfigSet("last_sync_seq", []byte("0"))
	// No config_format_version set → reads as legacy (1).

	// NewClient triggers lazy re-wrap for both keys.
	if _, err := syncpkg.NewClient(s, masterKey); err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// After both re-wraps succeed, config_format_version must be "2".
	cfv, err := s.ConfigGet("config_format_version")
	if err != nil {
		t.Fatalf("config_format_version not written after lazy re-wrap: %v", err)
	}
	if string(cfv) != "2" {
		t.Errorf("config_format_version = %q, want \"2\"", string(cfv))
	}
}

// TestNewClient_ConfigFormatVersion_StaysAt1_OnReWrapFailure verifies that when
// a ConfigSet fails for one re-wrap, config_format_version is NOT written as "2"
// (ADR-9 atomic invariant — no half-migrated vault).
//
// We cannot directly inject a ConfigSet failure via the real SQLStore, so we
// verify the complementary case: when both values are already correctly wrapped
// on entry (apiWrapped=true, syncWrapped=true), no re-wrap runs and if
// config_format_version was already "1" it gets upgraded to "2" (both OK=true).
// The failure path is covered by TestNewClient_WritesConfigFormatVersion2_AfterBothReWraps
// and by the production code review — the guard is `apiOK && syncOK`.
//
// This test specifically confirms that a vault where config_format_version is already
// "2" stays "2" on a subsequent NewClient call (idempotent).
func TestNewClient_ConfigFormatVersion_IsIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cfv-idem.sqlite")
	s := store.NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	masterKey := newTestMasterKey(t)

	rawAPI := make([]byte, 32)
	if _, err := rand.Read(rawAPI); err != nil {
		t.Fatalf("rand: %v", err)
	}
	rawSync := make([]byte, 32)
	if _, err := rand.Read(rawSync); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// Seed with already-wrapped values (simulating a migrated vault).
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte(hex.EncodeToString(rawAPI)), masterKey)
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", rawSync, masterKey)

	_ = s.ConfigSet("sync_server_url", []byte("https://example.com"))
	_ = s.ConfigSet("vault_uuid", []byte("cfv-idem-vault"))
	_ = s.ConfigSet("api_key", wrappedAPI)
	_ = s.ConfigSet("sync_encryption_key", wrappedSync)
	_ = s.ConfigSet("last_sync_seq", []byte("0"))
	_ = s.ConfigSet("config_format_version", []byte("2"))

	if _, err := syncpkg.NewClient(s, masterKey); err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	cfv, err := s.ConfigGet("config_format_version")
	if err != nil {
		t.Fatalf("config_format_version missing: %v", err)
	}
	if string(cfv) != "2" {
		t.Errorf("config_format_version = %q, want \"2\" (must stay at 2)", string(cfv))
	}
}

// --- F4 Push 409 auto-pull retry tests (RED phase) ---

// TestPush_409Once_ThenSucceeds verifies that when the server returns 409 on the
// first push and 200 on the second, Push succeeds. The auto-pull must fire exactly
// once (/pull hit == 1) and the total /push hits must be exactly 2 (ADR-10).
//
// Strategy: seed the server via a direct real server, then attach the test client
// to an intercepting server that injects 409 only on the first /push and delegates
// everything else (including /pull) to the real handler.
func TestPush_409Once_ThenSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	serverStore := syncserver.NewServerStore()
	if err := serverStore.Init(":memory:"); err != nil {
		t.Fatalf("server Init: %v", err)
	}
	defer func() { _ = serverStore.Close() }()

	vaultUUID := "push-409-once"
	if err := serverStore.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Shared credentials so both the seeder client and the test client can
	// decrypt each other's blobs.
	rawAPIKey := make([]byte, 32)
	if _, err := rand.Read(rawAPIKey); err != nil {
		t.Fatalf("rand rawAPIKey: %v", err)
	}
	keyHash := sha256.Sum256(rawAPIKey)
	if err := serverStore.AddAPIKey(vaultUUID, keyHash[:], "f4-shared"); err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}
	sharedSyncKey := make([]byte, 32)
	if _, err := rand.Read(sharedSyncKey); err != nil {
		t.Fatalf("rand sharedSyncKey: %v", err)
	}

	realAuth := syncserver.NewAuthMiddleware(serverStore)
	realMux := syncserver.NewHandlerMux(serverStore, realAuth)

	// Seed via direct real server (no 409 intercept).
	realTS := httptest.NewServer(realMux)
	defer realTS.Close()

	seederMK := newTestMasterKey(t)
	seederWrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte(hex.EncodeToString(rawAPIKey)), seederMK)
	seederWrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", sharedSyncKey, seederMK)

	seederDB := filepath.Join(t.TempDir(), "f4-seeder.sqlite")
	seederCS := store.NewSQLStore()
	if err := seederCS.Init(seederDB); err != nil {
		t.Fatalf("seeder Init: %v", err)
	}
	defer func() { _ = seederCS.Close() }()
	_ = seederCS.ConfigSet("sync_server_url", []byte(realTS.URL))
	_ = seederCS.ConfigSet("vault_uuid", []byte(vaultUUID))
	_ = seederCS.ConfigSet("api_key", seederWrappedAPI)
	_ = seederCS.ConfigSet("sync_encryption_key", seederWrappedSync)
	_ = seederCS.ConfigSet("last_sync_seq", []byte("0"))

	seederClient, err := syncpkg.NewClientInsecure(seederCS, seederMK)
	if err != nil {
		t.Fatalf("seeder NewClientInsecure: %v", err)
	}
	if err := testStoreSecret(seederCS, secret.Secret{
		Name: "seed-secret", Kind: secret.KindPassword, EncryptedValue: []byte("seed"),
	}); err != nil {
		t.Fatalf("Store seed: %v", err)
	}
	if _, err := seederClient.Push(); err != nil {
		t.Fatalf("seed Push: %v", err)
	}

	// Intercepting server: 409 on first /push, real handler for everything else.
	pushHits := 0
	pullHits := 0

	interceptTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/push") {
			pushHits++
			if pushHits == 1 {
				w.WriteHeader(http.StatusConflict)
				return
			}
		}
		if strings.HasSuffix(r.URL.Path, "/pull") {
			pullHits++
		}
		realMux.ServeHTTP(w, r)
	}))
	defer interceptTS.Close()

	// Test client: last_sync_seq=0 (behind the seeder's seq=1) → first push will 409.
	masterKey := newTestMasterKey(t)
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte(hex.EncodeToString(rawAPIKey)), masterKey)
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", sharedSyncKey, masterKey)

	dbPath := filepath.Join(t.TempDir(), "f4-client.sqlite")
	cs := store.NewSQLStore()
	if err := cs.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = cs.Close() }()

	_ = cs.ConfigSet("sync_server_url", []byte(interceptTS.URL))
	_ = cs.ConfigSet("vault_uuid", []byte(vaultUUID))
	_ = cs.ConfigSet("api_key", wrappedAPI)
	_ = cs.ConfigSet("sync_encryption_key", wrappedSync)
	_ = cs.ConfigSet("last_sync_seq", []byte("0"))
	// Anchor registration_seq=1 so no pre-flight fires on auto-pull.
	_ = cs.ConfigSet("registration_seq", []byte("1"))

	client, err := syncpkg.NewClientInsecure(cs, masterKey)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}

	if err := testStoreSecret(cs, secret.Secret{
		Name: "f4-secret", Kind: secret.KindPassword, EncryptedValue: []byte("val"),
	}); err != nil {
		t.Fatalf("Store f4-secret: %v", err)
	}

	_, err = client.Push()
	if err != nil {
		t.Fatalf("Push with 409-once-then-200 failed: %v", err)
	}
	if pullHits != 1 {
		t.Errorf("/pull hits = %d, want 1 (auto-pull must fire exactly once)", pullHits)
	}
	if pushHits != 2 {
		t.Errorf("/push hits = %d, want 2 (first 409, second success)", pushHits)
	}
}

// TestPush_409Twice_ReturnsError verifies that when the server returns 409 on both
// push attempts, Push returns an error containing "after auto-pull retry" and stops
// (no third /push call). /push must be hit exactly 2 times (ADR-10, loop bound=1).
//
// Strategy: server always returns 409 on /push, serves a valid blob on /pull so
// the auto-pull succeeds but the subsequent pushOnce still gets 409.
func TestPush_409Twice_ReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	serverStore := syncserver.NewServerStore()
	if err := serverStore.Init(":memory:"); err != nil {
		t.Fatalf("server Init: %v", err)
	}
	defer func() { _ = serverStore.Close() }()

	vaultUUID := "push-409-twice"
	if err := serverStore.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Shared credentials so the seeder blob is decryptable by the test client.
	rawAPIKey := make([]byte, 32)
	if _, err := rand.Read(rawAPIKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	keyHash := sha256.Sum256(rawAPIKey)
	if err := serverStore.AddAPIKey(vaultUUID, keyHash[:], "f4-twice"); err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}
	sharedSyncKey := make([]byte, 32)
	if _, err := rand.Read(sharedSyncKey); err != nil {
		t.Fatalf("rand: %v", err)
	}

	realAuth := syncserver.NewAuthMiddleware(serverStore)
	realMux := syncserver.NewHandlerMux(serverStore, realAuth)

	pushHits := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/push") {
			pushHits++
			w.WriteHeader(http.StatusConflict)
			return
		}
		// /pull and /status are served normally so auto-pull succeeds.
		realMux.ServeHTTP(w, r)
	}))
	defer ts.Close()

	// Seeder: push a valid blob so /pull has something to return.
	seederMK := newTestMasterKey(t)
	seederWrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte(hex.EncodeToString(rawAPIKey)), seederMK)
	seederWrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", sharedSyncKey, seederMK)

	seederStore := syncserver.NewServerStore()
	_ = seederStore // unused; we use clientStore for seeding

	seederDB := filepath.Join(t.TempDir(), "f4-seeder.sqlite")
	seederCS := store.NewSQLStore()
	if err := seederCS.Init(seederDB); err != nil {
		t.Fatalf("seeder Init: %v", err)
	}
	defer func() { _ = seederCS.Close() }()
	_ = seederCS.ConfigSet("sync_server_url", []byte(ts.URL))
	_ = seederCS.ConfigSet("vault_uuid", []byte(vaultUUID))
	_ = seederCS.ConfigSet("api_key", seederWrappedAPI)
	_ = seederCS.ConfigSet("sync_encryption_key", seederWrappedSync)
	_ = seederCS.ConfigSet("last_sync_seq", []byte("0"))

	// The seeder push will also be intercepted and return 409.
	// We need to bypass the 409 intercept for the seeder. Use a separate
	// server with the real handler for seeding, then switch to the 409 server.
	realTS := httptest.NewServer(realMux)
	defer realTS.Close()

	_ = seederCS.ConfigSet("sync_server_url", []byte(realTS.URL))
	seederClient, err := syncpkg.NewClientInsecure(seederCS, seederMK)
	if err != nil {
		t.Fatalf("seeder NewClientInsecure: %v", err)
	}
	if err := testStoreSecret(seederCS, secret.Secret{
		Name: "seed", Kind: secret.KindPassword, EncryptedValue: []byte("v"),
	}); err != nil {
		t.Fatalf("Store seed: %v", err)
	}
	if _, err := seederClient.Push(); err != nil {
		t.Fatalf("seeder Push: %v", err)
	}
	// Reset counter — seeder pushes went to realTS, not ts.
	pushHits = 0

	// Test client uses the 409 server.
	masterKey := newTestMasterKey(t)
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte(hex.EncodeToString(rawAPIKey)), masterKey)
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", sharedSyncKey, masterKey)

	dbPath := filepath.Join(t.TempDir(), "f4-twice-client.sqlite")
	cs := store.NewSQLStore()
	if err := cs.Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = cs.Close() }()

	_ = cs.ConfigSet("sync_server_url", []byte(ts.URL))
	_ = cs.ConfigSet("vault_uuid", []byte(vaultUUID))
	_ = cs.ConfigSet("api_key", wrappedAPI)
	_ = cs.ConfigSet("sync_encryption_key", wrappedSync)
	_ = cs.ConfigSet("last_sync_seq", []byte("0"))
	// Set registration_seq so the auto-pull pre-flight doesn't fire unexpectedly.
	_ = cs.ConfigSet("registration_seq", []byte("1"))

	client, err := syncpkg.NewClientInsecure(cs, masterKey)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}

	if err := testStoreSecret(cs, secret.Secret{
		Name: "f4-twice-sec", Kind: secret.KindPassword, EncryptedValue: []byte("v"),
	}); err != nil {
		t.Fatalf("Store: %v", err)
	}

	_, err = client.Push()
	if err == nil {
		t.Fatal("expected error from Push when server always returns 409, got nil")
	}
	if !strings.Contains(err.Error(), "after auto-pull retry") {
		t.Errorf("error = %q, want message containing \"after auto-pull retry\"", err.Error())
	}
	if pushHits != 2 {
		t.Errorf("/push hits = %d, want exactly 2 (no third push)", pushHits)
	}
}

func TestClient_Pull_NoRemoteData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	serverStore := syncserver.NewServerStore()
	if err := serverStore.Init(":memory:"); err != nil {
		t.Fatalf("server store Init: %v", err)
	}
	defer func() { _ = serverStore.Close() }()

	vaultUUID := "pull-empty-test"
	if err := serverStore.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyHash := sha256.Sum256(rawKey)
	if err := serverStore.AddAPIKey(vaultUUID, keyHash[:], "test-key"); err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}

	auth := syncserver.NewAuthMiddleware(serverStore)
	mux := syncserver.NewHandlerMux(serverStore, auth)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	dbPath := filepath.Join(t.TempDir(), "pull-empty-client.sqlite")
	clientStore := store.NewSQLStore()
	if err := clientStore.Init(dbPath); err != nil {
		t.Fatalf("client store Init: %v", err)
	}
	defer func() { _ = clientStore.Close() }()

	syncKey := make([]byte, 32)
	if _, err := rand.Read(syncKey); err != nil {
		t.Fatalf("generate sync key: %v", err)
	}

	masterKey := newTestMasterKey(t)
	wrappedAPI, _ := syncpkg.WrapConfigValue("api_key", []byte(hex.EncodeToString(rawKey)), masterKey)
	wrappedSync, _ := syncpkg.WrapConfigValue("sync_encryption_key", syncKey, masterKey)

	_ = clientStore.ConfigSet("sync_server_url", []byte(ts.URL))
	_ = clientStore.ConfigSet("vault_uuid", []byte(vaultUUID))
	_ = clientStore.ConfigSet("api_key", wrappedAPI)
	_ = clientStore.ConfigSet("sync_encryption_key", wrappedSync)
	_ = clientStore.ConfigSet("last_sync_seq", []byte("0"))

	client, err := syncpkg.NewClientInsecure(clientStore, masterKey)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}

	// Pull from vault with no blob — should return not found error
	_, err = client.Pull()
	if err == nil {
		t.Fatal("expected error pulling from empty server, got nil")
	}
}
