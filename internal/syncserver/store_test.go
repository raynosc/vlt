package syncserver

import (
	"testing"
	"time"
)

func TestServerStore_InitAndSchema(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Verify vaults table exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='vaults'").Scan(&count)
	if err != nil {
		t.Fatalf("check vaults table: %v", err)
	}
	if count != 1 {
		t.Error("vaults table not created")
	}

	// Verify api_keys table exists
	err = s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='api_keys'").Scan(&count)
	if err != nil {
		t.Fatalf("check api_keys table: %v", err)
	}
	if count != 1 {
		t.Error("api_keys table not created")
	}
}

func TestServerStore_VaultCRUD(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Create vault
	vaultUUID := "test-vault-uuid"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	// Get vault
	vault, err := s.GetVault(vaultUUID)
	if err != nil {
		t.Fatalf("GetVault failed: %v", err)
	}
	if vault.VaultUUID != vaultUUID {
		t.Errorf("VaultUUID = %q, want %q", vault.VaultUUID, vaultUUID)
	}
	if vault.Seq != 0 {
		t.Errorf("initial Seq = %d, want 0", vault.Seq)
	}
	if vault.EncryptedBlob != nil {
		t.Errorf("expected nil blob for new vault, got %d bytes", len(vault.EncryptedBlob))
	}
	if vault.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestServerStore_GetVault_NotFound(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, err := s.GetVault("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent vault, got nil")
	}
}

func TestServerStore_UpdateBlob(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	vaultUUID := "blob-test-vault"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	blob := []byte("encrypted-blob-data")
	newSeq, err := s.UpdateBlob(vaultUUID, blob, 0)
	if err != nil {
		t.Fatalf("UpdateBlob failed: %v", err)
	}
	if newSeq != 1 {
		t.Errorf("Seq after first update = %d, want 1", newSeq)
	}

	// Verify blob is stored
	vault, err := s.GetVault(vaultUUID)
	if err != nil {
		t.Fatalf("GetVault after update: %v", err)
	}
	if string(vault.EncryptedBlob) != string(blob) {
		t.Errorf("blob mismatch:\ngot:  %x\nwant: %x", vault.EncryptedBlob, blob)
	}
	if vault.Seq != 1 {
		t.Errorf("Seq = %d, want 1", vault.Seq)
	}
}

func TestServerStore_UpdateBlob_SeqIncrement(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	vaultUUID := "seq-test-vault"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	// Push three times, seq should increment
	for i := 1; i <= 3; i++ {
		blob := []byte("blob-v" + string(rune('0'+i)))
		newSeq, err := s.UpdateBlob(vaultUUID, blob, int64(i-1))
		if err != nil {
			t.Fatalf("UpdateBlob attempt %d failed: %v", i, err)
		}
		if newSeq != int64(i) {
			t.Errorf("UpdateBlob %d: expected seq %d, got %d", i, i, newSeq)
		}
	}
}

func TestServerStore_UpdateBlob_WrongSeq(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	vaultUUID := "wrong-seq-vault"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	// First update with seq=0 should work
	if _, err := s.UpdateBlob(vaultUUID, []byte("v1"), 0); err != nil {
		t.Fatalf("first UpdateBlob failed: %v", err)
	}

	// Second update with wrong seq (0 instead of 1) should fail
	_, err := s.UpdateBlob(vaultUUID, []byte("v2-wrong"), 0)
	if err == nil {
		t.Fatal("expected error for wrong seq, got nil")
	}
}

func TestServerStore_ApiKeyCRUD(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	vaultUUID := "key-test-vault"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	keyHash := []byte("sha256-hash-of-api-key")
	label := "test-key"

	if err := s.AddAPIKey(vaultUUID, keyHash, label); err != nil {
		t.Fatalf("AddAPIKey failed: %v", err)
	}

	// Lookup by hash
	gotKey, err := s.GetAPIKey(keyHash)
	if err != nil {
		t.Fatalf("GetAPIKey failed: %v", err)
	}
	if gotKey.VaultUUID != vaultUUID {
		t.Errorf("VaultUUID = %q, want %q", gotKey.VaultUUID, vaultUUID)
	}
	if gotKey.Label != label {
		t.Errorf("Label = %q, want %q", gotKey.Label, label)
	}
	if gotKey.Revoked {
		t.Error("new key should not be revoked")
	}
}

func TestServerStore_RevokeAPIKey(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	vaultUUID := "revoke-test-vault"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	keyHash := []byte("hash-to-revoke")
	if err := s.AddAPIKey(vaultUUID, keyHash, "revocable"); err != nil {
		t.Fatalf("AddAPIKey failed: %v", err)
	}

	if err := s.RevokeAPIKey(vaultUUID, keyHash); err != nil {
		t.Fatalf("RevokeAPIKey failed: %v", err)
	}

	// Verify revoked
	gotKey, err := s.GetAPIKey(keyHash)
	if err != nil {
		t.Fatalf("GetAPIKey after revoke: %v", err)
	}
	if !gotKey.Revoked {
		t.Error("key should be marked as revoked")
	}
}

func TestServerStore_APIKey_NotFound(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, err := s.GetAPIKey([]byte("nonexistent-hash"))
	if err == nil {
		t.Fatal("expected error for nonexistent key, got nil")
	}
}

func TestServerStore_GetVaultStatus(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	vaultUUID := "status-test-vault"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	// Update blob a couple times
	if _, err := s.UpdateBlob(vaultUUID, []byte("v1"), 0); err != nil {
		t.Fatalf("UpdateBlob v1: %v", err)
	}
	if _, err := s.UpdateBlob(vaultUUID, []byte("v2"), 1); err != nil {
		t.Fatalf("UpdateBlob v2: %v", err)
	}

	status, err := s.GetVaultStatus(vaultUUID)
	if err != nil {
		t.Fatalf("GetVaultStatus failed: %v", err)
	}
	if status.VaultUUID != vaultUUID {
		t.Errorf("VaultUUID = %q, want %q", status.VaultUUID, vaultUUID)
	}
	if status.Seq != 2 {
		t.Errorf("Seq = %d, want 2", status.Seq)
	}
	if status.LastUpdated.IsZero() {
		t.Error("expected non-zero LastUpdated")
	}
}

func TestServerStore_GetVaultStatus_NoBlob(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	vaultUUID := "empty-status-vault"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	status, err := s.GetVaultStatus(vaultUUID)
	if err != nil {
		t.Fatalf("GetVaultStatus failed: %v", err)
	}
	if status.Seq != 0 {
		t.Errorf("Seq = %d, want 0 for vault with no blob", status.Seq)
	}
}

func TestServerStore_DoubleInit_Idempotent(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("first Init failed: %v", err)
	}
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("second Init failed: %v", err)
	}
	_ = s.Close()
}

// Time-based helper for test stability
var _ = time.Now
