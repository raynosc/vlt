package sync

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/raynosc/vlt/internal/secret"
)

func TestSyncPayload_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload := SyncPayload{
		Secrets: []secret.Secret{
			{
				ID:             "abc-123",
				Name:           "test-key",
				Kind:           secret.KindPassword,
				EncryptedValue: []byte("ciphertext-data"),
				Notes:          "my note",
				Tags:           "test,tag",
				CreatedAt:      now,
				UpdatedAt:      now,
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal SyncPayload: %v", err)
	}

	var decoded SyncPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal SyncPayload: %v", err)
	}

	if len(decoded.Secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(decoded.Secrets))
	}
	if decoded.Secrets[0].Name != "test-key" {
		t.Errorf("Name = %q, want %q", decoded.Secrets[0].Name, "test-key")
	}
	if string(decoded.Secrets[0].EncryptedValue) != "ciphertext-data" {
		t.Errorf("EncryptedValue = %q, want %q", string(decoded.Secrets[0].EncryptedValue), "ciphertext-data")
	}
	if decoded.Secrets[0].Kind != secret.KindPassword {
		t.Errorf("Kind = %q, want %q", decoded.Secrets[0].Kind, secret.KindPassword)
	}
}

func TestSyncPayload_EmptySecrets(t *testing.T) {
	payload := SyncPayload{
		Secrets: []secret.Secret{},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal empty SyncPayload: %v", err)
	}

	var decoded SyncPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal empty SyncPayload: %v", err)
	}

	if decoded.Secrets == nil {
		t.Error("expected non-nil empty slice after unmarshal")
	}
	if len(decoded.Secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(decoded.Secrets))
	}
}

func TestPushRequest_JSONRoundTrip(t *testing.T) {
	req := PushRequest{
		Seq:  42,
		Blob: []byte("encrypted-blob-data"),
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal PushRequest: %v", err)
	}

	var decoded PushRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal PushRequest: %v", err)
	}

	if decoded.Seq != 42 {
		t.Errorf("Seq = %d, want %d", decoded.Seq, 42)
	}
	if string(decoded.Blob) != "encrypted-blob-data" {
		t.Errorf("Blob = %q, want %q", string(decoded.Blob), "encrypted-blob-data")
	}
}

func TestPushRequest_ZeroValue(t *testing.T) {
	req := PushRequest{}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal zero PushRequest: %v", err)
	}

	var decoded PushRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal zero PushRequest: %v", err)
	}

	if decoded.Seq != 0 {
		t.Errorf("Seq = %d, want 0", decoded.Seq)
	}
	if decoded.Blob != nil {
		t.Errorf("Blob = %v, want nil", decoded.Blob)
	}
}

func TestPullResponse_JSONRoundTrip(t *testing.T) {
	resp := PullResponse{
		Seq:  99,
		Blob: []byte("server-blob-data"),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal PullResponse: %v", err)
	}

	var decoded PullResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal PullResponse: %v", err)
	}

	if decoded.Seq != 99 {
		t.Errorf("Seq = %d, want %d", decoded.Seq, 99)
	}
	if string(decoded.Blob) != "server-blob-data" {
		t.Errorf("Blob = %q, want %q", string(decoded.Blob), "server-blob-data")
	}
}

func TestSyncConflict_JSONRoundTrip(t *testing.T) {
	localTS := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	remoteTS := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)

	conflict := SyncConflict{
		Name:     "conflict-key",
		LocalTS:  localTS,
		RemoteTS: remoteTS,
		Resolved: "remote_wins",
	}

	data, err := json.Marshal(conflict)
	if err != nil {
		t.Fatalf("Marshal SyncConflict: %v", err)
	}

	var decoded SyncConflict
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal SyncConflict: %v", err)
	}

	if decoded.Name != "conflict-key" {
		t.Errorf("Name = %q, want %q", decoded.Name, "conflict-key")
	}
	if !decoded.LocalTS.Equal(localTS) {
		t.Errorf("LocalTS = %v, want %v", decoded.LocalTS, localTS)
	}
	if !decoded.RemoteTS.Equal(remoteTS) {
		t.Errorf("RemoteTS = %v, want %v", decoded.RemoteTS, remoteTS)
	}
	if decoded.Resolved != "remote_wins" {
		t.Errorf("Resolved = %q, want %q", decoded.Resolved, "remote_wins")
	}
}

func TestVaultStatus_JSONRoundTrip(t *testing.T) {
	updated := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	status := VaultStatus{
		VaultUUID:   "vault-abc",
		Seq:         7,
		LastUpdated: updated,
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("Marshal VaultStatus: %v", err)
	}

	var decoded VaultStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal VaultStatus: %v", err)
	}

	if decoded.VaultUUID != "vault-abc" {
		t.Errorf("VaultUUID = %q, want %q", decoded.VaultUUID, "vault-abc")
	}
	if decoded.Seq != 7 {
		t.Errorf("Seq = %d, want %d", decoded.Seq, 7)
	}
	if !decoded.LastUpdated.Equal(updated) {
		t.Errorf("LastUpdated = %v, want %v", decoded.LastUpdated, updated)
	}
}
