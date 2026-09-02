// Package sync provides types and operations for vault synchronization.
//
// It implements the sync protocol: encrypted blob push/pull between client
// and server, LWW conflict resolution, and conflict logging.
package sync

import (
	"time"

	"github.com/raynosc/vlt/internal/secret"
)

// SyncPayload wraps the full set of secrets for encrypted transport.
type SyncPayload struct {
	Secrets []secret.Secret `json:"secrets"`
}

// PushRequest is the body sent to the server when pushing a snapshot.
type PushRequest struct {
	Seq  int64  `json:"seq"`
	Blob []byte `json:"blob"` // base64-encoded ciphertext
}

// PushResponse is returned by the server after a successful push.
type PushResponse struct {
	Seq    int64  `json:"seq"`
	Status string `json:"status"`
}

// PullResponse is returned by the server when pulling a snapshot.
type PullResponse struct {
	Seq  int64  `json:"seq"`
	Blob []byte `json:"blob"` // base64-encoded ciphertext
}

// SyncConflict records a conflict where local and remote versions diverged.
type SyncConflict struct {
	Name     string    `json:"name"`
	LocalTS  time.Time `json:"local_updated_at"`
	RemoteTS time.Time `json:"remote_updated_at"`
	Resolved string    `json:"resolution"` // "local_wins" | "remote_wins"
}

// VaultStatus represents server-side vault metadata (no blob content).
type VaultStatus struct {
	VaultUUID   string    `json:"vault_uuid"`
	Seq         int64     `json:"seq"`
	LastUpdated time.Time `json:"last_updated"`
}

// RegisterRequest is sent to create a new vault and obtain an API key.
type RegisterRequest struct {
	VaultUUID string `json:"vault_uuid"`
	KeyHash   []byte `json:"key_hash"`
}

// RegisterResponse is returned after successful vault registration.
type RegisterResponse struct {
	VaultUUID string `json:"vault_uuid"`
	Status    string `json:"status,omitempty"`
	APIKey    string `json:"api_key,omitempty"`
	// VaultSeq is the server's current sequence number at registration time.
	// New vaults return 0; re-registration/adopt returns the current seq.
	// Used by the client to anchor registration_seq (F1/F2 anti-rollback).
	VaultSeq int64 `json:"vault_seq"`
}

// RevokeRequest is sent to revoke an API key.
type RevokeRequest struct {
	KeyHash []byte `json:"key_hash"`
}

// ErrorResponse is a standard error body returned by the server.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

// DeviceInfo represents a registered device connected to the sync server.
type DeviceInfo struct {
	DeviceID              string    `json:"device_id"`
	VaultUUID             string    `json:"vault_uuid"`
	Hostname              string    `json:"hostname"`
	IPAddress             string    `json:"ip_address"`
	ClientVersion         string    `json:"client_version"`
	ClientCertFingerprint string    `json:"client_cert_fingerprint,omitempty"`
	Revoked               bool      `json:"revoked"`
	CreatedAt             time.Time `json:"created_at"`
	LastSeenAt            time.Time `json:"last_seen_at"`
}

// HeartbeatRequest is sent by clients to register or update their active device presence.
type HeartbeatRequest struct {
	DeviceID              string `json:"device_id"`
	Hostname              string `json:"hostname"`
	ClientVersion         string `json:"client_version"`
	ClientCertFingerprint string `json:"client_cert_fingerprint,omitempty"`
}

// SecurityAlert represents a real-time security intrusion or circuit breaker event.
type SecurityAlert struct {
	EventID   string     `json:"event_id"`
	VaultUUID string     `json:"vault_uuid"`
	EventType string     `json:"event_type"` // e.g. "security_alert"
	Severity  string     `json:"severity"`   // "WARNING", "HIGH", "CRITICAL"
	Reason    string     `json:"reason"`     // e.g. "circuit_breaker_pin_challenge_triggered"
	Device    DeviceInfo `json:"device"`
	Timestamp time.Time  `json:"timestamp"`
	Signature string     `json:"signature,omitempty"`
}
