// Package syncserver provides the sync protocol server implementation.
//
// It stores encrypted vault blobs in SQLite, authenticates via API keys,
// and exposes REST endpoints for push/pull/status operations.
package syncserver

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	syncpkg "github.com/raynosc/vlt/internal/sync"
)

// VaultRow represents a row in the vaults table.
type VaultRow struct {
	VaultUUID     string
	EncryptedBlob []byte
	Seq           int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// APIKeyRow represents a row in the api_keys table.
type APIKeyRow struct {
	KeyHash   []byte
	VaultUUID string
	Label     string
	CreatedAt time.Time
	Revoked   bool
}

const sqliteTimeFormat = "2006-01-02 15:04:05"

// ServerStore provides SQLite storage for the sync server.
type ServerStore struct {
	mu sync.RWMutex
	db *sql.DB
}

// NewServerStore creates a new ServerStore. Call Init before use.
func NewServerStore() *ServerStore {
	return &ServerStore{}
}

// Init opens the SQLite database and creates tables if needed.
func (s *ServerStore) Init(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create sync db dir: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}

	// Enable WAL mode and foreign keys
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return fmt.Errorf("enable WAL: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		_ = db.Close()
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	s.db = db

	if err := s.createTables(); err != nil {
		_ = db.Close()
		s.db = nil
		return fmt.Errorf("create tables: %w", err)
	}

	return nil
}

// createTables creates the vaults and api_keys tables if they don't exist.
func (s *ServerStore) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS vaults (
			vault_uuid TEXT PRIMARY KEY,
			encrypted_blob BLOB,
			seq INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			key_hash BLOB PRIMARY KEY,
			vault_uuid TEXT NOT NULL,
			label TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			revoked INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (vault_uuid) REFERENCES vaults(vault_uuid)
		)`,
		`CREATE TABLE IF NOT EXISTS sync_devices (
			device_id TEXT PRIMARY KEY,
			vault_uuid TEXT NOT NULL,
			hostname TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			client_version TEXT NOT NULL,
			client_cert_fingerprint TEXT,
			revoked INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
			FOREIGN KEY (vault_uuid) REFERENCES vaults(vault_uuid) ON DELETE CASCADE
		)`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("exec table creation: %w", err)
		}
	}
	return nil
}

// Close closes the database connection.
func (s *ServerStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db != nil {
		err := s.db.Close()
		s.db = nil
		return err
	}
	return nil
}

// CreateVault creates a new vault record.
func (s *ServerStore) CreateVault(vaultUUID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	_, err := s.db.Exec(
		"INSERT INTO vaults (vault_uuid, seq) VALUES (?, 0)",
		vaultUUID,
	)
	if err != nil {
		return fmt.Errorf("create vault: %w", err)
	}
	return nil
}

// GetVault retrieves a vault by UUID, including the blob.
func (s *ServerStore) GetVault(vaultUUID string) (*VaultRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	var row VaultRow
	var createdAtStr, updatedAtStr string

	err := s.db.QueryRow(
		`SELECT vault_uuid, encrypted_blob, seq, created_at, updated_at
		 FROM vaults WHERE vault_uuid = ?`,
		vaultUUID,
	).Scan(&row.VaultUUID, &row.EncryptedBlob, &row.Seq, &createdAtStr, &updatedAtStr)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("vault not found: %s", vaultUUID)
	}
	if err != nil {
		return nil, fmt.Errorf("get vault: %w", err)
	}

	row.CreatedAt, _ = time.Parse(sqliteTimeFormat, createdAtStr)
	row.UpdatedAt, _ = time.Parse(sqliteTimeFormat, updatedAtStr)

	return &row, nil
}

// UpdateBlob stores an encrypted blob for a vault, incrementing the sequence
// number. It validates that the client's seq matches the current server seq
// to prevent lost updates. Returns the new sequence number.
func (s *ServerStore) UpdateBlob(vaultUUID string, blob []byte, clientSeq int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return 0, fmt.Errorf("store not initialized")
	}

	// Read current seq
	var currentSeq int64
	err := s.db.QueryRow("SELECT seq FROM vaults WHERE vault_uuid = ?", vaultUUID).Scan(&currentSeq)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("vault not found: %s", vaultUUID)
	}
	if err != nil {
		return 0, fmt.Errorf("read current seq: %w", err)
	}

	if clientSeq != currentSeq {
		return 0, fmt.Errorf("seq mismatch: client %d, server %d", clientSeq, currentSeq)
	}

	newSeq := currentSeq + 1
	now := time.Now().UTC().Format(sqliteTimeFormat)

	_, err = s.db.Exec(
		"UPDATE vaults SET encrypted_blob = ?, seq = ?, updated_at = ? WHERE vault_uuid = ?",
		blob, newSeq, now, vaultUUID,
	)
	if err != nil {
		return 0, fmt.Errorf("update blob: %w", err)
	}

	return newSeq, nil
}

// AddAPIKey adds a new API key for a vault.
func (s *ServerStore) AddAPIKey(vaultUUID string, keyHash []byte, label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	_, err := s.db.Exec(
		"INSERT INTO api_keys (key_hash, vault_uuid, label) VALUES (?, ?, ?)",
		keyHash, vaultUUID, label,
	)
	if err != nil {
		return fmt.Errorf("add api key: %w", err)
	}
	return nil
}

// GetAPIKey retrieves an API key by its hash.
func (s *ServerStore) GetAPIKey(keyHash []byte) (*APIKeyRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	var row APIKeyRow
	var createdAtStr string
	var revokedInt int

	err := s.db.QueryRow(
		`SELECT key_hash, vault_uuid, label, created_at, revoked
		 FROM api_keys WHERE key_hash = ?`,
		keyHash,
	).Scan(&row.KeyHash, &row.VaultUUID, &row.Label, &createdAtStr, &revokedInt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("api key not found")
	}
	if err != nil {
		return nil, fmt.Errorf("get api key: %w", err)
	}

	row.CreatedAt, _ = time.Parse(sqliteTimeFormat, createdAtStr)
	row.Revoked = revokedInt != 0

	return &row, nil
}

// RevokeAPIKey marks an API key as revoked, restricted to the authenticated vaultUUID to prevent IDOR.
func (s *ServerStore) RevokeAPIKey(vaultUUID string, keyHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	result, err := s.db.Exec("UPDATE api_keys SET revoked = 1 WHERE key_hash = ? AND vault_uuid = ?", keyHash, vaultUUID)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("api key not found")
	}

	return nil
}

// GetVaultStatus returns vault metadata (seq, last_updated) without the blob.
func (s *ServerStore) GetVaultStatus(vaultUUID string) (*syncpkg.VaultStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	var status syncpkg.VaultStatus
	var updatedAtStr string

	err := s.db.QueryRow(
		"SELECT vault_uuid, COALESCE(seq, 0), updated_at FROM vaults WHERE vault_uuid = ?",
		vaultUUID,
	).Scan(&status.VaultUUID, &status.Seq, &updatedAtStr)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("vault not found: %s", vaultUUID)
	}
	if err != nil {
		return nil, fmt.Errorf("get vault status: %w", err)
	}

	status.LastUpdated, _ = time.Parse(sqliteTimeFormat, updatedAtStr)

	return &status, nil
}

// VerifyExists checks if a vault exists (used by auth middleware).
func (s *ServerStore) VerifyExists(vaultUUID string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM vaults WHERE vault_uuid = ?", vaultUUID).Scan(&count)
	if err != nil {
		return fmt.Errorf("verify vault: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("vault not found: %s", vaultUUID)
	}
	return nil
}

// UpsertDevice inserts or updates a client device record in sync_devices.
func (s *ServerStore) UpsertDevice(dev syncpkg.DeviceInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	query := `INSERT INTO sync_devices (
		device_id, vault_uuid, hostname, ip_address, client_version, client_cert_fingerprint, revoked, created_at, last_seen_at
	) VALUES (?, ?, ?, ?, ?, ?, 0, datetime('now'), datetime('now'))
	ON CONFLICT(device_id) DO UPDATE SET
		hostname = excluded.hostname,
		ip_address = excluded.ip_address,
		client_version = excluded.client_version,
		client_cert_fingerprint = excluded.client_cert_fingerprint,
		last_seen_at = datetime('now')
	WHERE sync_devices.revoked = 0`

	_, err := s.db.Exec(query, dev.DeviceID, dev.VaultUUID, dev.Hostname, dev.IPAddress, dev.ClientVersion, dev.ClientCertFingerprint)
	if err != nil {
		return fmt.Errorf("upsert device: %w", err)
	}
	return nil
}

// ListDevices returns all registered devices for a vault.
func (s *ServerStore) ListDevices(vaultUUID string) ([]syncpkg.DeviceInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	query := `SELECT device_id, vault_uuid, hostname, ip_address, client_version, 
		COALESCE(client_cert_fingerprint, ''), revoked, created_at, last_seen_at 
		FROM sync_devices WHERE vault_uuid = ? ORDER BY last_seen_at DESC`

	rows, err := s.db.Query(query, vaultUUID)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var devices []syncpkg.DeviceInfo
	for rows.Next() {
		var dev syncpkg.DeviceInfo
		var revokedInt int
		var createdStr, lastSeenStr string

		if err := rows.Scan(
			&dev.DeviceID, &dev.VaultUUID, &dev.Hostname, &dev.IPAddress, &dev.ClientVersion,
			&dev.ClientCertFingerprint, &revokedInt, &createdStr, &lastSeenStr,
		); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}

		dev.Revoked = revokedInt == 1
		dev.CreatedAt, _ = time.Parse(sqliteTimeFormat, createdStr)
		dev.LastSeenAt, _ = time.Parse(sqliteTimeFormat, lastSeenStr)
		devices = append(devices, dev)
	}

	return devices, nil
}

// RevokeDevice marks a device as revoked.
func (s *ServerStore) RevokeDevice(vaultUUID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	result, err := s.db.Exec(
		"UPDATE sync_devices SET revoked = 1, last_seen_at = datetime('now') WHERE vault_uuid = ? AND device_id = ?",
		vaultUUID, deviceID,
	)
	if err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("device not found")
	}

	return nil
}

// IsDeviceRevoked checks if a device is marked as revoked.
func (s *ServerStore) IsDeviceRevoked(vaultUUID, deviceID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return false, fmt.Errorf("store not initialized")
	}

	var revokedInt int
	err := s.db.QueryRow(
		"SELECT revoked FROM sync_devices WHERE vault_uuid = ? AND device_id = ?",
		vaultUUID, deviceID,
	).Scan(&revokedInt)

	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query device revoked: %w", err)
	}

	return revokedInt == 1, nil
}
