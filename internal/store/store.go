// Package store provides SQLite-backed encrypted secret storage.
//
// The Store layer is a dumb encrypted blob store — it NEVER performs
// encryption or decryption. Secret values are always ciphertext BLOBs.
// Metadata (name, kind, tags, notes) is stored as plaintext for searchability.
//
// Dependencies:
//   - internal/config (for DB path resolution)
//   - modernc.org/sqlite (pure Go, no CGo)
//
// Store does NOT depend on internal/crypto (by design — crypto is the layer above).
package store

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/raynosc/vlt/internal/secret"
)

// CurrentSchemaVersion is the latest schema version the application expects.
//
// v7 is a clean break that encrypts all secret metadata at rest:
// name, notes, tags, and metadata are stored as ciphertext BLOBs.
// A name_lookup column holds HMAC-SHA256(masterKey, "passwd.name."+name)
// with a UNIQUE constraint for O(1) exact-match lookup.
//
// Legacy v1–v6 vaults are NOT migrated in-place. Init() returns
// ErrMigrationRequired, directing the user to export and re-import.
const CurrentSchemaVersion = 7

// Store defines the interface for encrypted secret storage operations.
// All methods are safe for concurrent use.
//
// Schema v7: metadata (name, notes, tags, metadata) is stored as encrypted
// BLOBs. The store does NOT perform encryption/decryption — callers must
// populate Encrypted* fields and NameLookup before Store, and decrypt after
// Load. Name-based lookups use the pre-computed NameLookup HMAC.
type Store interface {
	// Init opens or creates the SQLite database and runs migrations.
	Init(path string) error

	// Store inserts a new secret or returns ErrDuplicate if name_lookup exists.
	// The secret's EncryptedValue must be ciphertext — never plaintext.
	// Callers must set NameLookup, EncryptedName, EncryptedNotes, EncryptedTags,
	// and EncryptedMetadata before calling Store.
	Store(s secret.Secret) error

	// GetByNameLookup retrieves a secret by its HMAC name_lookup BLOB.
	// Returns ErrNotFound if the lookup does not exist.
	GetByNameLookup(nameLookup []byte) (secret.Secret, error)

	// GetByID retrieves a secret by its UUID.
	// Returns ErrNotFound if the ID does not exist.
	GetByID(id string) (secret.Secret, error)

	// List returns all live secrets with encrypted metadata only
	// (EncryptedValue is nil). Soft-deleted rows are excluded.
	List() ([]secret.Secret, error)

	// ListWithEncryptedAll returns all live secrets with full encrypted values.
	// Soft-deleted rows are excluded.
	ListWithEncryptedAll() ([]secret.Secret, error)

	// DeleteByLookup removes a live secret by its name_lookup BLOB.
	// Returns ErrNotFound if the lookup does not exist.
	DeleteByLookup(nameLookup []byte) error

	// SoftDeleteByLookup marks a secret as deleted by its name_lookup BLOB.
	// Returns ErrNotFound if the lookup does not exist or is already deleted.
	SoftDeleteByLookup(nameLookup []byte) error

	// ListWithTombstones returns all secrets including soft-deleted ones, with
	// full encrypted values. Used only by the sync layer for snapshot push/merge.
	ListWithTombstones() ([]secret.Secret, error)

	// PurgeTombstones hard-deletes tombstones with deleted_at < before.
	// Returns the number of rows deleted.
	PurgeTombstones(before time.Time) (int, error)

	// UpdateTombstoneDeletedAt advances the deleted_at timestamp of a tombstone to
	// the given time. Used by the sync merge loop when a remote tombstone has a
	// newer DeletedAt than the local one so the purge horizon is not stale.
	// The nameLookup identifies the tombstone.
	// Returns ErrNotFound if the secret does not exist or is not a tombstone.
	UpdateTombstoneDeletedAt(nameLookup []byte, deletedAt time.Time) error

	// UpdateOTPSeedAndMetadata atomically updates the encrypted_otp_seed and
	// encrypted_metadata columns of an existing secret in a single statement,
	// preserving the encrypted value.
	// Returns ErrNotFound if the name_lookup does not exist.
	UpdateOTPSeedAndMetadata(nameLookup []byte, encryptedOTPSeed []byte, encryptedMetadata []byte) error

	// ConfigGet retrieves a value from the config table by key.
	// Returns ErrNotFound if the key does not exist.
	ConfigGet(key string) ([]byte, error)

	// ConfigSet stores a value in the config table.
	// If the key already exists, it is overwritten.
	ConfigSet(key string, value []byte) error

	// ConfigDelete removes a value from the config table by key.
	ConfigDelete(key string) error

	// Count returns the number of live secrets in the vault.
	Count() (int, error)

	// LogAction records an audit log entry with the given action, secret name,
	// and optional details. Auto-prunes to keep the last 1000 entries.
	LogAction(action, secretName, details string) error

	// GetAuditLog returns the most recent audit log entries up to the given limit.
	GetAuditLog(limit int) ([]secret.AuditEntry, error)

	// Close closes the database connection.
	Close() error
}

// SQLStore is a SQLite-backed implementation of Store.
type SQLStore struct {
	mu sync.RWMutex
	db *sql.DB
}

// NewSQLStore creates a new SQLStore. Call Init before using.
func NewSQLStore() *SQLStore {
	return &SQLStore{}
}

// Init opens or creates the SQLite database at the given path and runs
// any pending schema migrations.
func (s *SQLStore) Init(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create vault dir: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}

	// Enable WAL mode for better concurrent read performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return fmt.Errorf("enable WAL: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		_ = db.Close()
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	s.db = db

	if err := s.runMigrations(); err != nil {
		_ = db.Close()
		s.db = nil
		return fmt.Errorf("migrations: %w", err)
	}

	return nil
}

// runMigrations handles the v7 clean-break policy:
//   - New vaults (currentVersion == 0) get the v7 schema created directly.
//   - Legacy v1–v6 vaults are rejected with ErrMigrationRequired.
//   - v7 vaults are accepted as-is.
func (s *SQLStore) runMigrations() error {
	currentVersion := 0

	// Check if schema_version table exists
	row := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'")
	var count int
	if err := row.Scan(&count); err != nil {
		return fmt.Errorf("check schema_version table: %w", err)
	}

	if count > 0 {
		// Read current version
		err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&currentVersion)
		if err != nil {
			return fmt.Errorf("read schema version: %w", err)
		}
	}

	if currentVersion >= CurrentSchemaVersion {
		return nil
	}

	// Clean break: reject legacy vaults v1–v6
	if currentVersion > 0 && currentVersion < CurrentSchemaVersion {
		return fmt.Errorf("schema v%d: %w", currentVersion, ErrMigrationRequired)
	}

	// New vault (version 0) — create v7 schema directly
	if currentVersion == 0 {
		if err := s.createV7Schema(); err != nil {
			return fmt.Errorf("create v7 schema: %w", err)
		}
	}

	return nil
}

// createV7Schema creates the full v7 schema for a brand-new vault.
func (s *SQLStore) createV7Schema() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(migration007); err != nil {
		return fmt.Errorf("exec v7 schema: %w", err)
	}
	if _, err := tx.Exec("INSERT INTO schema_version (version) VALUES (?)", CurrentSchemaVersion); err != nil {
		return fmt.Errorf("record schema version: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit v7 schema: %w", err)
	}
	return nil
}

// migration001 is the initial schema SQL, embedded from migrations/001_initial.sql.
const migration001 = `
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'other',
    encrypted_value BLOB NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
CREATE INDEX IF NOT EXISTS idx_secrets_tags ON secrets(tags);
`

// migration002 adds the metadata column for certificate/key metadata storage.
const migration002 = `
ALTER TABLE secrets ADD COLUMN metadata TEXT NOT NULL DEFAULT '';
`

// migration003 adds the audit_log table for tracking vault activity.
const migration003 = `
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    action TEXT NOT NULL,
    secret_name TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT ''
);
`

// migration004 adds the sync_conflicts table for sync conflict tracking.
// Sync config keys are stored in the existing config table — no schema changes needed.
const migration004 = `
CREATE TABLE IF NOT EXISTS sync_conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_name TEXT NOT NULL,
    conflict_time TEXT NOT NULL DEFAULT (datetime('now')),
    local_json TEXT NOT NULL,
    remote_json TEXT NOT NULL,
    resolution TEXT NOT NULL DEFAULT 'pending'
);
`

// migration006 adds the deleted_at column for soft-delete tombstones.
// Additive, nullable, no data migration required — v5 binaries reading a v6 DB
// ignore the unknown column harmlessly (rollback-safe).
// Stored as RFC3339 TEXT to match created_at/updated_at formatting.
const migration006 = `
ALTER TABLE secrets ADD COLUMN deleted_at TEXT DEFAULT NULL;
`

// migration005 supports issues S-01 and S-02:
//
//   - S-01: api_key and sync_encryption_key are now wrapped with the master
//     key. Re-wrapping happens lazily on first authenticated access; no SQL
//     change is required here.
//
//   - S-02: TOTP/HOTP seeds (the `secret=` parameter of otpauth:// URIs)
//     used to live in plaintext inside the `metadata` column. They now move
//     into a dedicated, master-key-encrypted column. The column is nullable
//     so unrelated secrets pay no cost, and so legacy rows remain readable
//     until migrated.
const migration005 = `
ALTER TABLE secrets ADD COLUMN encrypted_otp_seed BLOB DEFAULT NULL;
`

// migration007 is the v7 clean-break schema. It creates the full schema for
// new vaults with encrypted-metadata columns and a HMAC name_lookup UNIQUE BLOB.
// Legacy v1–v6 vaults are rejected in runMigrations; this SQL runs only for
// fresh vaults (schema_version == 0).
const migration007 = `
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    action TEXT NOT NULL,
    secret_name TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sync_conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_name TEXT NOT NULL,
    conflict_time TEXT NOT NULL DEFAULT (datetime('now')),
    local_json TEXT NOT NULL,
    remote_json TEXT NOT NULL,
    resolution TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    name_lookup BLOB NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'other',
    encrypted_value BLOB NOT NULL,
    encrypted_otp_seed BLOB DEFAULT NULL,
    encrypted_name BLOB NOT NULL,
    encrypted_notes BLOB NOT NULL DEFAULT X'',
    encrypted_tags BLOB NOT NULL DEFAULT X'',
    encrypted_metadata BLOB NOT NULL DEFAULT X'',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    deleted_at TEXT DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_secrets_name_lookup ON secrets(name_lookup);
`

// Store inserts a new secret. Returns ErrDuplicate if the name_lookup already exists.
func (s *SQLStore) Store(sec secret.Secret) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	if sec.ID == "" {
		id, err := newUUID()
		if err != nil {
			return fmt.Errorf("generate id: %w", err)
		}
		sec.ID = id
	}

	if sec.Kind == "" {
		sec.Kind = secret.KindOther
	}

	if sec.CreatedAt.IsZero() {
		sec.CreatedAt = time.Now().UTC()
	}
	if sec.UpdatedAt.IsZero() {
		sec.UpdatedAt = time.Now().UTC()
	}

	createdStr := sec.CreatedAt.Format(time.RFC3339)
	updatedStr := sec.UpdatedAt.Format(time.RFC3339)

	query := `INSERT INTO secrets (id, name_lookup, kind, encrypted_value, encrypted_otp_seed, encrypted_name, encrypted_notes, encrypted_tags, encrypted_metadata, created_at, updated_at, deleted_at)
	           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	           ON CONFLICT(name_lookup) DO UPDATE SET
	               id = excluded.id,
	               kind = excluded.kind,
	               encrypted_value = excluded.encrypted_value,
	               encrypted_otp_seed = excluded.encrypted_otp_seed,
	               encrypted_name = excluded.encrypted_name,
	               encrypted_notes = excluded.encrypted_notes,
	               encrypted_tags = excluded.encrypted_tags,
	               encrypted_metadata = excluded.encrypted_metadata,
	               created_at = excluded.created_at,
	               updated_at = excluded.updated_at,
	               deleted_at = excluded.deleted_at
	           WHERE secrets.deleted_at IS NOT NULL`

	// nullableBlob lets SQLite store NULL when no OTP seed is present, which
	// keeps the column cost negligible for non-OTP secrets.
	var otpBlob interface{}
	if len(sec.EncryptedOTPSeed) > 0 {
		otpBlob = sec.EncryptedOTPSeed
	} else {
		otpBlob = nil
	}

	// deletedAt is nil for live secrets; non-nil when inserting a tombstone
	// received from a remote peer during sync merge.
	var deletedAt interface{}
	if sec.DeletedAt != nil {
		deletedAt = sec.DeletedAt.UTC().Format(time.RFC3339)
	}

	encName := sec.EncryptedName
	if encName == nil {
		encName = []byte{}
	}
	encNotes := sec.EncryptedNotes
	if encNotes == nil {
		encNotes = []byte{}
	}
	encTags := sec.EncryptedTags
	if encTags == nil {
		encTags = []byte{}
	}
	encMeta := sec.EncryptedMetadata
	if encMeta == nil {
		encMeta = []byte{}
	}

	res, err := s.db.Exec(query, sec.ID, sec.NameLookup, string(sec.Kind), sec.EncryptedValue, otpBlob, encName, encNotes, encTags, encMeta, createdStr, updatedStr, deletedAt)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "UNIQUE") || strings.Contains(errStr, "unique") {
			return fmt.Errorf("%w: name_lookup", ErrDuplicate)
		}
		return fmt.Errorf("store secret: %w", err)
	}

	rows, err := res.RowsAffected()
	if err == nil && rows == 0 && sec.DeletedAt == nil {
		// A live (non-deleted) secret with the same name_lookup already exists
		return fmt.Errorf("%w: name_lookup", ErrDuplicate)
	}

	return nil
}

// GetByNameLookup retrieves a secret by its HMAC name_lookup BLOB.
// Returns ErrNotFound if the lookup does not exist.
func (s *SQLStore) GetByNameLookup(nameLookup []byte) (secret.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return secret.Secret{}, fmt.Errorf("store not initialized")
	}

	return s.getByLookup(nameLookup)
}

// GetByID retrieves a secret by ID. Returns ErrNotFound if not found.
func (s *SQLStore) GetByID(id string) (secret.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return secret.Secret{}, fmt.Errorf("store not initialized")
	}

	return s.getByID(id)
}

// getByLookup is the internal implementation for GetByNameLookup.
// Soft-deleted rows are excluded (WHERE deleted_at IS NULL).
func (s *SQLStore) getByLookup(nameLookup []byte) (secret.Secret, error) {
	query := `SELECT id, name_lookup, kind, encrypted_value, encrypted_otp_seed, encrypted_name, encrypted_notes, encrypted_tags, encrypted_metadata, created_at, updated_at
	          FROM secrets WHERE name_lookup = ? AND deleted_at IS NULL`

	var sec secret.Secret
	var kindStr, createdAtStr, updatedAtStr string
	var otpSeed []byte

	err := s.db.QueryRow(query, nameLookup).Scan(
		&sec.ID, &sec.NameLookup, &kindStr, &sec.EncryptedValue, &otpSeed,
		&sec.EncryptedName, &sec.EncryptedNotes, &sec.EncryptedTags, &sec.EncryptedMetadata, &createdAtStr, &updatedAtStr,
	)
	sec.EncryptedOTPSeed = otpSeed
	if err == sql.ErrNoRows {
		return secret.Secret{}, fmt.Errorf("%w: name_lookup", ErrNotFound)
	}
	if err != nil {
		return secret.Secret{}, fmt.Errorf("get by name_lookup: %w", err)
	}

	sec.Kind = secret.Kind(kindStr)
	sec.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("parse created_at: %w", err)
	}
	sec.UpdatedAt, err = time.Parse(time.RFC3339, updatedAtStr)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("parse updated_at: %w", err)
	}

	return sec, nil
}

// getByID is the internal implementation for GetByID.
// Soft-deleted rows are excluded (WHERE deleted_at IS NULL).
func (s *SQLStore) getByID(id string) (secret.Secret, error) {
	query := `SELECT id, name_lookup, kind, encrypted_value, encrypted_otp_seed, encrypted_name, encrypted_notes, encrypted_tags, encrypted_metadata, created_at, updated_at
	          FROM secrets WHERE id = ? AND deleted_at IS NULL`

	var sec secret.Secret
	var kindStr, createdAtStr, updatedAtStr string
	var otpSeed []byte

	err := s.db.QueryRow(query, id).Scan(
		&sec.ID, &sec.NameLookup, &kindStr, &sec.EncryptedValue, &otpSeed,
		&sec.EncryptedName, &sec.EncryptedNotes, &sec.EncryptedTags, &sec.EncryptedMetadata, &createdAtStr, &updatedAtStr,
	)
	sec.EncryptedOTPSeed = otpSeed
	if err == sql.ErrNoRows {
		return secret.Secret{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return secret.Secret{}, fmt.Errorf("get by id: %w", err)
	}

	sec.Kind = secret.Kind(kindStr)
	sec.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("parse created_at: %w", err)
	}
	sec.UpdatedAt, err = time.Parse(time.RFC3339, updatedAtStr)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("parse updated_at: %w", err)
	}

	return sec, nil
}

// scanFullSecrets scans rows with all columns including encrypted_value and deleted_at.
// Used by ListWithTombstones (tombstones included, full payload).
func scanFullSecrets(rows *sql.Rows) ([]secret.Secret, error) {
	var secrets []secret.Secret
	for rows.Next() {
		var sec secret.Secret
		var kindStr, createdAtStr, updatedAtStr string
		var otpSeed []byte
		var deletedAtStr sql.NullString

		if err := rows.Scan(
			&sec.ID, &sec.NameLookup, &kindStr, &sec.EncryptedValue, &otpSeed,
			&sec.EncryptedName, &sec.EncryptedNotes, &sec.EncryptedTags, &sec.EncryptedMetadata,
			&createdAtStr, &updatedAtStr, &deletedAtStr,
		); err != nil {
			return nil, fmt.Errorf("scan full secret: %w", err)
		}
		sec.EncryptedOTPSeed = otpSeed
		sec.Kind = secret.Kind(kindStr)

		var err error
		sec.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
		if err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		sec.UpdatedAt, err = time.Parse(time.RFC3339, updatedAtStr)
		if err != nil {
			return nil, fmt.Errorf("parse updated_at: %w", err)
		}
		if deletedAtStr.Valid && deletedAtStr.String != "" {
			t, err := time.Parse(time.RFC3339, deletedAtStr.String)
			if err != nil {
				return nil, fmt.Errorf("parse deleted_at: %w", err)
			}
			sec.DeletedAt = &t
		}
		secrets = append(secrets, sec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	if secrets == nil {
		secrets = []secret.Secret{}
	}
	return secrets, nil
}

// List returns all live secrets with encrypted metadata only
// (EncryptedValue is nil). Soft-deleted rows are excluded.
func (s *SQLStore) List() ([]secret.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	query := `SELECT id, name_lookup, kind, encrypted_name, encrypted_notes, encrypted_tags, encrypted_metadata, created_at, updated_at
	          FROM secrets WHERE deleted_at IS NULL ORDER BY name_lookup`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanMetadata(rows)
}

// ListWithEncryptedAll returns all live secrets with full encrypted values.
// Soft-deleted rows are excluded.
func (s *SQLStore) ListWithEncryptedAll() ([]secret.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	query := `SELECT id, name_lookup, kind, encrypted_value, encrypted_otp_seed, encrypted_name, encrypted_notes, encrypted_tags, encrypted_metadata, created_at, updated_at, deleted_at
	          FROM secrets WHERE deleted_at IS NULL ORDER BY name_lookup`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("list with encrypted all: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanFullSecrets(rows)
}

// scanMetadata scans rows into Secret structs with encrypted metadata only
// (no encrypted_value).
func scanMetadata(rows *sql.Rows) ([]secret.Secret, error) {
	var secrets []secret.Secret
	for rows.Next() {
		var sec secret.Secret
		var kindStr, createdAtStr, updatedAtStr string
		if err := rows.Scan(&sec.ID, &sec.NameLookup, &kindStr, &sec.EncryptedName, &sec.EncryptedNotes, &sec.EncryptedTags, &sec.EncryptedMetadata, &createdAtStr, &updatedAtStr); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		sec.Kind = secret.Kind(kindStr)
		sec.EncryptedValue = nil // explicitly nil — metadata only
		var err error
		sec.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
		if err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		sec.UpdatedAt, err = time.Parse(time.RFC3339, updatedAtStr)
		if err != nil {
			return nil, fmt.Errorf("parse updated_at: %w", err)
		}
		secrets = append(secrets, sec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	if secrets == nil {
		secrets = []secret.Secret{} // return empty slice, not nil
	}
	return secrets, nil
}

// DeleteByLookup removes a live secret by its name_lookup BLOB.
// Returns ErrNotFound if the lookup does not exist.
func (s *SQLStore) DeleteByLookup(nameLookup []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	result, err := s.db.Exec("DELETE FROM secrets WHERE name_lookup = ?", nameLookup)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("%w: name_lookup", ErrNotFound)
	}

	return nil
}

// SoftDeleteByLookup marks a secret as deleted by its name_lookup BLOB.
// Returns ErrNotFound if the lookup does not exist or is already deleted.
func (s *SQLStore) SoftDeleteByLookup(nameLookup []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.Exec(
		"UPDATE secrets SET deleted_at = ?, updated_at = ? WHERE name_lookup = ? AND deleted_at IS NULL",
		now, now, nameLookup,
	)
	if err != nil {
		return fmt.Errorf("soft delete secret: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: name_lookup", ErrNotFound)
	}
	return nil
}

// UpdateTombstoneDeletedAt advances the deleted_at timestamp of a tombstone to
// the given time. The nameLookup identifies the tombstone.
// Returns ErrNotFound if the secret does not exist or is not a tombstone.
func (s *SQLStore) UpdateTombstoneDeletedAt(nameLookup []byte, deletedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	deletedAtStr := deletedAt.UTC().Format(time.RFC3339)
	result, err := s.db.Exec(
		"UPDATE secrets SET deleted_at = ?, updated_at = ? WHERE name_lookup = ? AND deleted_at IS NOT NULL",
		deletedAtStr, deletedAtStr, nameLookup,
	)
	if err != nil {
		return fmt.Errorf("update tombstone deleted_at: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: name_lookup", ErrNotFound)
	}
	return nil
}

// ListWithTombstones returns all secrets including soft-deleted ones, with
// full encrypted values. Used only by the sync layer for snapshot push/merge.
func (s *SQLStore) ListWithTombstones() ([]secret.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	query := `SELECT id, name_lookup, kind, encrypted_value, encrypted_otp_seed, encrypted_name, encrypted_notes, encrypted_tags, encrypted_metadata, created_at, updated_at, deleted_at
	          FROM secrets ORDER BY name_lookup`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("list with tombstones: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanFullSecrets(rows)
}

// PurgeTombstones hard-deletes tombstones with deleted_at < before.
// Returns the number of rows deleted.
func (s *SQLStore) PurgeTombstones(before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return 0, fmt.Errorf("store not initialized")
	}

	beforeStr := before.UTC().Format(time.RFC3339)
	result, err := s.db.Exec(
		"DELETE FROM secrets WHERE deleted_at IS NOT NULL AND deleted_at < ?",
		beforeStr,
	)
	if err != nil {
		return 0, fmt.Errorf("purge tombstones: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return int(n), nil
}

// UpdateOTPSeedAndMetadata atomically updates the encrypted_otp_seed and
// encrypted_metadata columns of an existing secret in a single statement,
// preserving the encrypted value.
// Returns ErrNotFound if the name_lookup does not exist.
func (s *SQLStore) UpdateOTPSeedAndMetadata(nameLookup []byte, encryptedOTPSeed []byte, encryptedMetadata []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	result, err := s.db.Exec(
		"UPDATE secrets SET encrypted_otp_seed = ?, encrypted_metadata = ?, updated_at = ? WHERE name_lookup = ?",
		encryptedOTPSeed, encryptedMetadata, time.Now().UTC().Format(time.RFC3339), nameLookup,
	)
	if err != nil {
		return fmt.Errorf("update otp seed: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: name_lookup", ErrNotFound)
	}
	return nil
}

// Count returns the number of live secrets in the vault.
func (s *SQLStore) Count() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return 0, fmt.Errorf("store not initialized")
	}

	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM secrets WHERE deleted_at IS NULL").Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count secrets: %w", err)
	}
	return n, nil
}

// ConfigGet retrieves a value from the config table by key.
// Returns ErrNotFound if the key does not exist.
func (s *SQLStore) ConfigGet(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	var value []byte
	err := s.db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: config key %q", ErrNotFound, key)
	}
	if err != nil {
		return nil, fmt.Errorf("config get %q: %w", key, err)
	}
	return value, nil
}

// ConfigSet stores a value in the config table.
// If the key already exists, it is overwritten.
func (s *SQLStore) ConfigSet(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	_, err := s.db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, value)
	if err != nil {
		return fmt.Errorf("config set %q: %w", key, err)
	}
	return nil
}

// ConfigDelete removes a value from the config table by key.
func (s *SQLStore) ConfigDelete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	_, err := s.db.Exec("DELETE FROM config WHERE key = ?", key)
	if err != nil {
		return fmt.Errorf("config delete %q: %w", key, err)
	}
	return nil
}

// maxAuditEntries is the maximum number of audit log entries to keep.
const maxAuditEntries = 1000

const sqliteTimeFormat = "2006-01-02 15:04:05"

// LogAction records an audit log entry and auto-prunes to keep at most 1000 entries.
func (s *SQLStore) LogAction(action, secretName, details string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return fmt.Errorf("store not initialized")
	}

	_, err := s.db.Exec("INSERT INTO audit_log (action, secret_name, details) VALUES (?, ?, ?)",
		action, secretName, details)
	if err != nil {
		return fmt.Errorf("log action: %w", err)
	}

	// Auto-prune: keep only the last maxAuditEntries
	_, err = s.db.Exec(`DELETE FROM audit_log WHERE id NOT IN (
		SELECT id FROM audit_log ORDER BY id DESC LIMIT ?
	)`, maxAuditEntries)
	if err != nil {
		return fmt.Errorf("prune audit log: %w", err)
	}

	return nil
}

// GetAuditLog returns the most recent audit log entries.
func (s *SQLStore) GetAuditLog(limit int) ([]secret.AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	if limit <= 0 {
		limit = 50
	}

	rows, err := s.db.Query(`SELECT id, timestamp, action, secret_name, details
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []secret.AuditEntry
	for rows.Next() {
		var e secret.AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Action, &e.SecretName, &e.Details); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		e.Timestamp, err = time.Parse(sqliteTimeFormat, ts)
		if err != nil {
			return nil, fmt.Errorf("parse audit timestamp: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	if entries == nil {
		entries = []secret.AuditEntry{}
	}
	return entries, nil
}

// Close closes the database connection.
func (s *SQLStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db != nil {
		err := s.db.Close()
		s.db = nil
		return err
	}
	return nil
}

// newUUID generates a v4 UUID using crypto/rand.
func newUUID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("rand read: %w", err)
	}

	// Set version 4 bits
	buf[6] = (buf[6] & 0x0f) | 0x40
	// Set variant bits (10xx)
	buf[8] = (buf[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16]), nil
}
