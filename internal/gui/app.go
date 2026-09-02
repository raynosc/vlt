// Package gui provides the backend application logic for the vlt GUI.
//
// It wraps existing internal packages (store, crypto, config, keychain, otp)
// into a clean interface for the GUI layer. This package has ZERO GUI framework
// dependencies — it is pure Go business logic that any GUI framework can use.
package gui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/notify"
	"github.com/raynosc/vlt/internal/otp"
	"github.com/raynosc/vlt/internal/parse"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
	syncpkg "github.com/raynosc/vlt/internal/sync"
	"github.com/raynosc/vlt/internal/version"
	"github.com/raynosc/vlt/internal/watchtower"
)

// Version is the GUI app version.
const Version = version.Version

// App provides all vault operations for the GUI.
// It wraps the existing internal packages and manages the derived key lifecycle.
// All public methods are safe for concurrent use.
type App struct {
	mu         sync.RWMutex
	store      *store.SQLStore
	engine     *crypto.Engine
	salt       []byte
	verify     []byte
	key        []byte // derived key; nil when locked
	cfg        *config.Config
	vault      string // vault name for display
	ready      bool   // true after successful initialization
	syncCancel context.CancelFunc
	onActivity func()
}

// SetOnActivity sets a callback invoked whenever user activity or vault operations occur.
func (a *App) SetOnActivity(fn func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onActivity = fn
}

// RecordActivity notifies the registered activity callback (if any) to reset inactivity timers.
func (a *App) RecordActivity() {
	a.mu.RLock()
	fn := a.onActivity
	a.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

// NewApp loads configuration, discovers the vault, and initializes the store.
// It does NOT derive the key — the vault starts locked.
//
// Parameters:
//   - vaultName: optional named vault (empty = default)
//   - noKeychain: if true, skip macOS Keychain auto-unlock
func NewApp(vaultName string, noKeychain bool) (*App, error) {
	a := &App{
		engine: crypto.NewEngine(nil),
	}

	// Load config
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	a.cfg = cfg

	// Resolve vault path
	var vaultPath string
	if vaultName != "" {
		a.vault = vaultName
		vaultPath, err = config.VaultPathForName(vaultName)
		if err != nil {
			return nil, fmt.Errorf("vault path for %q: %w", vaultName, err)
		}
	} else if cfg.ActiveVault != "" {
		a.vault = cfg.ActiveVault
		vaultPath, err = config.VaultPathForName(cfg.ActiveVault)
		if err != nil {
			return nil, fmt.Errorf("active vault path: %w", err)
		}
	} else {
		vaultPath = cfg.VaultPath
		a.vault = config.VaultNameFromPath(vaultPath)
		if a.vault == "" {
			a.vault = "default"
		}
	}

	// Verify vault exists, or fall back to any available vault
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		vaults, listErr := config.ListVaults()
		if listErr == nil && len(vaults) > 0 {
			vaultPath = vaults[0].Path
			a.vault = vaults[0].Name
			cfg.ActiveVault = vaults[0].Name
			cfg.VaultPath = vaults[0].Path
			_ = cfg.Save()
		} else {
			return nil, fmt.Errorf("vault not found at %s\nRun 'vlt init' to create a new vault", vaultPath)
		}
	}

	// Open store
	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}
	a.store = st

	// Read salt and verify hash
	salt, err := st.ConfigGet("salt")
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("vault not initialized (missing salt): %w", err)
	}
	a.salt = salt

	verifyHash, err := st.ConfigGet("verify_hash")
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("vault not initialized (missing verify_hash): %w", err)
	}
	a.verify = verifyHash

	a.ready = true
	return a, nil
}

// VaultName returns the display name of the active vault.
func (a *App) VaultName() string {
	return a.vault
}

// IsUnlocked returns true if the vault key is currently in memory.
func (a *App) IsUnlocked() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.key != nil
}

// readArgon2Params reads stored Argon2 parameters from the store config.
// If any key is missing, it falls back to DefaultArgon2Params.
func readArgon2Params(st *store.SQLStore) *crypto.Argon2Params {
	params := crypto.DefaultArgon2Params

	if timeBytes, err := st.ConfigGet("argon2_time"); err == nil && len(timeBytes) == 4 {
		params.Time = binary.BigEndian.Uint32(timeBytes)
	}
	if memoryBytes, err := st.ConfigGet("argon2_memory"); err == nil && len(memoryBytes) == 4 {
		params.Memory = binary.BigEndian.Uint32(memoryBytes)
	}
	if threadsBytes, err := st.ConfigGet("argon2_threads"); err == nil && len(threadsBytes) == 1 {
		params.Threads = threadsBytes[0]
	}

	return &params
}

// Unlock derives the vault key from the master password and keeps it in memory.
func (a *App) Unlock(password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.key != nil {
		return fmt.Errorf("vault is already unlocked")
	}

	if password == "" {
		return fmt.Errorf("password must not be empty")
	}

	// Check Circuit Breaker
	if cb, err := a.store.GetCircuitBreakerState(); err == nil {
		if cb.IsHardLockout {
			return fmt.Errorf("vault is hard locked: use recovery kit to rescue")
		}
		if cb.IsPINChallenge {
			return fmt.Errorf("circuit breaker engaged: 3 failed attempts (PIN verification required)")
		}
	}

	// Read stored Argon2 params and create engine with them
	params := readArgon2Params(a.store)
	eng := crypto.NewEngine(params)

	if !eng.VerifyMasterPassword([]byte(password), a.salt, a.verify) {
		if newCb, _ := a.store.RecordFailedMasterAttempt(); newCb != nil && newCb.IsPINChallenge {
			return fmt.Errorf("3 failed attempts: circuit breaker engaged (PIN verification required)")
		}
		return fmt.Errorf("invalid master password")
	}

	key, err := eng.DeriveKey([]byte(password), a.salt)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	a.key = key

	// Clear attempts on success
	_ = a.store.ResetMasterAttempts()

	// Persist active vault so the app remembers the most recently unlocked vault on next launch
	if cfg, err := config.Load(); err == nil {
		if cfg.ActiveVault != a.vault {
			_ = cfg.SetActiveVault(a.vault)
		}
	}

	return nil
}

// GetCircuitBreakerState returns the current circuit breaker state.
func (a *App) GetCircuitBreakerState() (*store.CircuitBreakerState, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.store.GetCircuitBreakerState()
}

// VerifyPIN verifies the 8-digit PIN to unfreeze the master password prompt.
func (a *App) VerifyPIN(pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	params := readArgon2Params(a.store)
	eng := crypto.NewEngine(params)

	pinHash, pinSalt, err := a.store.GetPINConfig()
	if err != nil || !eng.VerifyPIN(pin, pinSalt, pinHash) {
		newCb, _ := a.store.RecordFailedPINAttempt()
		if newCb != nil && newCb.IsHardLockout {
			return fmt.Errorf("3 failed PIN attempts: hard lockout engaged (use recovery kit to rescue)")
		}
		remaining := 3
		if newCb != nil {
			remaining = 3 - newCb.PINFailedAttempts
		}
		return fmt.Errorf("invalid PIN: %d attempts remaining before hard lockout", remaining)
	}

	// Correct PIN: reset master attempts
	_ = a.store.ResetMasterAttempts()
	return nil
}

// RescueWithRecoveryKey rescues a hard-locked vault using the 36-word phrase.
func (a *App) RescueWithRecoveryKey(phrase string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	blob, err := a.store.ConfigGet(store.ConfigKeyRecoveryBlob)
	if err != nil || len(blob) == 0 {
		return fmt.Errorf("no recovery blob found in vault")
	}

	params := readArgon2Params(a.store)
	eng := crypto.NewEngine(params)

	valid, err := eng.VerifyRecoveryKit(phrase, blob, a.salt, a.verify)
	if err != nil || !valid {
		return fmt.Errorf("invalid recovery phrase")
	}

	return a.store.ResetCircuitBreaker()
}

// SetPIN configures or updates the 8-digit PIN for the vault.
func (a *App) SetPIN(pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.key == nil {
		return fmt.Errorf("vault must be unlocked to set PIN")
	}

	if err := crypto.ValidatePINFormat(pin); err != nil {
		return err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	params := readArgon2Params(a.store)
	eng := crypto.NewEngine(params)

	hash, err := eng.HashPIN(pin, salt)
	if err != nil {
		return fmt.Errorf("hash PIN: %w", err)
	}
	defer crypto.Zeroize(hash)

	return a.store.SetPIN(hash, salt)
}

// HasPIN returns true if a lockout PIN is configured for the vault.
func (a *App) HasPIN() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	cb, err := a.store.GetCircuitBreakerState()
	return err == nil && cb.HasPIN
}

// GenerateRecoveryKit generates a fresh 36-word recovery phrase and persists the recovery blob.
// Requires the vault to be currently unlocked.
func (a *App) GenerateRecoveryKit() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.key == nil {
		return "", fmt.Errorf("vault must be unlocked to generate recovery kit")
	}

	params := readArgon2Params(a.store)
	eng := crypto.NewEngine(params)

	mnemonic, blob, err := eng.GenerateRecoveryKit(a.key)
	if err != nil {
		return "", fmt.Errorf("generate recovery kit: %w", err)
	}

	if err := a.store.ConfigSet(store.ConfigKeyRecoveryBlob, blob); err != nil {
		return "", fmt.Errorf("persist recovery blob: %w", err)
	}

	return mnemonic, nil
}

// RemovePIN removes the PIN from the vault.
func (a *App) RemovePIN() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.key == nil {
		return fmt.Errorf("vault must be unlocked to remove PIN")
	}

	return a.store.RemovePIN()
}

// Lock zeroizes the derived key and locks the vault.
func (a *App) Lock() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.syncCancel != nil {
		a.syncCancel()
		a.syncCancel = nil
	}

	if a.key == nil {
		return
	}

	crypto.Zeroize(a.key)
	a.key = nil
}

// Close releases all resources (store, key).
func (a *App) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.syncCancel != nil {
		a.syncCancel()
		a.syncCancel = nil
	}

	a.ready = false
	if a.key != nil {
		crypto.Zeroize(a.key)
		a.key = nil
	}
	if a.store != nil {
		_ = a.store.Close()
	}
}

// StartAutoSync starts a background listener for real-time vault updates if sync is configured.
func (a *App) StartAutoSync(onSync func(seq int64)) {
	a.mu.Lock()
	if a.syncCancel != nil {
		a.syncCancel()
		a.syncCancel = nil
	}

	key := make([]byte, len(a.key))
	copy(key, a.key)
	st := a.store
	if len(key) != 32 || st == nil {
		a.mu.Unlock()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.syncCancel = cancel
	a.mu.Unlock()

	// Try creating sync client
	client, err := syncpkg.NewClientInsecure(st, key)
	if err != nil {
		return
	}

	go client.WatchAndSync(ctx, func(seq int64, syncErr error) {
		if syncErr == nil {
			_ = notify.Send("vlt", "Bóveda sincronizada", fmt.Sprintf("Cambios remotos aplicados (secuencia %d)", seq))
			if onSync != nil {
				onSync(seq)
			}
		}
	})
}

// List returns all live secrets with decrypted metadata (no values).
func (a *App) List() ([]secret.Secret, error) {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	store := a.store
	a.mu.RUnlock()

	if key == nil {
		return nil, fmt.Errorf("vault is locked")
	}

	secrets, err := store.List()
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	for i := range secrets {
		if err := a.decryptSecretMetadata(&secrets[i], key); err != nil {
			return nil, fmt.Errorf("decrypt metadata: %w", err)
		}
	}

	// Re-sort by plaintext name since store returns HMAC-sorted.
	sort.Slice(secrets, func(i, j int) bool {
		return strings.ToLower(secrets[i].Name) < strings.ToLower(secrets[j].Name)
	})

	return secrets, nil
}

// Search returns secrets whose decrypted metadata contains the query.
// An empty query returns all secrets.
func (a *App) Search(query string) ([]secret.Secret, error) {
	all, err := a.List()
	if err != nil {
		return nil, err
	}

	if query == "" {
		return all, nil
	}

	query = strings.ToLower(query)
	var results []secret.Secret
	for _, sec := range all {
		if strings.Contains(strings.ToLower(sec.Name), query) ||
			strings.Contains(strings.ToLower(sec.Notes), query) ||
			strings.Contains(strings.ToLower(sec.Tags), query) ||
			strings.Contains(strings.ToLower(sec.Metadata), query) {
			results = append(results, sec)
		}
	}
	return results, nil
}

// GetSecret retrieves a secret by name and decrypts its value.
// Returns the secret and the decrypted plaintext value.
// The caller MUST NOT store the plaintext — it should be zeroized after use.
func (a *App) GetSecret(name string) (*secret.Secret, string, error) {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	store := a.store
	engine := a.engine
	a.mu.RUnlock()

	if key == nil {
		return nil, "", fmt.Errorf("vault is locked")
	}

	lookup := crypto.ComputeNameLookup(key, name)
	sec, err := store.GetByNameLookup(lookup)
	if err != nil {
		return nil, "", fmt.Errorf("get secret: %w", err)
	}

	if err := a.decryptSecretMetadata(&sec, key); err != nil {
		return nil, "", fmt.Errorf("decrypt metadata: %w", err)
	}

	if len(sec.EncryptedValue) == 0 {
		return &sec, "", nil
	}

	nonce, ciphertext, err := unpackEnvelope(sec.EncryptedValue)
	if err != nil {
		return nil, "", fmt.Errorf("unpack envelope: %w", err)
	}

	plaintext, err := engine.Decrypt(ciphertext, key, nonce)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt: %w", err)
	}

	return &sec, string(plaintext), nil
}

// GetByName retrieves a secret by name with decrypted metadata (no value).
func (a *App) GetByName(name string) (secret.Secret, error) {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	store := a.store
	a.mu.RUnlock()

	if key == nil {
		return secret.Secret{}, fmt.Errorf("vault is locked")
	}

	lookup := crypto.ComputeNameLookup(key, name)
	sec, err := store.GetByNameLookup(lookup)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("get secret: %w", err)
	}

	if err := a.decryptSecretMetadata(&sec, key); err != nil {
		return secret.Secret{}, fmt.Errorf("decrypt metadata: %w", err)
	}

	return sec, nil
}

// AddSecret encrypts and stores a new secret.
func (a *App) AddSecret(name, kind, value, notes, tags string) error {
	return a.AddSecretFull(name, kind, value, notes, tags, "", "")
}

// AddSecretFull encrypts and stores a new secret with full metadata and optional OTP seed atomically.
func (a *App) AddSecretFull(name, kind, value, notes, tags, metadata, otpSeed string) error {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	store := a.store
	engine := a.engine
	a.mu.RUnlock()

	if key == nil {
		return fmt.Errorf("vault is locked")
	}
	if name == "" {
		return fmt.Errorf("name must not be empty")
	}
	if value == "" {
		return fmt.Errorf("value must not be empty")
	}

	secKind := secret.Kind(kind)
	if kind == "" || !secret.IsValidKind(kind) {
		secKind = secret.KindPassword
	}

	ciphertext, nonce, err := engine.Encrypt([]byte(value), key)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	blob := packEnvelope(nonce, ciphertext)
	s := secret.NewSecret("", name, secKind, blob, notes, tags)
	s.Metadata = metadata

	if otpSeed != "" {
		otpCipher, otpNonce, err := engine.Encrypt([]byte(otpSeed), key)
		if err != nil {
			return fmt.Errorf("encrypt otp seed: %w", err)
		}
		s.EncryptedOTPSeed = packEnvelope(otpNonce, otpCipher)
	}

	s, err = a.encryptSecretMetadata(s, key)
	if err != nil {
		return fmt.Errorf("encrypt metadata: %w", err)
	}

	if err := store.Store(s); err != nil {
		return fmt.Errorf("store secret: %w", err)
	}

	return nil
}

// EditSecret replaces a secret's encrypted value, notes, and tags while preserving metadata.
func (a *App) EditSecret(name, kind, value, notes, tags string) error {
	a.mu.RLock()
	key := a.key
	store := a.store
	a.mu.RUnlock()

	if key == nil {
		return fmt.Errorf("vault is locked")
	}
	lookup := crypto.ComputeNameLookup(key, name)
	existing, err := store.GetByNameLookup(lookup)
	if err != nil {
		return fmt.Errorf("get existing: %w", err)
	}
	if err := a.decryptSecretMetadata(&existing, key); err != nil {
		return fmt.Errorf("decrypt metadata: %w", err)
	}

	return a.EditSecretFull(name, name, kind, value, notes, tags, existing.Metadata, "")
}

// EditSecretFull updates an existing secret with full metadata and optional new OTP seed atomically,
// supporting renaming from oldName to newName.
func (a *App) EditSecretFull(oldName, newName, kind, value, notes, tags, metadata, newOTPSeed string) error {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	store := a.store
	engine := a.engine
	a.mu.RUnlock()

	if key == nil {
		return fmt.Errorf("vault is locked")
	}
	if oldName == "" {
		return fmt.Errorf("old name must not be empty")
	}
	if newName == "" {
		newName = oldName
	}

	secKind := secret.Kind(kind)
	if kind == "" || !secret.IsValidKind(kind) {
		secKind = secret.KindPassword
	}

	// Get existing secret to preserve created_at and existing OTP seed
	oldLookup := crypto.ComputeNameLookup(key, oldName)
	existing, err := store.GetByNameLookup(oldLookup)
	if err != nil {
		return fmt.Errorf("get existing: %w", err)
	}

	// If renaming to a different name, ensure newName does not already exist
	newLookup := crypto.ComputeNameLookup(key, newName)
	if newName != oldName {
		if _, err := store.GetByNameLookup(newLookup); err == nil {
			return fmt.Errorf("secret with name %q already exists", newName)
		}
	}

	// Hard delete old record to replace without creating a tombstone
	if err := store.DeleteByLookup(oldLookup); err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	ciphertext, nonce, err := engine.Encrypt([]byte(value), key)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	blob := packEnvelope(nonce, ciphertext)
	s := secret.NewSecret(existing.ID, newName, secKind, blob, notes, tags)
	s.CreatedAt = existing.CreatedAt
	// Best effort check for HIBP Pwned cache on save
	if secKind == secret.KindPassword && value != "" {
		metaObj := secret.UnmarshalPasswordMetadata(metadata)
		if metaObj == nil {
			metaObj = &secret.PasswordMetadata{}
		}
		pwnedMgr := watchtower.NewPwnedManager(watchtower.DefaultPwnedCooldown)
		if pwnedMgr.ShouldAttempt() {
			if count, err := pwnedMgr.CheckBatch([]string{value}); err == nil {
				now := time.Now().UTC()
				metaObj.PwnedCount = count[value]
				metaObj.LastAudited = &now
				metadata = secret.MarshalPasswordMetadata(metaObj)
			}
		}
	}

	s.Metadata = metadata
	s.EncryptedOTPSeed = existing.EncryptedOTPSeed

	if newOTPSeed != "" {
		otpCipher, otpNonce, err := engine.Encrypt([]byte(newOTPSeed), key)
		if err != nil {
			return fmt.Errorf("encrypt otp seed: %w", err)
		}
		s.EncryptedOTPSeed = packEnvelope(otpNonce, otpCipher)
	}

	s, err = a.encryptSecretMetadata(s, key)
	if err != nil {
		return fmt.Errorf("encrypt metadata: %w", err)
	}

	if err := store.Store(s); err != nil {
		return fmt.Errorf("store: %w", err)
	}

	return nil
}

// SaveOTPSeed encrypts an OTP seed (the base32 `secret=` value of an
// otpauth:// URI) with the master key and stores it in the secret's
// encrypted_otp_seed column.
//
// S-02: the seed must never be persisted in the plaintext metadata column.
// Callers that present an otpauth:// URI in the UI should pass only the
// `secret=` portion to this method and let MarshalPasswordMetadata redact
// the URI itself.
func (a *App) SaveOTPSeed(name, seedBase32 string) error {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	st := a.store
	engine := a.engine
	a.mu.RUnlock()

	if key == nil {
		return fmt.Errorf("vault is locked")
	}
	if name == "" {
		return fmt.Errorf("name must not be empty")
	}
	if seedBase32 == "" {
		return fmt.Errorf("seed must not be empty")
	}

	lookup := crypto.ComputeNameLookup(key, name)
	sec, err := st.GetByNameLookup(lookup)
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}

	ciphertext, nonce, err := engine.Encrypt([]byte(seedBase32), key)
	if err != nil {
		return fmt.Errorf("encrypt otp seed: %w", err)
	}
	sec.EncryptedOTPSeed = packEnvelope(nonce, ciphertext)

	// hard Delete: internal replace, not user deletion
	if err := st.DeleteByLookup(lookup); err != nil {
		return fmt.Errorf("delete before re-store: %w", err)
	}
	if err := st.Store(sec); err != nil {
		return fmt.Errorf("re-store with otp seed: %w", err)
	}
	return nil
}

// LoadOTPSeed decrypts the encrypted_otp_seed of a secret, if any.
// Returns ("", nil) when the secret has no OTP seed.
// The plaintext is up to the caller to zeroize.
func (a *App) LoadOTPSeed(name string) (string, error) {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	st := a.store
	engine := a.engine
	a.mu.RUnlock()

	if key == nil {
		return "", fmt.Errorf("vault is locked")
	}

	lookup := crypto.ComputeNameLookup(key, name)
	sec, err := st.GetByNameLookup(lookup)
	if err != nil {
		return "", fmt.Errorf("get secret: %w", err)
	}
	if len(sec.EncryptedOTPSeed) == 0 {
		return "", nil
	}

	nonce, ciphertext, err := unpackEnvelope(sec.EncryptedOTPSeed)
	if err != nil {
		return "", fmt.Errorf("unpack otp envelope: %w", err)
	}
	plaintext, err := engine.Decrypt(ciphertext, key, nonce)
	if err != nil {
		return "", fmt.Errorf("decrypt otp seed: %w", err)
	}
	return string(plaintext), nil
}

// DeleteSecret removes a secret by name.
func (a *App) DeleteSecret(name string) error {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	store := a.store
	a.mu.RUnlock()

	if key == nil {
		return fmt.Errorf("vault is locked")
	}

	lookup := crypto.ComputeNameLookup(key, name)
	if err := store.SoftDeleteByLookup(lookup); err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}

	return nil
}

// GeneratePassword generates a cryptographically secure random password.
func (a *App) GeneratePassword(length int) (string, error) {
	defer a.RecordActivity()
	if length <= 0 {
		length = 24
	}
	if length > 128 {
		length = 128
	}

	pw := make([]byte, length)
	for i := range pw {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(crypto.DefaultPasswordCharset))))
		if err != nil {
			return "", fmt.Errorf("rand.Int: %w", err)
		}
		pw[i] = crypto.DefaultPasswordCharset[idx.Int64()]
	}

	return string(pw), nil
}

// GetTOTP generates a TOTP code for a secret that has an OTP auth URL in its metadata.
// Returns the current code and the seconds remaining until it changes.
func (a *App) GetTOTP(name string) (code string, remaining int, err error) {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	store := a.store
	engine := a.engine
	a.mu.RUnlock()

	if key == nil {
		return "", 0, fmt.Errorf("vault is locked")
	}

	lookup := crypto.ComputeNameLookup(key, name)
	sec, err := store.GetByNameLookup(lookup)
	if err != nil {
		return "", 0, fmt.Errorf("get secret: %w", err)
	}
	if err := a.decryptSecretMetadata(&sec, key); err != nil {
		return "", 0, fmt.Errorf("decrypt metadata: %w", err)
	}

	// Get value for TOTP secret parsing
	if len(sec.EncryptedValue) == 0 {
		return "", 0, fmt.Errorf("secret has no value")
	}

	nonce, ciphertext, err := unpackEnvelope(sec.EncryptedValue)
	if err != nil {
		return "", 0, fmt.Errorf("unpack envelope: %w", err)
	}

	plaintext, err := engine.Decrypt(ciphertext, key, nonce)
	if err != nil {
		return "", 0, fmt.Errorf("decrypt: %w", err)
	}
	defer crypto.Zeroize(plaintext)

	// Try to parse the value as an otpauth URL
	val := string(plaintext)
	var otpSecret string

	// S-02: prefer the new encrypted_otp_seed column when present.
	if len(sec.EncryptedOTPSeed) > 0 {
		nonceOTP, ctOTP, uerr := unpackEnvelope(sec.EncryptedOTPSeed)
		if uerr == nil {
			if seedBytes, derr := engine.Decrypt(ctOTP, key, nonceOTP); derr == nil {
				otpSecret = string(seedBytes)
				defer crypto.Zeroize(seedBytes)
			}
		}
	}

	// Backward compatibility: legacy vaults stored the full URL in metadata.
	// Only fall through to this when the metadata URL is NOT redacted.
	if otpSecret == "" && sec.Metadata != "" {
		meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
		if meta != nil && meta.OTPAuth != "" {
			extracted := extractSecretFromOTPURL(meta.OTPAuth)
			if extracted != "" && extracted != secret.OTPAuthRedactedMarker {
				otpSecret = extracted
			}
		}
	}

	// If OTP auth URL found, use it; otherwise try the value itself as the secret
	if otpSecret == "" {
		otpSecret = val
	}

	code, err = otp.GenerateTOTP(otpSecret, time.Now(), 6, "SHA1")
	if err != nil {
		return "", 0, fmt.Errorf("generate totp: %w", err)
	}

	remaining = int(30 - (time.Now().Unix() % 30))
	return code, remaining, nil
}

// Config returns the current config.
func (a *App) Config() *config.Config {
	return a.cfg
}

// SyncServerURL returns the configured sync server URL for the current vault, if any.
func (a *App) SyncServerURL() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.store == nil {
		return ""
	}
	urlBytes, err := a.store.ConfigGet("sync_server_url")
	if err != nil || len(urlBytes) == 0 {
		return ""
	}
	return string(urlBytes)
}

// ConfigureSync registers and sets up sync with the given server URL.
func (a *App) ConfigureSync(serverURL string) error {
	a.mu.RLock()
	key := make([]byte, len(a.key))
	copy(key, a.key)
	st := a.store
	a.mu.RUnlock()

	if len(key) != 32 || st == nil {
		return fmt.Errorf("vault must be unlocked to configure sync")
	}

	serverURL = strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if serverURL == "" {
		return fmt.Errorf("server URL cannot be empty")
	}

	// Register or link with sync server
	client, err := syncpkg.InitVaultInsecure(st, key, serverURL)
	if err != nil {
		return fmt.Errorf("sync init failed: %w", err)
	}

	// Perform initial pull and push
	_, _ = client.Pull()
	_, _ = client.Push()

	return nil
}

// UnlinkSync removes sync configuration from the current vault.
func (a *App) UnlinkSync() error {
	a.mu.Lock()
	if a.syncCancel != nil {
		a.syncCancel()
		a.syncCancel = nil
	}
	st := a.store
	a.mu.Unlock()

	if st == nil {
		return fmt.Errorf("vault store unavailable")
	}

	_ = st.ConfigDelete("sync_server_url")
	_ = st.ConfigDelete("sync_vault_uuid")
	_ = st.ConfigDelete("sync_encryption_key")
	_ = st.ConfigDelete("sync_key_hash")
	_ = st.ConfigDelete("sync_sequence")
	return nil
}

// Store returns the underlying store (for advanced operations).
func (a *App) Store() *store.SQLStore {
	return a.store
}

// CreateVault creates a new vault with the given name and master password.
// It initializes the SQLite file, stores salt/verify_hash/argon2 params,
// generates a recovery kit, sets the vault as active, and saves the key
// to the keychain. Returns the recovery kit mnemonic.
func (a *App) CreateVault(name string, password string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("vault name must not be empty")
	}

	vaultPath, err := config.VaultPathForName(name)
	if err != nil {
		return "", fmt.Errorf("resolve vault path: %w", err)
	}

	// Check if vault already exists
	if _, err := os.Stat(vaultPath); err == nil {
		return "", fmt.Errorf("vault %q already exists", name)
	}

	// Ensure directory exists
	dir := filepath.Dir(vaultPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create vault dir: %w", err)
	}

	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Derive key
	pwBytes := []byte(password)
	defer crypto.Zeroize(pwBytes)

	eng := crypto.NewEngine(nil)
	key, err := eng.DeriveKey(pwBytes, salt)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}
	defer crypto.Zeroize(key)

	// Generate verify hash
	kdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	verifyHash := make([]byte, 32)
	if _, err := io.ReadFull(kdf, verifyHash); err != nil {
		return "", fmt.Errorf("generate verify hash: %w", err)
	}

	// Generate recovery kit
	mnemonic, recoveryBlob, err := eng.GenerateRecoveryKit(key)
	if err != nil {
		return "", fmt.Errorf("generate recovery kit: %w", err)
	}

	// Create store
	st := store.NewSQLStore()
	if err := st.Init(vaultPath); err != nil {
		return "", fmt.Errorf("init store: %w", err)
	}
	defer func() { _ = st.Close() }()

	// Store config values
	if err := st.ConfigSet("salt", salt); err != nil {
		return "", fmt.Errorf("store salt: %w", err)
	}
	if err := st.ConfigSet("verify_hash", verifyHash); err != nil {
		return "", fmt.Errorf("store verify hash: %w", err)
	}
	if err := st.ConfigSet("recovery_blob", recoveryBlob); err != nil {
		return "", fmt.Errorf("store recovery blob: %w", err)
	}

	// Store Argon2id parameters
	params := crypto.DefaultArgon2Params
	timeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBytes, params.Time)
	memoryBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(memoryBytes, params.Memory)
	threadsBytes := []byte{byte(params.Threads)}

	if err := st.ConfigSet("argon2_time", timeBytes); err != nil {
		return "", fmt.Errorf("store argon2 time: %w", err)
	}
	if err := st.ConfigSet("argon2_memory", memoryBytes); err != nil {
		return "", fmt.Errorf("store argon2 memory: %w", err)
	}
	if err := st.ConfigSet("argon2_threads", threadsBytes); err != nil {
		return "", fmt.Errorf("store argon2 threads: %w", err)
	}

	// Set active vault in config
	cfg, err := config.Load()
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}
	cfg.ActiveVault = name
	if err := cfg.Save(); err != nil {
		return "", fmt.Errorf("save config: %w", err)
	}

	_ = st.LogAction("vault_init", "", "")

	return mnemonic, nil
}

// ── Private helpers ──

// unpackEnvelope splits an encrypted blob into nonce (12 bytes) and ciphertext.
func unpackEnvelope(blob []byte) (nonce, ciphertext []byte, err error) {
	return crypto.UnpackEnvelope(blob)
}

// packEnvelope combines nonce and ciphertext into a single blob: nonce || ciphertext.
func packEnvelope(nonce, ciphertext []byte) []byte {
	return crypto.PackEnvelope(nonce, ciphertext)
}

// extractSecretFromOTPURL extracts the base32 secret from an otpauth:// URL.
func extractSecretFromOTPURL(url string) string {
	// Parse otpauth://totp/...?secret=BASE32SECRET&...
	if !strings.HasPrefix(url, "otpauth://") {
		return ""
	}

	// Find the secret parameter
	for _, part := range strings.Split(url, "&") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "secret=") {
			return strings.TrimPrefix(part, "secret=")
		}
	}

	// Also check the query string directly (before & splitting)
	if idx := strings.Index(url, "secret="); idx >= 0 {
		after := url[idx+7:]
		if amp := strings.Index(after, "&"); amp >= 0 {
			return after[:amp]
		}
		return after
	}

	return ""
}

// Ensure dir creation for app init
func init() {
	// Empty — ensures package compiles
}

// ── Vault listing (for settings screen) ──

// VaultInfo holds display info about a vault.
type VaultInfo struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	IsOpen   bool   `json:"is_open"`
	Disabled bool   `json:"disabled"`
}

// ListVaults returns all discovered vaults.
func ListVaults() ([]VaultInfo, error) {
	vaults, err := config.ListVaults()
	if err != nil {
		return nil, err
	}
	if vaults == nil {
		return []VaultInfo{}, nil
	}

	infos := make([]VaultInfo, len(vaults))
	for i, v := range vaults {
		infos[i] = VaultInfo{
			Name:     strings.TrimSuffix(v.Name, ".sqlite"),
			Path:     v.Path,
			IsOpen:   false,
			Disabled: v.Disabled,
		}
	}
	return infos, nil
}

// ListEnabledVaults returns only enabled vaults.
func ListEnabledVaults() ([]VaultInfo, error) {
	vaults, err := config.ListEnabledVaults()
	if err != nil {
		return nil, err
	}
	if vaults == nil {
		return []VaultInfo{}, nil
	}

	infos := make([]VaultInfo, len(vaults))
	for i, v := range vaults {
		infos[i] = VaultInfo{
			Name:     strings.TrimSuffix(v.Name, ".sqlite"),
			Path:     v.Path,
			IsOpen:   false,
			Disabled: false,
		}
	}
	return infos, nil
}

// VaultDir returns the vault directory.
func VaultDir() (string, error) {
	dir, err := config.VaultsDir()
	if err != nil {
		return "", err
	}
	// Ensure the directory exists
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create vault dir: %w", err)
	}
	return dir, nil
}

// RenameVault renames a vault from oldName to newName.
func RenameVault(oldName, newName string) error {
	return config.RenameVault(oldName, newName)
}

// DeleteVault deletes a vault permanently from disk.
func DeleteVault(name string) error {
	return config.DeleteVault(name)
}

// SecretValueFile returns the path to store a temporary secret value for file import.
func SecretValueFile() string {
	return filepath.Join(os.TempDir(), "vlt-secret-value.tmp")
}

// AnalyzePasswords decrypts all password-type secrets and runs security analysis.
// The caller MUST ensure the vault is unlocked before calling this.
func (a *App) AnalyzePasswords() (*watchtower.WatchtowerResult, error) {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	store := a.store
	engine := a.engine
	a.mu.RUnlock()

	if key == nil {
		return nil, fmt.Errorf("vault is locked")
	}

	return watchtower.Analyze(store, engine, key)
}

// ── Import / Export ──

// ImportResult holds the result of an import operation.
type ImportResult struct {
	Imported int
	Skipped  int
	Errors   int
	Total    int
}

// ImportPasswords imports secrets from CSV or JSON data.
// ext should be ".csv" or ".json". If overwrite is true, existing secrets
// with the same name are replaced.
func (a *App) ImportPasswords(data []byte, ext string, overwrite bool) (*ImportResult, error) {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	st := a.store
	eng := a.engine
	a.mu.RUnlock()

	if key == nil {
		return nil, fmt.Errorf("vault is locked")
	}

	var records []parse.Record
	var err error
	switch strings.ToLower(ext) {
	case ".csv":
		records, err = parse.ParsePasswordCSV(data)
	case ".json":
		records, err = parseOPJSON(data)
	default:
		return nil, fmt.Errorf("unsupported file format %q (use .csv or .json)", ext)
	}
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", ext, err)
	}

	result := &ImportResult{Total: len(records)}
	for _, rec := range records {
		if rec.Title == "" || rec.Password == "" {
			result.Errors++
			continue
		}

		meta := &secret.PasswordMetadata{
			URL:      rec.URL,
			Username: rec.Username,
			OTPAuth:  otp.RedactOTPAuth(rec.OTPAuth),
		}
		metadataStr := secret.MarshalPasswordMetadata(meta)

		lookup := crypto.ComputeNameLookup(key, rec.Title)
		if !overwrite {
			_, err := st.GetByNameLookup(lookup)
			if err == nil {
				result.Skipped++
				continue
			}
		} else {
			_ = st.DeleteByLookup(lookup) // hard Delete: internal replace, not user deletion
		}

		ciphertext, nonce, err := eng.Encrypt([]byte(rec.Password), key)
		if err != nil {
			result.Errors++
			continue
		}
		encryptedBlob := packEnvelope(nonce, ciphertext)

		sec := secret.Secret{
			Name:           rec.Title,
			Kind:           secret.KindPassword,
			EncryptedValue: encryptedBlob,
			Notes:          rec.Notes,
			Tags:           rec.Tags,
			Metadata:       metadataStr,
		}
		sec, err = a.encryptSecretMetadata(sec, key)
		if err != nil {
			result.Errors++
			continue
		}
		if err := st.Store(sec); err != nil {
			result.Errors++
			continue
		}
		result.Imported++
	}

	details := fmt.Sprintf("imported=%d skipped=%d errors=%d", result.Imported, result.Skipped, result.Errors)
	_ = st.LogAction("secret_import", "", details)

	return result, nil
}

// passwordExportRecord is the standard export format.
type passwordExportRecord struct {
	Title    string `json:"Title"`
	URL      string `json:"Url,omitempty"`
	Username string `json:"Username,omitempty"`
	Password string `json:"Password"`
	OTPAuth  string `json:"OTPAuth,omitempty"`
	Tags     string `json:"Tags,omitempty"`
	Notes    string `json:"Notes,omitempty"`
}

// ExportPasswords exports all secrets as CSV or JSON bytes.
// format should be "csv" or "json". Returns the exported data and the count
// of secrets exported.
func (a *App) ExportPasswords(format string) ([]byte, int, error) {
	defer a.RecordActivity()
	a.mu.RLock()
	key := a.key
	st := a.store
	eng := a.engine
	a.mu.RUnlock()

	if key == nil {
		return nil, 0, fmt.Errorf("vault is locked")
	}

	all, err := st.ListWithEncryptedAll()
	if err != nil {
		return nil, 0, fmt.Errorf("list secrets: %w", err)
	}

	var records []passwordExportRecord
	for _, sec := range all {
		if err := a.decryptSecretMetadata(&sec, key); err != nil {
			continue
		}
		if len(sec.EncryptedValue) == 0 {
			continue
		}

		nonce, ciphertext, err := unpackEnvelope(sec.EncryptedValue)
		if err != nil {
			continue
		}
		plaintext, err := eng.Decrypt(ciphertext, key, nonce)
		if err != nil {
			continue
		}

		meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
		rec := passwordExportRecord{
			Title:    sec.Name,
			Password: string(plaintext),
			Tags:     sec.Tags,
			Notes:    sec.Notes,
		}
		if meta != nil {
			rec.URL = meta.URL
			rec.Username = meta.Username
			rec.OTPAuth = meta.OTPAuth
		}
		records = append(records, rec)
		crypto.Zeroize(plaintext)
	}

	if len(records) == 0 {
		return nil, 0, fmt.Errorf("no secrets to export")
	}

	details := fmt.Sprintf("format=%s count=%d", format, len(records))
	_ = st.LogAction("secret_export", "", details)

	switch strings.ToLower(format) {
	case "json":
		data, err := json.MarshalIndent(records, "", "  ")
		if err != nil {
			return nil, 0, fmt.Errorf("encode json: %w", err)
		}
		return append(data, '\n'), len(records), nil
	default:
		var buf strings.Builder
		w := csv.NewWriter(&buf)
		w.Comma = ';'
		_ = w.Write([]string{"Title", "Url", "Username", "Password", "OTPAuth", "Tags", "Notes"})
		for _, rec := range records {
			row := []string{rec.Title, rec.URL, rec.Username, rec.Password, rec.OTPAuth, rec.Tags, rec.Notes}
			_ = w.Write(row)
		}
		w.Flush()
		return []byte(buf.String()), len(records), nil
	}
}

// parseOPJSON parses a JSON export (array of objects).
func parseOPJSON(data []byte) ([]parse.Record, error) {
	var rawRecords []map[string]interface{}
	if err := json.Unmarshal(data, &rawRecords); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}

	var records []parse.Record
	for _, raw := range rawRecords {
		rec := parse.Record{
			Title:    stringField(raw, "Title"),
			URL:      stringField(raw, "Url"),
			Username: stringField(raw, "Username"),
			Password: stringField(raw, "Password"),
			OTPAuth:  stringField(raw, "OTPAuth"),
			Tags:     stringField(raw, "Tags"),
			Notes:    stringField(raw, "Notes"),
		}
		records = append(records, rec)
	}

	return records, nil
}

// decryptSecretMetadata decrypts all metadata BLOBs of a secret in-place.
// The caller must provide the master key.
func (a *App) decryptSecretMetadata(sec *secret.Secret, key []byte) error {
	engine := a.engine
	if len(sec.EncryptedName) > 0 {
		nonce, ct, err := unpackEnvelope(sec.EncryptedName)
		if err != nil {
			return fmt.Errorf("decrypt name: %w", err)
		}
		pt, err := engine.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt name: %w", err)
		}
		sec.Name = string(pt)
		crypto.Zeroize(pt)
	}
	if len(sec.EncryptedNotes) > 0 {
		nonce, ct, err := unpackEnvelope(sec.EncryptedNotes)
		if err != nil {
			return fmt.Errorf("decrypt notes: %w", err)
		}
		pt, err := engine.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt notes: %w", err)
		}
		sec.Notes = string(pt)
		crypto.Zeroize(pt)
	}
	if len(sec.EncryptedTags) > 0 {
		nonce, ct, err := unpackEnvelope(sec.EncryptedTags)
		if err != nil {
			return fmt.Errorf("decrypt tags: %w", err)
		}
		pt, err := engine.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt tags: %w", err)
		}
		sec.Tags = string(pt)
		crypto.Zeroize(pt)
	}
	if len(sec.EncryptedMetadata) > 0 {
		nonce, ct, err := unpackEnvelope(sec.EncryptedMetadata)
		if err != nil {
			return fmt.Errorf("decrypt metadata: %w", err)
		}
		pt, err := engine.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt metadata: %w", err)
		}
		sec.Metadata = string(pt)
		crypto.Zeroize(pt)
	}
	return nil
}

// encryptSecretMetadata encrypts all plaintext metadata fields and returns
// the secret with Encrypted* fields and NameLookup populated.
// Empty fields are stored as empty BLOBs (NOT NULL with DEFAULT X”).
func encryptSecretMetadata(s secret.Secret, eng *crypto.Engine, key []byte) (secret.Secret, error) {
	ct, nonce, err := eng.Encrypt([]byte(s.Name), key)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("encrypt name: %w", err)
	}
	s.EncryptedName = packEnvelope(nonce, ct)

	if s.Notes != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Notes), key)
		if err != nil {
			return secret.Secret{}, fmt.Errorf("encrypt notes: %w", err)
		}
		s.EncryptedNotes = packEnvelope(nonce, ct)
	} else {
		s.EncryptedNotes = []byte{}
	}

	if s.Tags != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Tags), key)
		if err != nil {
			return secret.Secret{}, fmt.Errorf("encrypt tags: %w", err)
		}
		s.EncryptedTags = packEnvelope(nonce, ct)
	} else {
		s.EncryptedTags = []byte{}
	}

	if s.Metadata != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Metadata), key)
		if err != nil {
			return secret.Secret{}, fmt.Errorf("encrypt metadata: %w", err)
		}
		s.EncryptedMetadata = packEnvelope(nonce, ct)
	} else {
		s.EncryptedMetadata = []byte{}
	}

	s.NameLookup = crypto.ComputeNameLookup(key, s.Name)
	return s, nil
}

// encryptSecretMetadata is the App method wrapper.
func (a *App) encryptSecretMetadata(s secret.Secret, key []byte) (secret.Secret, error) {
	return encryptSecretMetadata(s, a.engine, key)
}

// ListExpiring returns certificate secrets expiring within the given number of days.
func (a *App) ListExpiring(days int) ([]secret.Secret, error) {
	all, err := a.List()
	if err != nil {
		return nil, err
	}
	var result []secret.Secret
	now := time.Now()
	for _, sec := range all {
		if sec.Kind != secret.KindCertificate {
			continue
		}
		meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
		if meta == nil || meta.URL == "" {
			continue
		}
		// Certificate expiry is stored in the metadata URL field as a structured
		// parse.Metadata in the encrypted metadata blob. Since we already decrypt
		// metadata in List(), we need a different approach for certificate expiry.
		// For now, this is a placeholder that relies on the encrypted_metadata
		// containing certificate-specific metadata JSON.
		// TODO(phase-2): Proper certificate expiry parsing from decrypted metadata.
		_ = now
		_ = days
	}
	return result, nil
}

// UpdateMetadata encrypts and updates the metadata of a secret by name.
func (a *App) UpdateMetadata(name string, metadata string) error {
	a.mu.RLock()
	key := a.key
	st := a.store
	a.mu.RUnlock()

	if key == nil {
		return fmt.Errorf("vault is locked")
	}

	lookup := crypto.ComputeNameLookup(key, name)
	sec, err := st.GetByNameLookup(lookup)
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}

	sec.Metadata = metadata
	sec, err = a.encryptSecretMetadata(sec, key)
	if err != nil {
		return fmt.Errorf("encrypt metadata: %w", err)
	}

	if err := st.UpdateOTPSeedAndMetadata(lookup, sec.EncryptedOTPSeed, sec.EncryptedMetadata); err != nil {
		return fmt.Errorf("update metadata: %w", err)
	}
	return nil
}

// IncrementHOTPCounter increments the HOTP counter in a secret's metadata.
func (a *App) IncrementHOTPCounter(name string) (uint64, error) {
	a.mu.RLock()
	key := a.key
	st := a.store
	a.mu.RUnlock()

	if key == nil {
		return 0, fmt.Errorf("vault is locked")
	}

	lookup := crypto.ComputeNameLookup(key, name)
	sec, err := st.GetByNameLookup(lookup)
	if err != nil {
		return 0, fmt.Errorf("get secret: %w", err)
	}
	if err := a.decryptSecretMetadata(&sec, key); err != nil {
		return 0, fmt.Errorf("decrypt metadata: %w", err)
	}

	meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
	if meta == nil {
		meta = &secret.PasswordMetadata{}
	}
	meta.HOTPCounter++
	sec.Metadata = secret.MarshalPasswordMetadata(meta)
	sec, err = a.encryptSecretMetadata(sec, key)
	if err != nil {
		return 0, fmt.Errorf("encrypt metadata: %w", err)
	}

	if err := st.UpdateOTPSeedAndMetadata(lookup, sec.EncryptedOTPSeed, sec.EncryptedMetadata); err != nil {
		return 0, fmt.Errorf("update metadata: %w", err)
	}
	return meta.HOTPCounter, nil
}

func stringField(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	val, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := val.(string)
	if !ok {
		return ""
	}
	return s
}
