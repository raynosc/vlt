package sync

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
)

// errSeqConflict is returned by pushOnce when the server responds with HTTP 409
// (CAS sequence conflict). It is unexported — callers use errors.Is.
var errSeqConflict = errors.New("sequence conflict")

// Client manages vault synchronization with the remote server.
type Client struct {
	store     *store.SQLStore
	baseURL   string
	apiKey    string
	syncKey   []byte
	masterKey []byte // used for name_lookup HMAC in v7 schema
	client    *http.Client
}

// newClientInternal creates a Client with optional HTTPS enforcement.
//
// masterKey is the vault's derived encryption key. It is used to unwrap
// sensitive config entries (api_key, sync_encryption_key) — issue S-01.
// When a vault still has the legacy plaintext format, the values are
// transparently re-wrapped on disk before the client is returned.
func newClientInternal(s *store.SQLStore, masterKey []byte, enforceHTTPS bool) (*Client, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes (vault unlocked?)")
	}

	serverURL, err := s.ConfigGet("sync_server_url")
	if err != nil {
		return nil, fmt.Errorf("sync not configured: %w", err)
	}

	// F3 (ADR-9): read config_format_version once; absent → legacy (1).
	configVersion := ConfigFormatVersionLegacy
	if cfv, cfvErr := s.ConfigGet("config_format_version"); cfvErr == nil {
		var v int
		if _, scanErr := fmt.Sscanf(string(cfv), "%d", &v); scanErr == nil && v >= ConfigFormatVersionAAD {
			configVersion = v
		}
	}

	rawAPI, err := s.ConfigGet("api_key")
	if err != nil {
		return nil, fmt.Errorf("sync api_key not configured: %w", err)
	}
	apiKey, apiWrapped, err := UnwrapConfigValue("api_key", rawAPI, masterKey, configVersion)
	if err != nil {
		return nil, fmt.Errorf("sync api_key: %w", err)
	}

	rawSync, err := s.ConfigGet("sync_encryption_key")
	if err != nil {
		return nil, fmt.Errorf("sync encryption key not configured: %w", err)
	}
	syncKey, syncWrapped, err := UnwrapConfigValue("sync_encryption_key", rawSync, masterKey, configVersion)
	if err != nil {
		return nil, fmt.Errorf("sync encryption key: %w", err)
	}

	// Lazy migration (S-01 & M1): older vaults stored these values in plaintext or legacy wrapped format.
	// Re-wrap them securely on disk on the first authenticated read.
	// F3 (ADR-9): capture ConfigSet errors; write config_format_version=2 only when both re-wraps
	// persisted successfully (atomic invariant — no half-migrated vault gets locked out).
	apiOK := apiWrapped
	if !apiWrapped {
		wrapped, werr := WrapConfigValue("api_key", apiKey, masterKey)
		if werr == nil {
			apiOK = s.ConfigSet("api_key", wrapped) == nil
		}
	}
	syncOK := syncWrapped
	if !syncWrapped {
		wrapped, werr := WrapConfigValue("sync_encryption_key", syncKey, masterKey)
		if werr == nil {
			syncOK = s.ConfigSet("sync_encryption_key", wrapped) == nil
		}
	}
	if apiOK && syncOK {
		_ = s.ConfigSet("config_format_version", []byte("2"))
	}

	if len(syncKey) != 32 {
		return nil, fmt.Errorf("sync encryption key must be 32 bytes")
	}

	baseURL := string(serverURL)
	if enforceHTTPS && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("sync server URL must use HTTPS (use --insecure to allow HTTP)")
	}

	// API key is hex-encoded for HTTP transmission; use it directly as the
	// Bearer token — do NOT double-encode.
	encodedKey := string(apiKey)

	tlsConfig := &tls.Config{}
	if !enforceHTTPS {
		tlsConfig.InsecureSkipVerify = true
	}
	if caPath := os.Getenv("VLT_SYNC_CA_CERT"); caPath != "" {
		if caData, err := os.ReadFile(caPath); err == nil {
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			pool.AppendCertsFromPEM(caData)
			tlsConfig.RootCAs = pool
		}
	}
	clientCertPath := os.Getenv("VLT_SYNC_CLIENT_CERT")
	clientKeyPath := os.Getenv("VLT_SYNC_CLIENT_KEY")
	if clientCertPath != "" && clientKeyPath != "" {
		if cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath); err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
		} else {
			return nil, fmt.Errorf("load mTLS client certificate (%s, %s): %w", clientCertPath, clientKeyPath, err)
		}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &Client{
		store:     s,
		baseURL:   baseURL,
		apiKey:    encodedKey,
		syncKey:   syncKey,
		masterKey: masterKey,
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}, nil
}

// nameLookup computes the HMAC-SHA256 name_lookup BLOB for a given secret name.
// Required for v7 schema store operations that no longer accept plaintext names.
func (c *Client) nameLookup(name string) []byte {
	return crypto.ComputeNameLookup(c.masterKey, name)
}

// NewClient creates a SyncClient by reading sync configuration from the vault store.
// Returns an error if sync is not configured or if the server URL does not use HTTPS.
//
// masterKey is the vault's derived encryption key (S-01).
func NewClient(s *store.SQLStore, masterKey []byte) (*Client, error) {
	return newClientInternal(s, masterKey, true)
}

// NewClientInsecure creates a SyncClient that allows HTTP URLs.
// This is intended for local development and testing only.
func NewClientInsecure(s *store.SQLStore, masterKey []byte) (*Client, error) {
	return newClientInternal(s, masterKey, false)
}

// InitVaultInsecure initializes or reconfigures a vault with the given sync server URL.
func InitVaultInsecure(s *store.SQLStore, masterKey []byte, serverURL string) (*Client, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes")
	}

	serverURL = strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if serverURL == "" {
		return nil, fmt.Errorf("server URL cannot be empty")
	}

	// Generate or reuse vault UUID
	var vaultUUID string
	if uuidBytes, err := s.ConfigGet("vault_uuid"); err == nil && len(uuidBytes) > 0 {
		vaultUUID = string(uuidBytes)
	} else {
		var buf [16]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, fmt.Errorf("generate uuid: %w", err)
		}
		buf[6] = (buf[6] & 0x0f) | 0x40
		buf[8] = (buf[8] & 0x3f) | 0x80
		vaultUUID = fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
	}

	// Generate sync encryption key (32 bytes)
	syncKey := make([]byte, 32)
	if _, err := rand.Read(syncKey); err != nil {
		return nil, fmt.Errorf("generate sync key: %w", err)
	}
	defer crypto.Zeroize(syncKey)

	// Generate API key (32 bytes random)
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		return nil, fmt.Errorf("generate api key: %w", err)
	}
	defer crypto.Zeroize(rawKey)

	keyHash := sha256.Sum256(rawKey)
	hexKey := hex.EncodeToString(rawKey)

	// Register with sync server
	registerReq := RegisterRequest{
		VaultUUID: vaultUUID,
		KeyHash:   keyHash[:],
	}
	body, _ := json.Marshal(registerReq)

	initTLSConfig := &tls.Config{InsecureSkipVerify: true}
	if caPath := os.Getenv("VLT_SYNC_CA_CERT"); caPath != "" {
		if caData, err := os.ReadFile(caPath); err == nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caData)
			initTLSConfig.RootCAs = pool
		}
	}
	if cCert, cKey := os.Getenv("VLT_SYNC_CLIENT_CERT"), os.Getenv("VLT_SYNC_CLIENT_KEY"); cCert != "" && cKey != "" {
		if cert, err := tls.LoadX509KeyPair(cCert, cKey); err == nil {
			initTLSConfig.Certificates = []tls.Certificate{cert}
		}
	}

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: initTLSConfig},
		Timeout:   10 * time.Second,
	}

	resp, err := httpClient.Post(
		serverURL+"/v1/auth/register",
		"application/json",
		bytes.NewReader(body),
	)
	var registrationSeq int64
	if err == nil {
		if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
			var regResp RegisterResponse
			if decErr := json.NewDecoder(resp.Body).Decode(&regResp); decErr == nil {
				registrationSeq = regResp.VaultSeq
			}
		}
		_ = resp.Body.Close()
	}

	wrappedAPI, err := WrapConfigValue("api_key", []byte(hexKey), masterKey)
	if err != nil {
		return nil, fmt.Errorf("wrap api key: %w", err)
	}
	wrappedSync, err := WrapConfigValue("sync_encryption_key", syncKey, masterKey)
	if err != nil {
		return nil, fmt.Errorf("wrap sync key: %w", err)
	}

	_ = s.ConfigSet("vault_uuid", []byte(vaultUUID))
	_ = s.ConfigSet("sync_server_url", []byte(serverURL))
	_ = s.ConfigSet("api_key", wrappedAPI)
	_ = s.ConfigSet("sync_encryption_key", wrappedSync)
	_ = s.ConfigSet("last_sync_seq", []byte("0"))
	_ = s.ConfigSet("registration_seq", []byte(fmt.Sprintf("%d", registrationSeq)))
	_ = s.ConfigSet("config_format_version", []byte("2"))

	return NewClientInsecure(s, masterKey)
}

// pushOnce performs a single push attempt. It returns errSeqConflict when the
// server responds with HTTP 409 (CAS conflict). All other errors are returned
// directly. On success it saves last_sync_seq and returns the new sequence number.
func (c *Client) pushOnce() (int64, error) {
	// ADR-7: use ListWithTombstones so deletions propagate to peers.
	fullSecrets, err := c.store.ListWithTombstones()
	if err != nil {
		return 0, fmt.Errorf("list secrets: %w", err)
	}

	// Handle empty vault (no live secrets AND no tombstones)
	if len(fullSecrets) == 0 {
		return 0, fmt.Errorf("no secrets to push")
	}

	payload := SyncPayload{Secrets: fullSecrets}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal payload: %w", err)
	}

	vaultUUID, err := c.store.ConfigGet("vault_uuid")
	if err != nil {
		return 0, fmt.Errorf("vault_uuid not configured: %w", err)
	}

	// Read current seq
	lastSeq := int64(0)
	seqData, err := c.store.ConfigGet("last_sync_seq")
	if err == nil {
		_, _ = fmt.Sscanf(string(seqData), "%d", &lastSeq)
	}

	// Expected sequence number after push will be lastSeq + 1
	expectedSeq := lastSeq + 1
	aad := []byte(fmt.Sprintf("%s|%d|v1", string(vaultUUID), expectedSeq))

	blob, err := EncryptBlob(plaintext, c.syncKey, aad)
	if err != nil {
		return 0, fmt.Errorf("encrypt blob: %w", err)
	}

	pushReq := PushRequest{
		Seq:  lastSeq,
		Blob: blob,
	}
	bodyBytes, err := json.Marshal(pushReq)
	if err != nil {
		return 0, fmt.Errorf("marshal push request: %w", err)
	}

	fullURL := fmt.Sprintf("%s/v1/vaults/%s/push", c.baseURL, string(vaultUUID))
	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, fmt.Errorf("create push request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("push request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return 0, fmt.Errorf("authentication failed")
	}
	if resp.StatusCode == http.StatusConflict {
		return 0, errSeqConflict
	}
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("server error: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}

	var pushResp PushResponse
	if err := json.Unmarshal(respBody, &pushResp); err != nil {
		return 0, fmt.Errorf("parse response: %w", err)
	}

	// Save new seq
	seqStr := fmt.Sprintf("%d", pushResp.Seq)
	if err := c.store.ConfigSet("last_sync_seq", []byte(seqStr)); err != nil {
		return 0, fmt.Errorf("save seq: %w", err)
	}

	return pushResp.Seq, nil
}

// Push serializes all secrets (including tombstones), encrypts them, and
// uploads to the server. Returns the new sequence number.
// On HTTP 409 it performs one auto-pull then retries exactly once (ADR-10).
// Push must NOT purge tombstones — purge runs only at the end of Pull.
func (c *Client) Push() (int64, error) {
	seq, err := c.pushOnce()
	if !errors.Is(err, errSeqConflict) {
		return seq, err // success or non-conflict error
	}
	// One auto-pull to absorb the remote change, then retry exactly once.
	if _, perr := c.Pull(); perr != nil {
		return 0, fmt.Errorf("push conflict, auto-pull failed: %w", perr)
	}
	seq, err = c.pushOnce()
	if errors.Is(err, errSeqConflict) {
		return 0, fmt.Errorf("sequence conflict after auto-pull retry: pull and try again")
	}
	return seq, err
}

// Pull downloads the latest encrypted blob from the server, decrypts it,
// and merges remote changes into the local vault using LWW.
// Returns a list of conflicts that occurred during the merge.
func (c *Client) Pull() ([]SyncConflict, error) {
	vaultUUID, err := c.store.ConfigGet("vault_uuid")
	if err != nil {
		return nil, fmt.Errorf("vault_uuid not configured: %w", err)
	}

	// F1/F2: compute effectiveSeq = max(lastSeq, registrationSeq) for rollback detection.
	lastSeq := int64(0)
	if seqData, serr := c.store.ConfigGet("last_sync_seq"); serr == nil {
		_, _ = fmt.Sscanf(string(seqData), "%d", &lastSeq)
	}
	registrationSeq := int64(0)
	if regData, rerr := c.store.ConfigGet("registration_seq"); rerr == nil {
		_, _ = fmt.Sscanf(string(regData), "%d", &registrationSeq)
	}
	effectiveSeq := lastSeq
	if registrationSeq > effectiveSeq {
		effectiveSeq = registrationSeq
	}

	// F1/F2 pre-flight: when effectiveSeq == 0, issue a single GET /status to anchor
	// registration_seq BEFORE accepting any pull blob. This closes the gap where a
	// brand-new vault has no anchored seq and could accept a replayed old blob.
	// Structural loop avoidance: the guard is `if effectiveSeq == 0` — not a loop.
	// After this block writes registration_seq, subsequent pulls see effectiveSeq > 0.
	//
	// TOFU limitation: a malicious server that lies about its own seq on a device
	// with no prior state cannot be detected — we pin trust-on-first-use only.
	// The pre-flight is fail-closed: any network error, non-200 status, or decode
	// failure aborts the Pull rather than proceeding unanchored.
	if effectiveSeq == 0 {
		statusURL := fmt.Sprintf("%s/v1/vaults/%s/status", c.baseURL, string(vaultUUID))
		statusReq, err := http.NewRequest(http.MethodGet, statusURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create status request: %w", err)
		}
		statusReq.Header.Set("Authorization", "Bearer "+c.apiKey)

		statusResp, err := c.client.Do(statusReq)
		if err != nil {
			return nil, fmt.Errorf("pre-flight status request failed (fail-closed): %w", err)
		}
		defer func() { _ = statusResp.Body.Close() }()

		if statusResp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("pre-flight status returned %d (fail-closed, unanchored vault)", statusResp.StatusCode)
		}

		var vs VaultStatus
		if decErr := json.NewDecoder(statusResp.Body).Decode(&vs); decErr != nil {
			return nil, fmt.Errorf("pre-flight status decode failed (fail-closed): %w", decErr)
		}

		// Always persist registration_seq even when seq=0 (TOFU semantics).
		// This prevents the pre-flight from re-firing on the next Pull and ensures
		// the rollback guard has a baseline to compare against.
		regSeqStr := fmt.Sprintf("%d", vs.Seq)
		_ = c.store.ConfigSet("registration_seq", []byte(regSeqStr))
		registrationSeq = vs.Seq
		if registrationSeq > effectiveSeq {
			effectiveSeq = registrationSeq
		}
	}

	fullURL := fmt.Sprintf("%s/v1/vaults/%s/pull", c.baseURL, string(vaultUUID))

	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create pull request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pull request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no remote data")
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("authentication failed")
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("server error: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var pullResp PullResponse
	if err := json.Unmarshal(respBody, &pullResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	// F1/F2: enforce effectiveSeq-based rollback detection (ADR-8).
	if pullResp.Seq < effectiveSeq {
		return nil, fmt.Errorf("rollback detected: server seq %d < effective seq %d", pullResp.Seq, effectiveSeq)
	}

	// Verify the blob using GCM AAD binding
	aad := []byte(fmt.Sprintf("%s|%d|v1", string(vaultUUID), pullResp.Seq))
	plaintext, err := DecryptBlob(pullResp.Blob, c.syncKey, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt blob: %w", err)
	}

	var remote SyncPayload
	if err := json.Unmarshal(plaintext, &remote); err != nil {
		return nil, fmt.Errorf("unmarshal remote secrets: %w", err)
	}

	// Normalize remote secrets: ensure NameLookup and Name are populated
	for i := range remote.Secrets {
		if len(remote.Secrets[i].NameLookup) == 0 && len(remote.Secrets[i].EncryptedName) > 12 && len(c.masterKey) == 32 {
			nonce, ct := remote.Secrets[i].EncryptedName[:12], remote.Secrets[i].EncryptedName[12:]
			if pt, err := crypto.NewEngine(nil).Decrypt(ct, c.masterKey, nonce); err == nil {
				remote.Secrets[i].Name = string(pt)
				remote.Secrets[i].NameLookup = c.nameLookup(string(pt))
				crypto.Zeroize(pt)
			}
		} else if len(remote.Secrets[i].NameLookup) == 0 && remote.Secrets[i].Name != "" {
			remote.Secrets[i].NameLookup = c.nameLookup(remote.Secrets[i].Name)
		}
	}

	// Get full local secrets including tombstones for merge
	fullLocal, err := c.store.ListWithTombstones()
	if err != nil {
		return nil, fmt.Errorf("list local secrets: %w", err)
	}

	// Merge using effectiveTS-based LWW (ADR-2)
	merged, conflicts := mergeSecrets(fullLocal, remote.Secrets)

	// Build remote name index for quick lookup
	remoteIndex := make(map[string]secret.Secret, len(remote.Secrets))
	for _, r := range remote.Secrets {
		remoteIndex[secretNameOrEncrypted(r)] = r
	}

	// Build local name index for quick lookup
	localIndex := make(map[string]secret.Secret, len(fullLocal))
	for _, l := range fullLocal {
		localIndex[secretNameOrEncrypted(l)] = l
	}

	// Apply merged results to local store — only remote-winner entries need action
	for _, sec := range merged {
		secKey := secretNameOrEncrypted(sec)
		_, isRemote := remoteIndex[secKey]
		if !isRemote {
			// Local-only secret — no action needed
			continue
		}

		localSec, hasLocal := localIndex[secKey]

		// Check if the merged winner is actually the remote version
		// by comparing effectiveTS values. If local won, skip.
		if hasLocal {
			remoteWinner := remoteIndex[secKey]
			localEff := effectiveTS(localSec)
			remoteEff := effectiveTS(remoteWinner)
			if !remoteEff.After(localEff) &&
				(!remoteEff.Equal(localEff) || !isTomb(remoteWinner) || isTomb(localSec)) {
				// Local wins — no action
				continue
			}
		}

		name := sec.Name
		lookup := sec.NameLookup
		if len(lookup) == 0 {
			if len(sec.EncryptedName) > 12 && len(c.masterKey) == 32 {
				nonce, ct := sec.EncryptedName[:12], sec.EncryptedName[12:]
				if pt, err := crypto.NewEngine(nil).Decrypt(ct, c.masterKey, nonce); err == nil {
					name = string(pt)
					lookup = c.nameLookup(name)
					sec.Name = name
					crypto.Zeroize(pt)
				}
			}
			if len(lookup) == 0 && hasLocal && len(localSec.NameLookup) > 0 {
				lookup = localSec.NameLookup
			} else if len(lookup) == 0 && name != "" {
				lookup = c.nameLookup(name)
			}
		}
		sec.NameLookup = lookup

		// Apply the remote winner
		if isTomb(sec) {
			if hasLocal && !isTomb(localSec) {
				// Remote tombstone beats live local → soft-delete
				if err := c.store.SoftDeleteByLookup(lookup); err != nil {
					return nil, fmt.Errorf("soft-delete from remote tombstone %q: %w", sec.Name, err)
				}
			} else if !hasLocal {
				// Tombstone exists only remotely → insert as tombstone so it propagates
				if err := c.store.Store(sec); err != nil {
					return nil, fmt.Errorf("store remote tombstone %q: %w", sec.Name, err)
				}
			} else {
				// Both are tombstones and remote has a newer effectiveTS (remote won the
				// merge). Advance the local deleted_at so the purge horizon uses the
				// newer deletion time instead of the stale local value.
				remoteTS := effectiveTS(remoteIndex[secKey])
				localTS := effectiveTS(localSec)
				if remoteTS.After(localTS) && sec.DeletedAt != nil {
					if err := c.store.UpdateTombstoneDeletedAt(lookup, *sec.DeletedAt); err != nil {
						return nil, fmt.Errorf("advance tombstone deleted_at %q: %w", sec.Name, err)
					}
				}
			}
		} else {
			// Live remote winner
			if hasLocal {
				// Replace: hard Delete then Store (internal replace, not user deletion)
				_ = c.store.DeleteByLookup(lookup) // hard Delete: internal replace, not user deletion
				if err := c.store.Store(sec); err != nil {
					return nil, fmt.Errorf("replace secret %q: %w", sec.Name, err)
				}
			} else {
				if err := c.store.Store(sec); err != nil {
					return nil, fmt.Errorf("store remote secret %q: %w", sec.Name, err)
				}
			}
		}
	}

	// Log conflicts
	for _, conflict := range conflicts {
		_ = c.logConflict(conflict)
	}

	// Save new seq
	seqStr := fmt.Sprintf("%d", pullResp.Seq)
	if err := c.store.ConfigSet("last_sync_seq", []byte(seqStr)); err != nil {
		return nil, fmt.Errorf("save seq: %w", err)
	}

	// ADR-6: purge tombstones older than 30d AFTER seq is saved, only on Pull.
	if err := c.purgeExpiredTombstones(); err != nil {
		// Non-fatal: log but don't fail the pull
		// (purge is best-effort; a later pull will retry)
		_ = err
	}

	return conflicts, nil
}

// Status returns the local sync status.
func (c *Client) Status() (*VaultStatus, error) {
	seqData, err := c.store.ConfigGet("last_sync_seq")
	if err != nil {
		return nil, fmt.Errorf("sync not configured: %w", err)
	}

	var seq int64
	_, _ = fmt.Sscanf(string(seqData), "%d", &seq)

	vaultUUID, _ := c.store.ConfigGet("vault_uuid")

	secrets, _ := c.store.List()

	status := &VaultStatus{
		VaultUUID:   string(vaultUUID),
		Seq:         seq,
		LastUpdated: time.Now().UTC(),
	}
	_ = secrets

	return status, nil
}

// logConflict records a sync conflict in the sync_conflicts table.
func (c *Client) logConflict(conflict SyncConflict) error {
	localJSON, _ := json.Marshal(map[string]interface{}{
		"name":       conflict.Name,
		"updated_at": conflict.LocalTS,
	})
	remoteJSON, _ := json.Marshal(map[string]interface{}{
		"name":       conflict.Name,
		"updated_at": conflict.RemoteTS,
	})

	// Insert via raw SQL since there's no dedicated method
	// Use store's ConfigSet pattern — actually we need a direct insert
	// Let's store conflicts separately
	_ = localJSON
	_ = remoteJSON

	// For now, store in config with key prefix
	conflictKey := fmt.Sprintf("sync_conflict_%s_%d", conflict.Name, time.Now().UnixNano())
	conflictData, _ := json.Marshal(conflict)
	return c.store.ConfigSet(conflictKey, conflictData)
}

// tombstonePurgeHorizon is the age after which a soft-deleted tombstone is
// eligible for permanent removal. ADR-6: 30 days gives every honest peer
// sufficient time to observe the deletion.
const tombstonePurgeHorizon = 30 * 24 * time.Hour

// effectiveTS returns the timestamp that represents the most recent write to a
// secret, treating a tombstone deletion as a write. ADR-2.
func effectiveTS(s secret.Secret) time.Time {
	if s.DeletedAt != nil && s.DeletedAt.After(s.UpdatedAt) {
		return *s.DeletedAt
	}
	return s.UpdatedAt
}

// isTomb returns true when the secret is a soft-deleted tombstone.
func isTomb(s secret.Secret) bool {
	return s.DeletedAt != nil
}

// purgeExpiredTombstones hard-deletes tombstones older than the purge horizon.
// Called at the end of Pull, after last_sync_seq is saved. Never called on Push.
func (c *Client) purgeExpiredTombstones() error {
	before := time.Now().UTC().Add(-tombstonePurgeHorizon)
	_, err := c.store.PurgeTombstones(before)
	return err
}

func secretNameOrEncrypted(s secret.Secret) string {
	if len(s.NameLookup) > 0 {
		return string(s.NameLookup)
	}
	if s.Name != "" {
		return s.Name
	}
	return string(s.EncryptedName)
}

// mergeSecrets performs LWW (Last-Writer-Wins) merge of local and remote secrets
// using effectiveTS as the comparison key (ADR-2).
//
// Tie-break rules (ADR-2, pinned):
//  1. Tombstone beats live when effectiveTS is equal and exactly one side is a tombstone.
//  2. Both same type at equal effectiveTS → local wins.
//
// Returns the merged list and conflicts where remote overwrites local.
// Tombstones are preserved in the output (Pull apply-loop acts on them).
func mergeSecrets(local, remote []secret.Secret) ([]secret.Secret, []SyncConflict) {
	// Build map of local secrets by name
	localMap := make(map[string]secret.Secret)
	for _, s := range local {
		localMap[secretNameOrEncrypted(s)] = s
	}

	// Build map of remote secrets by name
	remoteMap := make(map[string]secret.Secret)
	for _, s := range remote {
		remoteMap[secretNameOrEncrypted(s)] = s
	}

	// Collect all unique names
	nameSet := make(map[string]bool)
	for _, s := range local {
		nameSet[secretNameOrEncrypted(s)] = true
	}
	for _, s := range remote {
		nameSet[secretNameOrEncrypted(s)] = true
	}

	merged := make([]secret.Secret, 0, len(nameSet))
	var conflicts []SyncConflict

	for name := range nameSet {
		localSec, hasLocal := localMap[name]
		remoteSec, hasRemote := remoteMap[name]

		if !hasLocal {
			// Only in remote — add it (includes remote tombstones)
			merged = append(merged, remoteSec)
			continue
		}

		if !hasRemote {
			// Only in local — keep it (includes local tombstones)
			merged = append(merged, localSec)
			continue
		}

		// Present in both — effectiveTS-based LWW (ADR-2)
		localEff := effectiveTS(localSec)
		remoteEff := effectiveTS(remoteSec)

		remoteWins := remoteEff.After(localEff) ||
			(remoteEff.Equal(localEff) && isTomb(remoteSec) && !isTomb(localSec))

		if remoteWins {
			merged = append(merged, remoteSec)
			conflicts = append(conflicts, SyncConflict{
				Name:     name,
				LocalTS:  localEff,
				RemoteTS: remoteEff,
				Resolved: "remote_wins",
			})
		} else {
			// Local wins (newer, or tie with local preference)
			merged = append(merged, localSec)
		}
	}

	if merged == nil {
		merged = []secret.Secret{}
	}
	if conflicts == nil {
		conflicts = []SyncConflict{}
	}

	return merged, conflicts
}

// MergeSecretsForTest exposes mergeSecrets for white-box testing from the
// external test package. Only used in tests.
func MergeSecretsForTest(local, remote []secret.Secret) []secret.Secret {
	merged, _ := mergeSecrets(local, remote)
	return merged
}
