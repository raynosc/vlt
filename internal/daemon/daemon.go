// Package daemon provides the vlt Unix socket daemon.
//
// It listens on a Unix domain socket and accepts newline-delimited JSON commands.
// The daemon acts as an interface adapter — it uses internal/crypto, internal/store,
// and internal/config directly but contains no business logic.
//
// Security properties:
//   - Socket permissions: 0o600 (owner only)
//   - Never logs plaintext secret values
//   - Rate-limited unlock attempts (max 3 per connection)
//   - Auto-lock on inactivity timeout
//   - Key zeroized on shutdown/lock
//   - Single-client: one connection at a time
package daemon

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
	"github.com/raynosc/vlt/internal/version"
)

// maxUnlockAttempts is the maximum failed unlock attempts globally (not per connection).
const maxUnlockAttempts = 5

// socketPermission is the Unix socket file permission (owner-only read/write).
const socketPermission = 0o600

// lockoutDurations defines progressive lockout periods: 5min → 15min → 1hr.
var lockoutDurations = []time.Duration{5 * time.Minute, 15 * time.Minute, 1 * time.Hour}

// Request represents a JSON command from a daemon client.
type Request struct {
	Cmd      string `json:"cmd"`
	Password []byte `json:"-"` // populated via UnmarshalJSON
	Name     string `json:"name,omitempty"`
	Value    string `json:"value,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Length   int    `json:"length,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler to decode password as a plain
// string into a []byte (instead of base64, which is encoding/json's default).
func (r *Request) UnmarshalJSON(data []byte) error {
	type alias Request // prevent recursion
	var tmp alias
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	*r = Request(tmp)

	// Decode Password using zero-allocation bytes parser to prevent immutable string allocations
	if pw, ok := parseJSONStringBytes(data, "password"); ok {
		r.Password = pw
	}
	return nil
}

// Response represents a JSON response sent to a daemon client.
type Response struct {
	Status   string                   `json:"status"`
	Message  string                   `json:"message,omitempty"`
	Version  string                   `json:"version,omitempty"`
	Name     string                   `json:"name,omitempty"`
	Value    string                   `json:"value,omitempty"`
	Secrets  []map[string]interface{} `json:"secrets,omitempty"`
	Password string                   `json:"password,omitempty"`
}

// Daemon is a Unix domain socket daemon that accepts JSON commands.
//
// Zero value is not usable — use New() to create an instance.
type Daemon struct {
	store      *store.SQLStore
	engine     *crypto.Engine
	salt       []byte
	verifyHash []byte

	key        []byte // derived key; nil when vault is locked
	socketPath string
	timeout    time.Duration
	listener   net.Listener
	activeConn net.Conn

	// MED-05: Global rate limiting (persisted across connections)
	unlockAttempts      int
	lockoutUntil        time.Time
	consecutiveLockouts int // increments each time a lockout is triggered

	mu       sync.Mutex
	shutdown bool
	timer    *time.Timer
	timerSet bool // true when timer is armed

	// Ready is closed when the listener is accepting connections.
	// Used for test synchronization; may be nil in production.
	Ready chan struct{}

	// readyOnce guards close(d.Ready) to prevent panics on double Run.
	readyOnce sync.Once

	// panicHook is called at the start of handleConnection for testing panic recovery.
	panicHook func()

	// lastPassword is set during unlock for testing zeroization.
	lastPassword []byte
}

// New creates a Daemon with the given dependencies.
//
// Parameters:
//   - st: initialized SQLStore
//   - eng: crypto engine
//   - salt: vault salt (from store config)
//   - verifyHash: vault verification hash (from store config)
//   - socketPath: Unix socket path to listen on
//   - timeout: auto-lock inactivity duration (0 means no auto-lock)
func New(st *store.SQLStore, eng *crypto.Engine, salt, verifyHash []byte, socketPath string, timeout time.Duration) *Daemon {
	d := &Daemon{
		store:      st,
		engine:     eng,
		salt:       salt,
		verifyHash: verifyHash,
		socketPath: socketPath,
		timeout:    timeout,
	}
	d.Ready = make(chan struct{})
	return d
}

// Run starts the daemon's Unix socket listener and begins accepting connections.
// This method blocks until Shutdown is called or a fatal error occurs.
func (d *Daemon) Run() error {
	// TOCTOU guard: verify socket path is not a symlink before binding
	if fi, err := os.Lstat(d.socketPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("socket path is a symlink: %s", d.socketPath)
		}
	}

	// Remove stale socket file
	if err := os.Remove(d.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	// Ensure socket directory exists
	if err := os.MkdirAll(filepath.Dir(d.socketPath), 0700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	listener, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	d.listener = listener

	// Restrict socket to owner only
	if err := os.Chmod(d.socketPath, socketPermission); err != nil {
		_ = listener.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Signal that the daemon is ready to accept connections
	d.readyOnce.Do(func() { close(d.Ready) })

	// Handle OS signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		d.Shutdown()
	}()

	// Accept loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}

		d.mu.Lock()
		if d.shutdown {
			d.mu.Unlock()
			_ = conn.Close()
			return nil
		}

		// HIGH-02: Verify peer credentials — only accept connections from same UID
		if !d.verifyPeer(conn) {
			d.mu.Unlock()
			_ = writeJSON(conn, Response{Status: "error", Message: "peer authentication failed"})
			_ = conn.Close()
			continue
		}

		if d.activeConn != nil {
			d.mu.Unlock()
			_ = writeJSON(conn, Response{Status: "error", Message: "another client is connected"})
			_ = conn.Close()
			continue
		}

		d.activeConn = conn
		d.mu.Unlock()

		go d.handleConnection(conn)
	}
}

// Shutdown performs a graceful shutdown: closes the listener, zeroizes the key,
// closes the active connection, and closes the store.
func (d *Daemon) Shutdown() {
	d.mu.Lock()
	if d.shutdown {
		d.mu.Unlock()
		return
	}
	d.shutdown = true
	d.mu.Unlock()

	// Stop auto-lock timer
	d.stopTimer()

	d.mu.Lock()

	// Zeroize derived key
	if d.key != nil {
		crypto.Zeroize(d.key)
		d.key = nil
	}

	// Close active client connection
	if d.activeConn != nil {
		_ = d.activeConn.Close()
		d.activeConn = nil
	}

	d.mu.Unlock()

	// Close listener (breaks accept loop)
	if d.listener != nil {
		_ = d.listener.Close()
	}

	// Close store (logs audit entry during shutdown)
	_ = d.store.LogAction("daemon_shutdown", "", "")
	_ = d.store.Close()
}

// handleConnection manages a single client connection.
// Reads newline-delimited JSON, dispatches commands, and writes responses.
func (d *Daemon) handleConnection(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			_ = writeJSON(conn, Response{Status: "error", Message: "internal error"})
		}
		d.mu.Lock()
		d.activeConn = nil
		// MED-05: Do NOT reset unlockAttempts on disconnect — global rate limit
		d.mu.Unlock()
		_ = conn.Close()
	}()

	if d.panicHook != nil {
		d.panicHook()
	}

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Bytes()
		lineTrimmed := bytes.TrimSpace(line)
		if len(lineTrimmed) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(lineTrimmed, &req); err != nil {
			_ = writeJSON(conn, Response{Status: "error", Message: "invalid JSON"})
			continue
		}

		if req.Cmd == "" {
			_ = writeJSON(conn, Response{Status: "error", Message: "missing cmd field"})
			continue
		}

		resp := d.processCommand(&req)
		_ = writeJSON(conn, resp)

		// Manage auto-lock timer based on command
		switch req.Cmd {
		case "shutdown":
			return
		case "lock":
			if resp.Status == "ok" {
				d.stopTimer()
			}
		case "unlock":
			if resp.Status == "ok" {
				d.startTimer()
			}
		default:
			d.mu.Lock()
			unlocked := d.isUnlocked()
			d.mu.Unlock()
			if unlocked {
				d.resetTimer()
			}
		}
	}
}

// processCommand dispatches a parsed request to the appropriate handler.
// The mutex is held for the duration of command processing.
func (d *Daemon) processCommand(req *Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()

	switch req.Cmd {
	case "ping":
		return Response{Status: "ok", Version: version.Version}

	case "unlock":
		return d.handleUnlock(req)

	case "lock":
		return d.handleLock()

	case "list":
		return d.handleList(req)

	case "get":
		return d.handleGet(req)

	case "add":
		return d.handleAdd(req)

	case "generate":
		return d.handleGenerate(req)

	case "shutdown":
		go d.Shutdown()
		return Response{Status: "ok"}

	default:
		return Response{Status: "error", Message: fmt.Sprintf("unknown command: %s", req.Cmd)}
	}
}

// isUnlocked returns true if the vault key is currently in memory.
// Caller must hold d.mu.
func (d *Daemon) isUnlocked() bool {
	return d.key != nil
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

// --- Command handlers ---
// All handlers assume d.mu is held by the caller.

func (d *Daemon) handleUnlock(req *Request) Response {
	if d.key != nil {
		return Response{Status: "error", Message: "already unlocked"}
	}

	// MED-05: Check global lockout
	if !d.lockoutUntil.IsZero() && time.Now().Before(d.lockoutUntil) {
		remaining := time.Until(d.lockoutUntil).Round(time.Second)
		return Response{Status: "error", Message: fmt.Sprintf("locked out for %v due to too many failed attempts", remaining)}
	}

	d.unlockAttempts++
	if d.unlockAttempts > maxUnlockAttempts {
		d.consecutiveLockouts++
		duration := lockoutDurations[len(lockoutDurations)-1]
		if d.consecutiveLockouts <= len(lockoutDurations) {
			duration = lockoutDurations[d.consecutiveLockouts-1]
		}
		d.lockoutUntil = time.Now().Add(duration)
		d.unlockAttempts = 0
		return Response{Status: "error", Message: fmt.Sprintf("too many failed unlock attempts, locked out for %v", duration)}
	}

	// Read stored Argon2 params and create engine with them
	params := readArgon2Params(d.store)
	eng := crypto.NewEngine(params)

	// Store password for testing zeroization
	d.lastPassword = req.Password

	// HIGH-03: Single-pass Argon2id — verify and derive in one call
	key, ok := eng.VerifyAndDeriveKey(req.Password, d.salt, d.verifyHash)

	// Zeroize password immediately after key derivation
	crypto.Zeroize(req.Password)
	if d.lastPassword != nil {
		crypto.Zeroize(d.lastPassword)
	}

	if !ok {
		return Response{Status: "error", Message: "invalid master password"}
	}

	d.key = key
	d.unlockAttempts = 0
	d.consecutiveLockouts = 0    // reset progressive lockout on success
	d.lockoutUntil = time.Time{} // clear any lockout

	_ = d.store.LogAction("daemon_unlock", "", "")
	return Response{Status: "ok"}
}

func (d *Daemon) handleLock() Response {
	if d.key == nil {
		return Response{Status: "error", Message: "already locked"}
	}

	crypto.Zeroize(d.key)
	d.key = nil
	d.unlockAttempts = 0
	_ = d.store.LogAction("daemon_lock", "", "")
	return Response{Status: "ok"}
}

func (d *Daemon) handleList(req *Request) Response {
	if d.key == nil {
		return Response{Status: "error", Message: "vault is locked"}
	}

	secrets, err := d.store.List()
	if err != nil {
		return Response{Status: "error", Message: err.Error()}
	}

	var result []map[string]interface{}
	for _, s := range secrets {
		if err := decryptSecretMetadata(&s, d.engine, d.key); err != nil {
			continue
		}
		if req.Kind != "" && string(s.Kind) != req.Kind {
			continue
		}
		entry := map[string]interface{}{
			"name": s.Name,
			"kind": string(s.Kind),
		}
		// Only add non-empty optional fields
		if s.Notes != "" {
			entry["notes"] = s.Notes
		}
		if s.Tags != "" {
			entry["tags"] = s.Tags
		}
		result = append(result, entry)
	}
	if result == nil {
		result = []map[string]interface{}{}
	}

	_ = d.store.LogAction("daemon_list", "", "")
	return Response{Status: "ok", Secrets: result}
}

func (d *Daemon) handleGet(req *Request) Response {
	if d.key == nil {
		return Response{Status: "error", Message: "vault is locked"}
	}

	if req.Name == "" {
		return Response{Status: "error", Message: "name is required"}
	}

	sec, err := d.store.GetByNameLookup(crypto.ComputeNameLookup(d.key, req.Name))
	if err != nil {
		return Response{Status: "error", Message: "secret not found"}
	}

	if len(sec.EncryptedValue) == 0 {
		return Response{Status: "error", Message: "secret has no encrypted value"}
	}

	nonce, ciphertext, err := unpackEnvelope(sec.EncryptedValue)
	if err != nil {
		return Response{Status: "error", Message: err.Error()}
	}

	plaintext, err := d.engine.Decrypt(ciphertext, d.key, nonce)
	if err != nil {
		return Response{Status: "error", Message: "decryption failed"}
	}
	defer crypto.Zeroize(plaintext)

	_ = d.store.LogAction("daemon_get", req.Name, "")
	return Response{Status: "ok", Name: req.Name, Value: string(plaintext)}
}

func (d *Daemon) handleAdd(req *Request) Response {
	if d.key == nil {
		return Response{Status: "error", Message: "vault is locked"}
	}

	if req.Name == "" || req.Value == "" {
		return Response{Status: "error", Message: "name and value are required"}
	}

	kind := secret.Kind(req.Kind)
	if req.Kind == "" || !secret.IsValidKind(req.Kind) {
		kind = secret.KindPassword
	}

	ciphertext, nonce, err := d.engine.Encrypt([]byte(req.Value), d.key)
	if err != nil {
		return Response{Status: "error", Message: err.Error()}
	}

	blob := packEnvelope(nonce, ciphertext)

	s := secret.NewSecret("", req.Name, kind, blob, "", "")
	s, err = encryptSecretMetadata(s, d.engine, d.key)
	if err != nil {
		return Response{Status: "error", Message: err.Error()}
	}
	if err := d.store.Store(s); err != nil {
		return Response{Status: "error", Message: err.Error()}
	}

	_ = d.store.LogAction("daemon_add", req.Name, "")
	return Response{Status: "ok"}
}

func (d *Daemon) handleGenerate(req *Request) Response {
	length := req.Length
	if length <= 0 {
		length = crypto.DefaultPasswordLength
	}

	pw, err := generatePassword(length)
	if err != nil {
		return Response{Status: "error", Message: err.Error()}
	}
	defer crypto.Zeroize(pw)

	return Response{Status: "ok", Password: string(pw)}
}

// --- Timer management ---

func (d *Daemon) startTimer() {
	if d.timeout <= 0 {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.timeout, d.onTimeout)
	d.timerSet = true
}

func (d *Daemon) stopTimer() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.timerSet = false
}

// MED-06: Simplified timer management to avoid potential race conditions.
// Uses stop-then-recreate pattern instead of Reset() which has documented
// edge cases with AfterFunc.
func (d *Daemon) resetTimer() {
	if d.timeout <= 0 {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.timerSet {
		return
	}

	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.timeout, d.onTimeout)
}

func (d *Daemon) onTimeout() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.key == nil {
		return // already locked
	}

	crypto.Zeroize(d.key)
	d.key = nil
	d.unlockAttempts = 0
	d.timerSet = false

	_ = d.store.LogAction("daemon_auto_lock", "", "timeout")
}

// --- Helpers ---

// unpackEnvelope splits an encrypted blob into nonce (12 bytes) and ciphertext.
func unpackEnvelope(blob []byte) (nonce, ciphertext []byte, err error) {
	return crypto.UnpackEnvelope(blob)
}

// packEnvelope combines nonce and ciphertext into a single blob: nonce || ciphertext.
func packEnvelope(nonce, ciphertext []byte) []byte {
	return crypto.PackEnvelope(nonce, ciphertext)
}

// decryptSecretMetadata decrypts all encrypted metadata fields of a secret in-place.
func decryptSecretMetadata(sec *secret.Secret, eng *crypto.Engine, key []byte) error {
	if len(sec.EncryptedName) > 0 {
		nonce, ct, err := unpackEnvelope(sec.EncryptedName)
		if err != nil {
			return fmt.Errorf("decrypt name: %w", err)
		}
		pt, err := eng.Decrypt(ct, key, nonce)
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
		pt, err := eng.Decrypt(ct, key, nonce)
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
		pt, err := eng.Decrypt(ct, key, nonce)
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
		pt, err := eng.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt metadata: %w", err)
		}
		sec.Metadata = string(pt)
		crypto.Zeroize(pt)
	}
	return nil
}

// encryptSecretMetadata encrypts all plaintext metadata fields.
func encryptSecretMetadata(s secret.Secret, eng *crypto.Engine, key []byte) (secret.Secret, error) {
	ct, nonce, err := eng.Encrypt([]byte(s.Name), key)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("encrypt name: %w", err)
	}
	s.EncryptedName = crypto.PackEnvelope(nonce, ct)

	if s.Notes != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Notes), key)
		if err != nil {
			return secret.Secret{}, fmt.Errorf("encrypt notes: %w", err)
		}
		s.EncryptedNotes = crypto.PackEnvelope(nonce, ct)
	} else {
		s.EncryptedNotes = []byte{}
	}

	if s.Tags != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Tags), key)
		if err != nil {
			return secret.Secret{}, fmt.Errorf("encrypt tags: %w", err)
		}
		s.EncryptedTags = crypto.PackEnvelope(nonce, ct)
	} else {
		s.EncryptedTags = []byte{}
	}

	if s.Metadata != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Metadata), key)
		if err != nil {
			return secret.Secret{}, fmt.Errorf("encrypt metadata: %w", err)
		}
		s.EncryptedMetadata = crypto.PackEnvelope(nonce, ct)
	} else {
		s.EncryptedMetadata = []byte{}
	}

	s.NameLookup = crypto.ComputeNameLookup(key, s.Name)
	return s, nil
}

// generatePassword generates a cryptographically secure random password.
// Uses all ASCII printable character categories (upper, lower, digits, symbols).
func generatePassword(length int) ([]byte, error) {
	if length <= 0 {
		length = crypto.DefaultPasswordLength
	}

	pw := make([]byte, length)
	for i := range pw {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(crypto.DefaultPasswordCharset))))
		if err != nil {
			return nil, fmt.Errorf("rand.Int: %w", err)
		}
		pw[i] = crypto.DefaultPasswordCharset[idx.Int64()]
	}

	return pw, nil
}

// writeJSON marshals and writes a Response as a newline-delimited JSON line to conn.
func writeJSON(conn net.Conn, resp Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = conn.Write(data)
	return err
}

// parseJSONStringBytes parses a JSON object byte slice and extracts the string value
// for the given key into a newly allocated byte slice, handling JSON escape sequences
// correctly without allocating any immutable Go strings.
func parseJSONStringBytes(data []byte, key string) ([]byte, bool) {
	keyBytes := []byte("\"" + key + "\"")
	idx := 0
	for {
		i := bytes.Index(data[idx:], keyBytes)
		if i == -1 {
			return nil, false
		}
		absIdx := idx + i
		pos := absIdx + len(keyBytes)
		for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r' || data[pos] == '\n') {
			pos++
		}
		if pos < len(data) && data[pos] == ':' {
			pos++
			for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r' || data[pos] == '\n') {
				pos++
			}
			if pos < len(data) && data[pos] == '"' {
				start := pos + 1
				end := start
				var decoded []byte
				escaped := false
				for end < len(data) {
					b := data[end]
					if escaped {
						switch b {
						case '"', '\\', '/':
							decoded = append(decoded, b)
						case 'b':
							decoded = append(decoded, '\b')
						case 'f':
							decoded = append(decoded, '\f')
						case 'n':
							decoded = append(decoded, '\n')
						case 'r':
							decoded = append(decoded, '\r')
						case 't':
							decoded = append(decoded, '\t')
						case 'u':
							if end+4 < len(data) {
								hexBytes := data[end+1 : end+5]
								var val rune
								for _, hb := range hexBytes {
									val <<= 4
									switch {
									case hb >= '0' && hb <= '9':
										val += rune(hb - '0')
									case hb >= 'a' && hb <= 'f':
										val += rune(hb - 'a' + 10)
									case hb >= 'A' && hb <= 'F':
										val += rune(hb - 'A' + 10)
									default:
										return nil, false
									}
								}
								var utf8Buf [4]byte
								n := encodeRune(utf8Buf[:], val)
								decoded = append(decoded, utf8Buf[:n]...)
								end += 4
							} else {
								return nil, false
							}
						default:
							decoded = append(decoded, '\\', b)
						}
						escaped = false
					} else {
						switch b {
						case '\\':
							escaped = true
						case '"':
							return decoded, true
						default:
							decoded = append(decoded, b)
						}
					}
					end++
				}
			}
		}
		idx = absIdx + 1
	}
}

// encodeRune is a simple zero-allocation UTF-8 encoder for runes.
func encodeRune(p []byte, r rune) int {
	if r <= 0x7F {
		p[0] = byte(r)
		return 1
	}
	if r <= 0x7FF {
		p[0] = byte(0xC0 | (r >> 6))
		p[1] = byte(0x80 | (r & 0x3F))
		return 2
	}
	if r <= 0xFFFF {
		p[0] = byte(0xE0 | (r >> 12))
		p[1] = byte(0x80 | ((r >> 6) & 0x3F))
		p[2] = byte(0x80 | (r & 0x3F))
		return 3
	}
	p[0] = byte(0xF0 | (r >> 18))
	p[1] = byte(0x80 | ((r >> 12) & 0x3F))
	p[2] = byte(0x80 | ((r >> 6) & 0x3F))
	p[3] = byte(0x80 | (r & 0x3F))
	return 4
}
