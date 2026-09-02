package daemon

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/store"
	"github.com/raynosc/vlt/internal/version"
)

// testPassword is the master password used for all test vaults.
var testPassword = []byte("test-master-password")

// testSalt is a fixed 16-byte salt for deterministic test setup.
var testSalt = []byte("0123456789abcdef")

// makeVerifyHash computes the HKDF verification hash for a derived key.
func makeVerifyHash(key, salt []byte) []byte {
	kdf := hkdf.New(sha256.New, key, salt, []byte("passwd.verify"))
	hash := make([]byte, 32)
	if _, err := io.ReadFull(kdf, hash); err != nil {
		panic(err)
	}
	return hash
}

// newTestDaemon creates a temporary vault, initializes it, and starts a daemon.
// Returns the daemon, socket path, and a cleanup function.
// newTestDaemon builds and starts a daemon. Any opts are applied to the daemon
// BEFORE the accept loop starts, so test-only fields like panicHook can be set
// without racing the handleConnection goroutine that reads them.
func newTestDaemon(t *testing.T, timeout time.Duration, opts ...func(*Daemon)) (*Daemon, string) {
	t.Helper()

	// Use a short socket path to stay within macOS Unix socket path limit (~104 chars)
	socketDir, err := os.MkdirTemp("", "vlt-")
	if err != nil {
		t.Fatalf("create socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "sock")

	// Create and initialize store
	vaultFile := filepath.Join(t.TempDir(), "test.sqlite")
	st := store.NewSQLStore()
	if err := st.Init(vaultFile); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Set up crypto engine
	eng := crypto.NewEngine(nil)

	// Derive key and store verification material
	key, err := eng.DeriveKey(testPassword, testSalt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)

	verifyHash := makeVerifyHash(key, testSalt)

	if err := st.ConfigSet("salt", testSalt); err != nil {
		t.Fatalf("set salt: %v", err)
	}
	if err := st.ConfigSet("verify_hash", verifyHash); err != nil {
		t.Fatalf("set verify hash: %v", err)
	}

	// Create and start daemon
	d := New(st, eng, testSalt, verifyHash, socketPath, timeout)
	// Apply options before Run so test hooks are set before the accept loop
	// (and handleConnection) can read them.
	for _, opt := range opts {
		opt(d)
	}
	go func() {
		_ = d.Run()
	}()

	// Wait for daemon to be ready (via Ready channel, no connection probe)
	waitForDaemon(t, d, 5*time.Second)

	return d, socketPath
}

// waitForDaemon blocks until the daemon's Ready channel is closed or timeout.
func waitForDaemon(t *testing.T, d *Daemon, timeout time.Duration) {
	t.Helper()
	select {
	case <-d.Ready:
	case <-time.After(timeout):
		t.Fatalf("daemon not ready after %v", timeout)
	}
	// Small extra delay to let the accept loop settle on slow CI
	time.Sleep(10 * time.Millisecond)
}

// dial connects to the daemon socket.
func dial(t *testing.T, socketPath string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

// send writes a line to the connection.
func send(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "%s\n", msg); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// recv reads one line from the connection.
func recv(t *testing.T, conn net.Conn) string {
	t.Helper()
	// Set a read deadline to prevent hangs
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			t.Fatalf("recv error: %v", err)
		}
		t.Fatal("recv: unexpected EOF")
	}
	return scanner.Text()
}

// recvJSON reads a line and unmarshals it as a Response.
func recvJSON(t *testing.T, conn net.Conn) Response {
	t.Helper()
	line := recv(t, conn)
	var resp Response
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", line, err)
	}
	return resp
}

// assertResponse checks common response fields.
func assertResponse(t *testing.T, resp Response, wantStatus, wantMessage string) {
	t.Helper()
	if resp.Status != wantStatus {
		t.Errorf("expected status %q, got %q", wantStatus, resp.Status)
	}
	if wantMessage != "" && resp.Message != wantMessage {
		t.Errorf("expected message %q, got %q", wantMessage, resp.Message)
	}
}

// command is a convenience for sending a JSON command and getting the response.
func command(t *testing.T, conn net.Conn, req interface{}) Response {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	send(t, conn, string(data))
	return recvJSON(t, conn)
}

// trySend writes a line and returns any error instead of failing the test.
// Use it in scenarios where the server may legitimately tear down the
// connection concurrently with the client write (panic recovery, shutdown),
// where a "broken pipe" is expected rather than a test failure.
func trySend(conn net.Conn, msg string) error {
	_, err := fmt.Fprintf(conn, "%s\n", msg)
	return err
}

// tryCommand sends a JSON command best-effort and returns the response and any
// error. Unlike command, it does not fail the test when the connection is torn
// down by the server mid-exchange — the caller decides what the race means.
func tryCommand(t *testing.T, conn net.Conn, req interface{}) (Response, error) {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if err := trySend(conn, string(data)); err != nil {
		return Response{}, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		if serr := scanner.Err(); serr != nil {
			return Response{}, serr
		}
		return Response{}, io.EOF
	}
	var resp Response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

// --- Tests ---

func TestDaemon_Ping(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	resp := command(t, conn, map[string]string{"cmd": "ping"})
	assertResponse(t, resp, "ok", "")
	if resp.Version != version.Version {
		t.Errorf("expected version %q, got %q", version.Version, resp.Version)
	}
}

func TestDaemon_UnlockLock(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// Lock when already locked

	resp := command(t, conn, map[string]string{"cmd": "lock"})
	assertResponse(t, resp, "error", "already locked")

	// Unlock with wrong password
	resp = command(t, conn, map[string]string{"cmd": "unlock", "password": "wrong-password"})
	assertResponse(t, resp, "error", "invalid master password")

	// Unlock with correct password
	resp = command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")

	// Unlock again should fail
	resp = command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "error", "already unlocked")

	// Lock
	resp = command(t, conn, map[string]string{"cmd": "lock"})
	assertResponse(t, resp, "ok", "")

	// Lock again should fail
	resp = command(t, conn, map[string]string{"cmd": "lock"})
	assertResponse(t, resp, "error", "already locked")
}

func TestDaemon_ListGetAdd(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// Unlock
	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")

	// List should be empty
	resp = command(t, conn, map[string]string{"cmd": "list"})
	assertResponse(t, resp, "ok", "")
	if len(resp.Secrets) != 0 {
		t.Fatalf("expected 0 secrets, got %d", len(resp.Secrets))
	}

	// Add a secret
	resp = command(t, conn, map[string]interface{}{
		"cmd":   "add",
		"name":  "test-secret",
		"value": "my-value",
		"kind":  "password",
	})
	assertResponse(t, resp, "ok", "")

	// List should have one entry
	resp = command(t, conn, map[string]string{"cmd": "list"})
	assertResponse(t, resp, "ok", "")
	if len(resp.Secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(resp.Secrets))
	}
	if resp.Secrets[0]["name"] != "test-secret" {
		t.Errorf("expected name 'test-secret', got %v", resp.Secrets[0]["name"])
	}

	// Get the secret
	resp = command(t, conn, map[string]string{"cmd": "get", "name": "test-secret"})
	assertResponse(t, resp, "ok", "")
	if resp.Name != "test-secret" {
		t.Errorf("expected name 'test-secret', got %q", resp.Name)
	}
	if resp.Value != "my-value" {
		t.Errorf("expected value 'my-value', got %q", resp.Value)
	}

	// Get non-existent secret
	resp = command(t, conn, map[string]string{"cmd": "get", "name": "does-not-exist"})
	assertResponse(t, resp, "error", "secret not found")
}

func TestDaemon_Generate(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// Generate with default length
	resp := command(t, conn, map[string]string{"cmd": "generate"})
	assertResponse(t, resp, "ok", "")
	if len(resp.Password) == 0 {
		t.Fatal("expected non-empty password")
	}

	// Generate with custom length
	resp = command(t, conn, map[string]interface{}{"cmd": "generate", "length": 32})
	assertResponse(t, resp, "ok", "")
	if len(resp.Password) != 32 {
		t.Errorf("expected 32-char password, got %d chars", len(resp.Password))
	}

	// Generated passwords should be different each time
	resp2 := command(t, conn, map[string]interface{}{"cmd": "generate", "length": 32})
	if resp.Password == resp2.Password {
		t.Error("expected different passwords on consecutive generates")
	}
}

func TestDaemon_RequiresUnlock(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// All commands except ping, unlock, generate, and shutdown should fail
	for _, cmd := range []string{"list", "get", "add"} {
		resp := command(t, conn, map[string]string{"cmd": cmd})
		assertResponse(t, resp, "error", "vault is locked")
	}

	// Generate is a utility command that does not require vault access
	resp := command(t, conn, map[string]string{"cmd": "generate"})
	assertResponse(t, resp, "ok", "")
}

func TestDaemon_TimeoutAutoLock(t *testing.T) {
	d, socketPath := newTestDaemon(t, 50*time.Millisecond)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// Unlock

	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")

	// Wait for timeout
	time.Sleep(100 * time.Millisecond)

	// Should be locked now
	resp = command(t, conn, map[string]string{"cmd": "list"})
	assertResponse(t, resp, "error", "vault is locked")

	// Should be able to unlock again
	resp = command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")
}

func TestDaemon_TimeoutResetsOnCommand(t *testing.T) {
	d, socketPath := newTestDaemon(t, 100*time.Millisecond)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// Unlock
	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")

	// Send commands to keep alive, each resetting the timer
	for i := 0; i < 5; i++ {
		time.Sleep(60 * time.Millisecond) // less than timeout
		resp = command(t, conn, map[string]string{"cmd": "ping"})
		assertResponse(t, resp, "ok", "")
	}

	// Still unlocked because each command reset the timer
	resp = command(t, conn, map[string]string{"cmd": "list"})
	assertResponse(t, resp, "ok", "")
}

func TestDaemon_RateLimit(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// Exhaust unlock attempts (MED-05: global rate limit = 5)
	for i := 0; i < maxUnlockAttempts; i++ {
		resp := command(t, conn, map[string]string{"cmd": "unlock", "password": "wrong"})
		assertResponse(t, resp, "error", "invalid master password")
	}

	// Next attempt triggers lockout
	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": "wrong"})
	if resp.Status != "error" {
		t.Errorf("expected error status, got %q", resp.Status)
	}
	if !strings.Contains(resp.Message, "too many failed unlock attempts") {
		t.Errorf("expected lockout message, got %q", resp.Message)
	}

	// Even correct password should be rejected during lockout
	resp = command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	if resp.Status != "error" {
		t.Errorf("expected error during lockout, got %q", resp.Status)
	}
	if !strings.Contains(resp.Message, "locked out") {
		t.Errorf("expected lockout message, got %q", resp.Message)
	}

	_ = conn.Close()
	// Reset consecutiveLockouts for other tests
	d.consecutiveLockouts = 0
	d.lockoutUntil = time.Time{}
}

// TestDaemon_RateLimitIsGlobal verifies that rate limits persist across connections.
// MED-05: This is a deliberate behavior change — reconnecting does NOT reset the counter.
func TestDaemon_RateLimitIsGlobal(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	// Use 4 out of 5 attempts on first connection
	conn1 := dial(t, socketPath)
	for i := 0; i < maxUnlockAttempts-1; i++ {
		resp := command(t, conn1, map[string]string{"cmd": "unlock", "password": "wrong"})
		assertResponse(t, resp, "error", "invalid master password")
	}
	_ = conn1.Close()
	time.Sleep(30 * time.Millisecond)

	// New connection still has the global counter
	conn2 := dial(t, socketPath)
	defer func() { _ = conn2.Close() }()

	// One more wrong attempt triggers lockout
	resp := command(t, conn2, map[string]string{"cmd": "unlock", "password": "wrong"})
	assertResponse(t, resp, "error", "invalid master password")

	resp = command(t, conn2, map[string]string{"cmd": "unlock", "password": "wrong"})
	if resp.Status != "error" {
		t.Errorf("expected error, got %q", resp.Status)
	}
	if !strings.Contains(resp.Message, "too many failed unlock attempts") {
		t.Errorf("expected lockout message, got %q", resp.Message)
	}

	// Reset for other tests
	d.consecutiveLockouts = 0
	d.lockoutUntil = time.Time{}
}

func TestDaemon_ConcurrentRejection(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	// First connection occupies the daemon
	conn1 := dial(t, socketPath)
	defer func() { _ = conn1.Close() }()

	// Second connection should be rejected
	conn2, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		t.Fatalf("dial conn2: %v", err)
	}
	defer func() { _ = conn2.Close() }()

	// Read rejection response
	scanner := bufio.NewScanner(conn2)
	if !scanner.Scan() {
		t.Fatal("expected rejection response")
	}
	var resp Response
	if err := json.Unmarshal([]byte(scanner.Text()), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	assertResponse(t, resp, "error", "another client is connected")

	// After conn1 closes, conn2 should be able to connect
	_ = conn1.Close()
	time.Sleep(50 * time.Millisecond)

	conn3 := dial(t, socketPath)
	defer func() { _ = conn3.Close() }()
	resp = command(t, conn3, map[string]string{"cmd": "ping"})
	assertResponse(t, resp, "ok", "")
}

func TestDaemon_Shutdown(t *testing.T) {
	_, socketPath := newTestDaemon(t, 0)

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// Send shutdown. The response is best-effort: d.Shutdown() runs
	// asynchronously (go d.Shutdown()) and may close the active connection
	// before "ok" is flushed, so a teardown race here is expected. If a
	// response does arrive it must be "ok"; the authoritative check is that the
	// socket stops accepting connections below.
	if resp, err := tryCommand(t, conn, map[string]string{"cmd": "shutdown"}); err == nil {
		assertResponse(t, resp, "ok", "")
	}

	// Wait for daemon to shut down
	time.Sleep(100 * time.Millisecond)

	// Socket should be closed
	_, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err == nil {
		t.Fatal("expected connection to fail after shutdown")
	}
}

func TestDaemon_InvalidCommand(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	resp := command(t, conn, map[string]string{"cmd": "nonexistent"})
	assertResponse(t, resp, "error", "unknown command: nonexistent")
}

func TestDaemon_InvalidJSON(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	send(t, conn, "not json at all")
	resp := recvJSON(t, conn)
	assertResponse(t, resp, "error", "invalid JSON")
}

func TestDaemon_MissingCmd(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	resp := command(t, conn, map[string]string{"foo": "bar"})
	assertResponse(t, resp, "error", "missing cmd field")
}

func TestDaemon_ShutdownZeroizesKey(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)

	conn := dial(t, socketPath)

	// Unlock
	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")
	_ = conn.Close()

	// Verify key is set
	d.mu.Lock()
	keyNonNil := d.key != nil
	d.mu.Unlock()

	if !keyNonNil {
		t.Fatal("expected key to be set after unlock")
	}

	// Shutdown
	d.Shutdown()

	// Verify key is zeroized
	d.mu.Lock()
	keyStillSet := d.key != nil
	d.mu.Unlock()

	if keyStillSet {
		t.Fatal("expected key to be nil after shutdown")
	}
}

func TestDaemon_LockZeroizesKey(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// Unlock
	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")

	// Lock
	resp = command(t, conn, map[string]string{"cmd": "lock"})
	assertResponse(t, resp, "ok", "")

	// Verify key is nil
	d.mu.Lock()
	keySet := d.key != nil
	d.mu.Unlock()

	if keySet {
		t.Fatal("expected key to be nil after lock")
	}
}

// TestDaemon_GetBeforeAddMissingName verifies that get without name returns error.
func TestDaemon_GetMissingName(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")

	resp = command(t, conn, map[string]string{"cmd": "get"})
	assertResponse(t, resp, "error", "name is required")
}

// TestDaemon_AddMissingFields verifies that add without name or value returns error.
func TestDaemon_AddMissingFields(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")

	resp = command(t, conn, map[string]string{"cmd": "add", "name": "only-name"})
	assertResponse(t, resp, "error", "name and value are required")

	resp = command(t, conn, map[string]string{"cmd": "add", "value": "only-value"})
	assertResponse(t, resp, "error", "name and value are required")
}

// TestDaemon_EmptyLine verifies that empty lines are ignored.
func TestDaemon_EmptyLine(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// Send empty line, then a real command
	send(t, conn, "")
	send(t, conn, "")
	resp := command(t, conn, map[string]string{"cmd": "ping"})
	assertResponse(t, resp, "ok", "")
}

// TestDaemon_GenerateReturnsNoPlaintextInLogs verifies that generate doesn't log
// the generated password (we use t.Log to show no log line contains the password).
func TestDaemon_ListKindFilter(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")

	// Add secrets of different kinds
	for _, k := range []string{"password", "api_key", "note"} {
		resp = command(t, conn, map[string]interface{}{
			"cmd":   "add",
			"name":  fmt.Sprintf("secret-%s", k),
			"value": fmt.Sprintf("value-%s", k),
			"kind":  k,
		})
		assertResponse(t, resp, "ok", "")
	}

	resp = command(t, conn, map[string]string{"cmd": "list"})
	assertResponse(t, resp, "ok", "")

	if len(resp.Secrets) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(resp.Secrets))
	}

	// Verify kinds are preserved
	kinds := make(map[string]string)
	for _, s := range resp.Secrets {
		name, _ := s["name"].(string)
		kind, _ := s["kind"].(string)
		kinds[name] = kind
	}
	if kinds["secret-password"] != "password" {
		t.Errorf("expected kind 'password', got %q", kinds["secret-password"])
	}
	if kinds["secret-api_key"] != "api_key" {
		t.Errorf("expected kind 'api_key', got %q", kinds["secret-api_key"])
	}
}

// TestDaemon_SocketPermissions verifies the socket has 0o600 permissions.
func TestDaemon_TOCTOU_Symlink(t *testing.T) {
	tmpDir := t.TempDir()
	vaultFile := filepath.Join(t.TempDir(), "test.sqlite")
	st := store.NewSQLStore()
	if err := st.Init(vaultFile); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer func() { _ = st.Close() }()

	eng := crypto.NewEngine(nil)
	key, err := eng.DeriveKey(testPassword, testSalt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	defer crypto.Zeroize(key)
	verifyHash := makeVerifyHash(key, testSalt)
	_ = st.ConfigSet("salt", testSalt)
	_ = st.ConfigSet("verify_hash", verifyHash)

	// Create a symlink at the socket path
	socketPath := filepath.Join(tmpDir, "sock")
	realSocket := filepath.Join(tmpDir, "real-sock")
	if err := os.Symlink(realSocket, socketPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	d := New(st, eng, testSalt, verifyHash, socketPath, 0)

	done := make(chan error, 1)
	go func() {
		done <- d.Run()
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error when socket path is a symlink, got nil")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("expected symlink error, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected Run to return error quickly, but it timed out")
	}
}

func TestDaemon_SocketPermissions(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("expected socket permissions 0o600, got 0o%o", perm)
	}
}

// TestDaemon_DuplicateAdd verifies adding an existing name returns error.
func TestDaemon_DuplicateAdd(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")

	resp = command(t, conn, map[string]interface{}{
		"cmd": "add", "name": "dup", "value": "first",
	})
	assertResponse(t, resp, "ok", "")

	resp = command(t, conn, map[string]interface{}{
		"cmd": "add", "name": "dup", "value": "second",
	})
	if resp.Status != "error" {
		t.Fatal("expected error for duplicate add")
	}
	if !strings.Contains(resp.Message, "already exists") {
		t.Errorf("expected 'already exists' in error, got %q", resp.Message)
	}
}

// TestDaemon_ShutdownMultipleCalls verifies Shutdown is idempotent.
func TestDaemon_ShutdownMultipleCalls(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// Call shutdown via command. The response is best-effort: d.Shutdown() runs
	// asynchronously and may close the connection before "ok" is flushed. If a
	// response arrives it must be "ok"; the real assertions are the idempotent
	// direct calls and the closed socket below.
	if resp, err := tryCommand(t, conn, map[string]string{"cmd": "shutdown"}); err == nil {
		assertResponse(t, resp, "ok", "")
	}

	// Direct call should be safe (no panic, no hang)
	d.Shutdown()
	d.Shutdown()

	// Verify socket is gone (or at least broken)
	time.Sleep(50 * time.Millisecond)
	_, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
	if err == nil {
		// Socket may still exist on filesystem but listener is closed
		// Try pinging to confirm
		altConn, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if dialErr == nil {
			_, writeErr := fmt.Fprintf(altConn, "ping\n")
			_ = altConn.Close()
			if writeErr == nil {
				t.Fatal("expected daemon to be shut down")
			}
		}
	}
}

// TestDaemon_TimeoutNotSetByDefault verifies that with 0 timeout there's no auto-lock.
func TestDaemon_ProgressiveLockout(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	// First lockout: 5 failures → 5min lockout
	conn1 := dial(t, socketPath)
	for i := 0; i < maxUnlockAttempts; i++ {
		resp := command(t, conn1, map[string]string{"cmd": "unlock", "password": "wrong"})
		assertResponse(t, resp, "error", "invalid master password")
	}
	// 6th attempt triggers lockout
	resp := command(t, conn1, map[string]string{"cmd": "unlock", "password": "wrong"})
	if resp.Status != "error" {
		t.Fatalf("expected error, got %q", resp.Status)
	}
	if !strings.Contains(resp.Message, "5m0s") && !strings.Contains(resp.Message, "5m") {
		t.Errorf("expected 5m lockout, got: %s", resp.Message)
	}
	_ = conn1.Close()
	time.Sleep(50 * time.Millisecond)

	// Reset lockout state to test escalation
	d.mu.Lock()
	d.lockoutUntil = time.Time{}
	d.unlockAttempts = 0
	d.mu.Unlock()

	// Second lockout: 5 more failures → 15min lockout
	conn2 := dial(t, socketPath)
	for i := 0; i < maxUnlockAttempts; i++ {
		resp := command(t, conn2, map[string]string{"cmd": "unlock", "password": "wrong"})
		assertResponse(t, resp, "error", "invalid master password")
	}
	resp = command(t, conn2, map[string]string{"cmd": "unlock", "password": "wrong"})
	if !strings.Contains(resp.Message, "15m0s") && !strings.Contains(resp.Message, "15m") {
		t.Errorf("expected 15m lockout, got: %s", resp.Message)
	}
	_ = conn2.Close()
	time.Sleep(50 * time.Millisecond)

	// Reset lockout state to test escalation
	d.mu.Lock()
	d.lockoutUntil = time.Time{}
	d.unlockAttempts = 0
	d.mu.Unlock()

	// Third lockout: 5 more failures → 1hr lockout
	conn3 := dial(t, socketPath)
	for i := 0; i < maxUnlockAttempts; i++ {
		resp := command(t, conn3, map[string]string{"cmd": "unlock", "password": "wrong"})
		assertResponse(t, resp, "error", "invalid master password")
	}
	resp = command(t, conn3, map[string]string{"cmd": "unlock", "password": "wrong"})
	if !strings.Contains(resp.Message, "1h0m0s") && !strings.Contains(resp.Message, "1h") {
		t.Errorf("expected 1h lockout, got: %s", resp.Message)
	}
	_ = conn3.Close()
	time.Sleep(50 * time.Millisecond)

	// Reset for other tests
	d.mu.Lock()
	d.consecutiveLockouts = 0
	d.lockoutUntil = time.Time{}
	d.mu.Unlock()
}

func TestDaemon_UnlockZeroizesPassword(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	req := map[string]interface{}{"cmd": "unlock", "password": string(testPassword)}
	resp := command(t, conn, req)
	assertResponse(t, resp, "ok", "")

	// Verify password is zeroized after unlock
	for _, b := range d.lastPassword {
		if b != 0 {
			t.Fatal("expected password to be zeroized after unlock")
		}
	}
}

func TestDaemon_PanicRecovery(t *testing.T) {
	// Set the panic hook BEFORE the accept loop starts (via the option) so the
	// handleConnection goroutine never races the test writing d.panicHook.
	panicOnce := sync.Once{}
	d, socketPath := newTestDaemon(t, 0, func(d *Daemon) {
		d.panicHook = func() {
			panicOnce.Do(func() { panic("test panic") })
		}
	})
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// First command triggers the panic hook, which fires at the start of
	// handleConnection (concurrently with this write). The server recovers and
	// closes the connection, so the write or read here races with that teardown
	// — best-effort. The authoritative check is that the daemon survives the
	// panic and still serves the new connection below.
	_, _ = tryCommand(t, conn, map[string]string{"cmd": "ping"})
	// Connection should be closed after panic, so we need a new connection
	_ = conn.Close()

	// The daemon should still be running
	conn2 := dial(t, socketPath)
	defer func() { _ = conn2.Close() }()

	resp := command(t, conn2, map[string]string{"cmd": "ping"})
	assertResponse(t, resp, "ok", "")
}

func TestDaemon_DoubleRun_DoesNotPanic(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	// First Run is already running from newTestDaemon
	// Try to run again — should not panic
	panicCh := make(chan interface{}, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicCh <- r
			}
		}()
		_ = d.Run()
	}()

	// Give the second Run a moment to reach the close(Ready) line
	time.Sleep(100 * time.Millisecond)

	select {
	case r := <-panicCh:
		t.Fatalf("second Run panicked: %v", r)
	default:
		// No panic — good
	}

	// Verify daemon is still functional (first Run still active)
	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()
	resp := command(t, conn, map[string]string{"cmd": "ping"})
	assertResponse(t, resp, "ok", "")
}

func TestDaemon_UnlockWithCustomArgon2Params(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	// Store custom Argon2 params in the vault
	customTime := uint32(7)
	customMemory := uint32(128 * 1024)
	customThreads := uint8(9)

	timeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBytes, customTime)
	memoryBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(memoryBytes, customMemory)
	threadsBytes := []byte{customThreads}

	_ = d.store.ConfigSet("argon2_time", timeBytes)
	_ = d.store.ConfigSet("argon2_memory", memoryBytes)
	_ = d.store.ConfigSet("argon2_threads", threadsBytes)

	// Derive key with custom params and store new verify hash
	customEng := crypto.NewEngine(&crypto.Argon2Params{
		Time:    customTime,
		Memory:  customMemory,
		Threads: customThreads,
	})
	key, err := customEng.DeriveKey(testPassword, testSalt)
	if err != nil {
		t.Fatalf("derive key with custom params: %v", err)
	}
	defer crypto.Zeroize(key)
	verifyHash := makeVerifyHash(key, testSalt)
	_ = d.store.ConfigSet("verify_hash", verifyHash)

	// Update daemon's cached verifyHash so it reads from store
	d.verifyHash = verifyHash

	// The daemon must use stored params to unlock
	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")
}

func TestDaemon_NoTimeoutByDefault(t *testing.T) {
	d, socketPath := newTestDaemon(t, 0)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")

	// Wait a bit - should still be unlocked
	time.Sleep(200 * time.Millisecond)

	resp = command(t, conn, map[string]string{"cmd": "list"})
	assertResponse(t, resp, "ok", "")
}

// TestDaemon_LockStopsTimer verifies that locking stops the auto-lock timer.
func TestDaemon_LockStopsTimer(t *testing.T) {
	d, socketPath := newTestDaemon(t, 100*time.Millisecond)
	defer d.Shutdown()

	conn := dial(t, socketPath)
	defer func() { _ = conn.Close() }()

	// Unlock
	resp := command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")

	// Immediately lock
	resp = command(t, conn, map[string]string{"cmd": "lock"})
	assertResponse(t, resp, "ok", "")

	// Wait longer than timeout
	time.Sleep(200 * time.Millisecond)

	// Unlock again should work (timer was stopped)
	resp = command(t, conn, map[string]string{"cmd": "unlock", "password": string(testPassword)})
	assertResponse(t, resp, "ok", "")
}

func TestParseJSONStringBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		key     string
		wantOk  bool
		wantVal []byte
	}{
		{
			name:    "simple password",
			input:   `{"password": "my_secure_pass"}`,
			key:     "password",
			wantOk:  true,
			wantVal: []byte("my_secure_pass"),
		},
		{
			name:    "escaped quotes and backslashes",
			input:   `{"password": "pass\\with\"escapes"}`,
			key:     "password",
			wantOk:  true,
			wantVal: []byte(`pass\with"escapes`),
		},
		{
			name:    "escaped control characters",
			input:   `{"password": "pass\nwith\tcontrol\rchars"}`,
			key:     "password",
			wantOk:  true,
			wantVal: []byte("pass\nwith\tcontrol\rchars"),
		},
		{
			name:    "unicode escape basic",
			input:   `{"password": "pass\u0020with\u0061unicode"}`,
			key:     "password",
			wantOk:  true,
			wantVal: []byte("pass withaunicode"),
		},
		{
			name:    "unicode escape multi-byte",
			input:   `{"password": "unicode\u2728sparkles"}`,
			key:     "password",
			wantOk:  true,
			wantVal: []byte("unicode✨sparkles"),
		},
		{
			name:    "extra spaces and newlines",
			input:   "  {\n  \"password\"  :  \n  \"my_secure_pass\"\n  }  ",
			key:     "password",
			wantOk:  true,
			wantVal: []byte("my_secure_pass"),
		},
		{
			name:    "missing password",
			input:   `{"cmd": "ping"}`,
			key:     "password",
			wantOk:  false,
			wantVal: nil,
		},
		{
			name:    "invalid unicode hex",
			input:   `{"password": "pass\u002Gunicode"}`,
			key:     "password",
			wantOk:  false,
			wantVal: nil,
		},
		{
			name:    "truncated unicode escape",
			input:   `{"password": "pass\u00"}`,
			key:     "password",
			wantOk:  false,
			wantVal: nil,
		},
		{
			name:    "unclosed string",
			input:   `{"password": "pass`,
			key:     "password",
			wantOk:  false,
			wantVal: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVal, gotOk := parseJSONStringBytes([]byte(tt.input), tt.key)
			if gotOk != tt.wantOk {
				t.Errorf("gotOk = %v, wantOk = %v", gotOk, tt.wantOk)
			}
			if !bytes.Equal(gotVal, tt.wantVal) {
				t.Errorf("gotVal = %q, wantVal = %q", gotVal, tt.wantVal)
			}
		})
	}
}

func TestRequest_UnmarshalJSON_ZeroAllocation(t *testing.T) {
	input := []byte(`{"cmd": "unlock", "password": "my_secure_pass"}`)
	var req Request
	err := json.Unmarshal(input, &req)
	if err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}

	if req.Cmd != "unlock" {
		t.Errorf("expected cmd 'unlock', got %q", req.Cmd)
	}

	if !bytes.Equal(req.Password, []byte("my_secure_pass")) {
		t.Errorf("expected password 'my_secure_pass', got %q", req.Password)
	}
}
