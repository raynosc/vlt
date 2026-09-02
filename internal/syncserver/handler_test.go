package syncserver

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	syncpkg "github.com/raynosc/vlt/internal/sync"
)

// setupHandlerTest creates a fresh store, registers a vault+key, and returns
// the mux, raw API key, and vault UUID for use in tests.
func setupHandlerTest(t *testing.T) (http.Handler, string, string) {
	t.Helper()

	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Register a vault
	vaultUUID := "handler-test-vault"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	// Create API key
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyHash := sha256.Sum256(rawKey)
	if err := s.AddAPIKey(vaultUUID, keyHash[:], "test-key"); err != nil {
		t.Fatalf("AddAPIKey failed: %v", err)
	}

	auth := NewAuthMiddleware(s)
	mux := NewHandlerMux(s, auth)

	return mux, hex.EncodeToString(rawKey), vaultUUID
}

func TestHealthz(t *testing.T) {
	mux, _, _ := setupHandlerTest(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != `{"status":"ok"}` {
		t.Errorf("expected ok body, got %q", rec.Body.String())
	}
}

func TestReadyz(t *testing.T) {
	mux, _, _ := setupHandlerTest(t)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRegisterVault(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	auth := NewAuthMiddleware(s)
	mux := NewHandlerMux(s, auth)

	body := syncpkg.RegisterRequest{
		VaultUUID: "new-vault-uuid",
		KeyHash:   []byte("new-key-hash-data"),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify vault was created
	vault, err := s.GetVault("new-vault-uuid")
	if err != nil {
		t.Fatalf("vault should exist after register: %v", err)
	}
	if vault.VaultUUID != "new-vault-uuid" {
		t.Errorf("VaultUUID = %q", vault.VaultUUID)
	}
}

func TestRegisterVault_Duplicate(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Pre-create vault
	if err := s.CreateVault("dup-vault"); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}

	auth := NewAuthMiddleware(s)
	mux := NewHandlerMux(s, auth)

	body := syncpkg.RegisterRequest{
		VaultUUID: "dup-vault",
		KeyHash:   []byte("dup-key-hash"),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate vault, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPushPull_RoundTrip(t *testing.T) {
	mux, apiKey, vaultUUID := setupHandlerTest(t)

	// Push encrypted blob
	pushReq := syncpkg.PushRequest{
		Seq:  0,
		Blob: []byte("encrypted-blob-data"),
	}
	bodyBytes, _ := json.Marshal(pushReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/"+vaultUUID+"/push", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("push expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var pushResp syncpkg.PushResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pushResp); err != nil {
		t.Fatalf("unmarshal push response: %v", err)
	}
	if pushResp.Seq != 1 {
		t.Errorf("push response seq = %d, want 1", pushResp.Seq)
	}
	if pushResp.Status != "ok" {
		t.Errorf("push status = %q, want ok", pushResp.Status)
	}

	// Pull blob
	req2 := httptest.NewRequest(http.MethodGet, "/v1/vaults/"+vaultUUID+"/pull", nil)
	req2.Header.Set("Authorization", "Bearer "+apiKey)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("pull expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}

	var pullResp syncpkg.PullResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &pullResp); err != nil {
		t.Fatalf("unmarshal pull response: %v", err)
	}
	if pullResp.Seq != 1 {
		t.Errorf("pull seq = %d, want 1", pullResp.Seq)
	}
	if string(pullResp.Blob) != "encrypted-blob-data" {
		t.Errorf("pull blob = %q, want %q", string(pullResp.Blob), "encrypted-blob-data")
	}
}

func TestPull_NotFound(t *testing.T) {
	mux, apiKey, vaultUUID := setupHandlerTest(t)

	// Pull from vault that exists but has no blob yet
	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/"+vaultUUID+"/pull", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for vault with no blob, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPull_NonexistentVault_Returns403(t *testing.T) {
	mux, apiKey, _ := setupHandlerTest(t)

	// Pull from nonexistent vault using a valid key — should return 403
	// (authz check runs before vault lookup to avoid leaking vault existence)
	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/nonexistent/pull", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for nonexistent vault with valid key, got %d", rec.Code)
	}
}

func TestRegister_RateLimited(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	auth := NewAuthMiddleware(s)
	mux := NewHandlerMux(s, auth)

	// Exceed the per-IP registration limit
	for i := 0; i < maxRegisterPerIP+1; i++ {
		body := syncpkg.RegisterRequest{
			VaultUUID: fmt.Sprintf("rate-limit-vault-%d", i),
			KeyHash:   []byte(fmt.Sprintf("key-hash-%d", i)),
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		// Simulate same IP via RemoteAddr
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if i < maxRegisterPerIP {
			if rec.Code != http.StatusCreated {
				t.Fatalf("request %d: expected 201, got %d: %s", i, rec.Code, rec.Body.String())
			}
		} else {
			if rec.Code != http.StatusTooManyRequests {
				t.Errorf("request %d: expected 429, got %d: %s", i, rec.Code, rec.Body.String())
			}
		}
	}
}

func TestPush_Unauthenticated(t *testing.T) {
	mux, _, vaultUUID := setupHandlerTest(t)

	pushReq := syncpkg.PushRequest{Seq: 0, Blob: []byte("data")}
	bodyBytes, _ := json.Marshal(pushReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/"+vaultUUID+"/push", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	// No auth header
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestGetVaultStatus(t *testing.T) {
	mux, apiKey, vaultUUID := setupHandlerTest(t)

	// Push a blob first so we have some state
	pushReq := syncpkg.PushRequest{Seq: 0, Blob: []byte("blob-data")}
	bodyBytes, _ := json.Marshal(pushReq)
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/"+vaultUUID+"/push", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("push expected 200, got %d", rec.Code)
	}

	// Get status
	req2 := httptest.NewRequest(http.MethodGet, "/v1/vaults/"+vaultUUID+"/status", nil)
	req2.Header.Set("Authorization", "Bearer "+apiKey)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("status expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}

	var status syncpkg.VaultStatus
	if err := json.Unmarshal(rec2.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if status.VaultUUID != vaultUUID {
		t.Errorf("VaultUUID = %q, want %q", status.VaultUUID, vaultUUID)
	}
	if status.Seq != 1 {
		t.Errorf("Seq = %d, want 1", status.Seq)
	}
	if status.LastUpdated.IsZero() {
		t.Error("expected non-zero LastUpdated")
	}
}

func TestRevokeKey(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Register vault + key via API
	auth := NewAuthMiddleware(s)
	mux := NewHandlerMux(s, auth)

	registerBody := syncpkg.RegisterRequest{
		VaultUUID: "revoke-test-vault",
		KeyHash:   []byte("revoke-key-hash"),
	}
	bodyBytes, _ := json.Marshal(registerBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register expected 201, got %d", rec.Code)
	}

	// Revoke the key
	// We need the raw key for auth. Since we set key_hash directly,
	// let's create a proper key pair for the revoke test.
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyHash := sha256.Sum256(rawKey)

	if err := s.AddAPIKey("revoke-test-vault", keyHash[:], "revocable"); err != nil {
		t.Fatalf("AddAPIKey failed: %v", err)
	}

	// Verify key works
	encodedKey := hex.EncodeToString(rawKey)
	statusReq := httptest.NewRequest(http.MethodGet, "/v1/vaults/revoke-test-vault/status", nil)
	statusReq.Header.Set("Authorization", "Bearer "+encodedKey)
	statusRec := httptest.NewRecorder()
	mux.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("expected 200 before revoke, got %d", statusRec.Code)
	}

	// Revoke
	revokeBody := syncpkg.RevokeRequest{
		KeyHash: keyHash[:],
	}
	bodyBytes, _ = json.Marshal(revokeBody)
	revokeReq := httptest.NewRequest(http.MethodPost, "/v1/auth/revoke", bytes.NewReader(bodyBytes))
	revokeReq.Header.Set("Content-Type", "application/json")
	revokeReq.Header.Set("Authorization", "Bearer "+encodedKey)
	revokeRec := httptest.NewRecorder()
	mux.ServeHTTP(revokeRec, revokeReq)

	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke expected 200, got %d: %s", revokeRec.Code, revokeRec.Body.String())
	}

	// Verify key no longer works
	statusReq2 := httptest.NewRequest(http.MethodGet, "/v1/vaults/revoke-test-vault/status", nil)
	statusReq2.Header.Set("Authorization", "Bearer "+encodedKey)
	statusRec2 := httptest.NewRecorder()
	mux.ServeHTTP(statusRec2, statusReq2)
	if statusRec2.Code != http.StatusForbidden {
		t.Errorf("expected 403 after revoke, got %d", statusRec2.Code)
	}
}

func TestPull_NoBlob(t *testing.T) {
	mux, apiKey, vaultUUID := setupHandlerTest(t)

	// Pull from vault that exists but has no blob yet
	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/"+vaultUUID+"/pull", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for vault with no blob, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPushPull_WrongVault_Returns403(t *testing.T) {
	// Set up two vaults with separate API keys
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	vaultA := "vault-a"
	vaultB := "vault-b"
	if err := s.CreateVault(vaultA); err != nil {
		t.Fatalf("CreateVault A failed: %v", err)
	}
	if err := s.CreateVault(vaultB); err != nil {
		t.Fatalf("CreateVault B failed: %v", err)
	}

	// Create API key for vault A
	rawKeyA := make([]byte, 32)
	if _, err := rand.Read(rawKeyA); err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	keyHashA := sha256.Sum256(rawKeyA)
	if err := s.AddAPIKey(vaultA, keyHashA[:], "key-a"); err != nil {
		t.Fatalf("AddAPIKey A failed: %v", err)
	}

	auth := NewAuthMiddleware(s)
	mux := NewHandlerMux(s, auth)

	apiKeyA := hex.EncodeToString(rawKeyA)

	// Push to vault B using vault A's key → should return 403
	pushReq := syncpkg.PushRequest{Seq: 0, Blob: []byte("blob")}
	bodyBytes, _ := json.Marshal(pushReq)
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/"+vaultB+"/push", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKeyA)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("push to wrong vault: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Pull from vault B using vault A's key → should return 403
	req2 := httptest.NewRequest(http.MethodGet, "/v1/vaults/"+vaultB+"/pull", nil)
	req2.Header.Set("Authorization", "Bearer "+apiKeyA)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Errorf("pull from wrong vault: expected 403, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

func TestRevokeKey_WrongVault_ReturnsNotFound(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	auth := NewAuthMiddleware(s)
	mux := NewHandlerMux(s, auth)

	// Create Vault A
	vaultA := "vault-a"
	if err := s.CreateVault(vaultA); err != nil {
		t.Fatalf("CreateVault A failed: %v", err)
	}
	// Create Vault B
	vaultB := "vault-b"
	if err := s.CreateVault(vaultB); err != nil {
		t.Fatalf("CreateVault B failed: %v", err)
	}

	// Create API Key for Vault A
	rawKeyA := make([]byte, 32)
	_, _ = rand.Read(rawKeyA)
	keyHashA := sha256.Sum256(rawKeyA)
	if err := s.AddAPIKey(vaultA, keyHashA[:], "key-a"); err != nil {
		t.Fatalf("AddAPIKey A: %v", err)
	}

	// Create API Key for Vault B
	rawKeyB := make([]byte, 32)
	_, _ = rand.Read(rawKeyB)
	keyHashB := sha256.Sum256(rawKeyB)
	if err := s.AddAPIKey(vaultB, keyHashB[:], "key-b"); err != nil {
		t.Fatalf("AddAPIKey B: %v", err)
	}

	// Authenticate as Vault A, but attempt to revoke Vault B's API key
	revokeBody := syncpkg.RevokeRequest{
		KeyHash: keyHashB[:],
	}
	bodyBytes, _ := json.Marshal(revokeBody)
	revokeReq := httptest.NewRequest(http.MethodPost, "/v1/auth/revoke", bytes.NewReader(bodyBytes))
	revokeReq.Header.Set("Content-Type", "application/json")
	revokeReq.Header.Set("Authorization", "Bearer "+hex.EncodeToString(rawKeyA))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, revokeReq)

	// Should return 404 (Not Found) because Vault A does not own Vault B's API key
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for foreign key revoke, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPush_OversizedPayload_Returns413(t *testing.T) {
	mux, apiKey, vaultUUID := setupHandlerTest(t)

	// Create a payload larger than 10 MB (11 MB)
	oversizedBlob := make([]byte, 11<<20)
	_, _ = rand.Read(oversizedBlob)

	pushReq := syncpkg.PushRequest{
		Seq:  0,
		Blob: oversizedBlob,
	}
	bodyBytes, _ := json.Marshal(pushReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/"+vaultUUID+"/push", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- F1/F2 registration_seq tests (RED phase) ---

func TestRegister_NewVault_VaultSeqIsZero(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	auth := NewAuthMiddleware(s)
	mux := NewHandlerMux(s, auth)

	body := syncpkg.RegisterRequest{
		VaultUUID: "brand-new-vault",
		KeyHash:   []byte("some-key-hash"),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp syncpkg.RegisterResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.VaultSeq != 0 {
		t.Errorf("new vault VaultSeq = %d, want 0", resp.VaultSeq)
	}
}

// TestGetVaultStatus_ReturnsCurrentSeq verifies that GetVaultStatus returns the
// current seq after blob updates, and that re-registering an existing vault
// returns 409 Conflict (anti-hijack). Cross-device adoption anchors via the
// pre-flight GET /status (TOFU), not registration.
func TestGetVaultStatus_ReturnsCurrentSeq(t *testing.T) {
	s := NewServerStore()
	if err := s.Init(":memory:"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = s.Close() }()

	vaultUUID := "existing-vault-at-seq"
	if err := s.CreateVault(vaultUUID); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	rawKey := make([]byte, 32)
	_, _ = rand.Read(rawKey)
	keyHash := sha256.Sum256(rawKey)
	if err := s.AddAPIKey(vaultUUID, keyHash[:], "key1"); err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}

	// Advance seq to 2 via two pushes.
	if _, err := s.UpdateBlob(vaultUUID, []byte("blob-data"), 0); err != nil {
		t.Fatalf("UpdateBlob: %v", err)
	}
	if _, err := s.UpdateBlob(vaultUUID, []byte("blob-data-2"), 1); err != nil {
		t.Fatalf("UpdateBlob seq2: %v", err)
	}

	// GetVaultStatus must reflect the current seq=2.
	status, err := s.GetVaultStatus(vaultUUID)
	if err != nil {
		t.Fatalf("GetVaultStatus: %v", err)
	}
	if status.Seq != 2 {
		t.Errorf("GetVaultStatus.Seq = %d, want 2", status.Seq)
	}

	auth := NewAuthMiddleware(s)
	mux := NewHandlerMux(s, auth)

	// Re-registering the same vault UUID must return 409 Conflict (anti-hijack).
	// A device adopting an existing vault must use the pre-flight GET /status instead.
	reDupBody := syncpkg.RegisterRequest{
		VaultUUID: vaultUUID,
		KeyHash:   []byte("attacker-key-hash"),
	}
	dupBytes, _ := json.Marshal(reDupBody)
	dupReq := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(dupBytes))
	dupReq.Header.Set("Content-Type", "application/json")
	dupRec := httptest.NewRecorder()
	mux.ServeHTTP(dupRec, dupReq)
	if dupRec.Code != http.StatusConflict {
		t.Errorf("re-register existing vault: expected 409, got %d: %s", dupRec.Code, dupRec.Body.String())
	}

	// New-vault registration must return 201 with VaultSeq=0.
	newBody := syncpkg.RegisterRequest{
		VaultUUID: "another-new-vault",
		KeyHash:   []byte("hash-for-new"),
	}
	newBytes, _ := json.Marshal(newBody)
	newReq := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(newBytes))
	newReq.Header.Set("Content-Type", "application/json")
	newRec := httptest.NewRecorder()
	mux.ServeHTTP(newRec, newReq)

	if newRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for new vault, got %d: %s", newRec.Code, newRec.Body.String())
	}
	var resp syncpkg.RegisterResponse
	if err := json.NewDecoder(newRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.VaultSeq != 0 {
		t.Errorf("new vault VaultSeq = %d, want 0", resp.VaultSeq)
	}
}
