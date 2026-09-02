package syncserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	syncpkg "github.com/raynosc/vlt/internal/sync"
)

func TestDevicesAndAlerts_Integration(t *testing.T) {
	dbPath := t.TempDir() + "/test-sync.db"
	store := NewServerStore()
	if err := store.Init(dbPath); err != nil {
		t.Fatalf("store init: %v", err)
	}
	defer func() { _ = store.Close() }()

	vaultUUID := "vlt_test_device_uuid"
	if err := store.CreateVault(vaultUUID); err != nil {
		t.Fatalf("create vault: %v", err)
	}

	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i + 1)
	}
	keyHash := sha256.Sum256(rawKey)
	if err := store.AddAPIKey(vaultUUID, keyHash[:], "test-client"); err != nil {
		t.Fatalf("create api key: %v", err)
	}

	auth := NewAuthMiddleware(store)
	mux := NewHandlerMux(store, auth)

	apiKey := hex.EncodeToString(rawKey)

	// 1. Send Heartbeat
	hbReq := syncpkg.HeartbeatRequest{
		DeviceID:      "dev_123456",
		Hostname:      "macbook-m3",
		ClientVersion: "v1.0.0",
	}
	body, _ := json.Marshal(hbReq)
	req := httptest.NewRequest("POST", "/v1/vaults/"+vaultUUID+"/devices/heartbeat", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 2. List Devices
	req = httptest.NewRequest("GET", "/v1/vaults/"+vaultUUID+"/devices", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list devices expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var devices []syncpkg.DeviceInfo
	if err := json.NewDecoder(w.Body).Decode(&devices); err != nil {
		t.Fatalf("decode devices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	if devices[0].DeviceID != "dev_123456" || devices[0].Hostname != "macbook-m3" {
		t.Errorf("unexpected device info: %+v", devices[0])
	}

	// 3. Publish Security Alert
	alert := syncpkg.SecurityAlert{
		EventID:   "evt_001",
		EventType: "security_alert",
		Severity:  "HIGH",
		Reason:    "circuit_breaker_pin_challenge_triggered",
		Device:    devices[0],
		Timestamp: time.Now().UTC(),
	}
	alertBody, _ := json.Marshal(alert)
	req = httptest.NewRequest("POST", "/v1/vaults/"+vaultUUID+"/alerts", bytes.NewReader(alertBody))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("alerts expected 202, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Revoke Device
	req = httptest.NewRequest("POST", "/v1/vaults/"+vaultUUID+"/devices/dev_123456/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("revoke device expected 200, got %d: %s", w.Code, w.Body.String())
	}

	revoked, err := store.IsDeviceRevoked(vaultUUID, "dev_123456")
	if err != nil || !revoked {
		t.Fatalf("expected device to be revoked, err: %v, revoked: %v", err, revoked)
	}
}
