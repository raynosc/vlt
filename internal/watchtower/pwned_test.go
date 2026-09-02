package watchtower

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPwnedChecker_KAnonymity_Invariant(t *testing.T) {
	// Adversarial test: Ensure that the client ONLY sends a 5-character prefix
	// and NEVER sends the full password or full hash in URL/headers/body.
	secretPassword := "P@ssw0rd123!"
	hasher := sha1.New()
	hasher.Write([]byte(secretPassword))
	fullHash := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))
	prefix := fullHash[:5]
	suffix := fullHash[5:]

	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		// Verify URL does not contain full password or full hash
		if strings.Contains(r.URL.RawQuery, secretPassword) || strings.Contains(r.URL.Path, secretPassword) {
			t.Errorf("SECURITY INVARIANT VIOLATION: Full password leaked in URL: %s", r.URL.String())
		}
		if strings.Contains(r.URL.Path, fullHash) {
			t.Errorf("SECURITY INVARIANT VIOLATION: Full hash leaked in URL: %s", r.URL.String())
		}

		// Return mock HIBP response containing the matching suffix with 42 breaches
		resp := fmt.Sprintf("0018A0F2B0E767E96F1D0A50D8DA212F13B:2\r\n%s:42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\r\n", suffix)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(resp))
	}))
	defer server.Close()

	client := NewPwnedClient(WithBaseURL(server.URL), WithTimeout(2*time.Second))

	// Verify path matches only /range/{prefix}
	count, err := client.CheckPassword(secretPassword)
	if err != nil {
		t.Fatalf("CheckPassword failed: %v", err)
	}
	if count != 42 {
		t.Errorf("expected 42 breaches, got %d", count)
	}
	expectedPath := "/range/" + prefix
	if receivedPath != expectedPath {
		t.Errorf("expected request path %q, got %q", expectedPath, receivedPath)
	}
}

func TestPwnedChecker_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := "0018A0F2B0E767E96F1D0A50D8DA212F13B:2\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\r\n"
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(resp))
	}))
	defer server.Close()

	client := NewPwnedClient(WithBaseURL(server.URL))
	count, err := client.CheckPassword("super-unique-never-compromised-pass-xyz-999!")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 breaches for uncompromised password, got %d", count)
	}
}

func TestPwnedManager_OfflineBackoff(t *testing.T) {
	// Simulate an offline / unreachable endpoint
	offlineServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	// Immediately close the server to simulate network connection refused
	offlineServer.Close()

	cooldown := 30 * time.Minute
	manager := NewPwnedManager(cooldown, WithBaseURL(offlineServer.URL), WithTimeout(500*time.Millisecond))

	// 1. First attempt: Should attempt network, fail, and activate backoff cooldown
	if !manager.ShouldAttempt() {
		t.Fatal("expected ShouldAttempt to be true on first run")
	}

	results, err := manager.CheckBatch([]string{"pass1", "pass2"})
	if err == nil {
		t.Fatal("expected network error on closed server, got nil")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results on network failure, got %d", len(results))
	}

	// 2. Second attempt immediately after: Should NOT attempt network due to cooldown
	if manager.ShouldAttempt() {
		t.Error("expected ShouldAttempt to be false while in backoff cooldown")
	}

	// Calling CheckBatch while in cooldown should return empty results and ErrOfflineCooldown without making network requests
	results, err = manager.CheckBatch([]string{"pass1"})
	if err != ErrOfflineCooldown {
		t.Errorf("expected ErrOfflineCooldown, got %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected empty results during cooldown, got %v", results)
	}

	// 3. Simulate cooldown expiration
	manager.SetLastFailedAttempt(time.Now().Add(-35 * time.Minute))
	if !manager.ShouldAttempt() {
		t.Error("expected ShouldAttempt to be true after cooldown expired")
	}
}

func TestPwnedManager_DisabledOffline(t *testing.T) {
	manager := NewPwnedManager(0) // 0 duration or disabled
	manager.SetDisabled(true)

	if manager.ShouldAttempt() {
		t.Error("expected ShouldAttempt to be false when manager is disabled")
	}

	results, err := manager.CheckBatch([]string{"pass1"})
	if err != ErrOfflineDisabled {
		t.Errorf("expected ErrOfflineDisabled, got %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected empty results when disabled, got %v", results)
	}
}

// FuzzParseHIBPResponse fuzz tests that the HIBP response stream parser never panics on arbitrary inputs.
func FuzzParseHIBPResponse(f *testing.F) {
	f.Add("0018A0F2B0E767E96F1D0A50D8DA212F13B:2\r\nAC6008F9CAB4083784CBD1874F76618D2A97:1432859\r\n", "AC6008F9CAB4083784CBD1874F76618D2A97")
	f.Add("", "AC6008F9CAB4083784CBD1874F76618D2A97")
	f.Add("malformed line without colon\r\ninvalid:count\r\n", "suffix")
	f.Add("SUFFIX:0\n", "suffix")
	f.Add("SUFFIX:9999999999999999999999999999999999999999999\n", "suffix")

	f.Fuzz(func(t *testing.T, payload string, suffix string) {
		_, _ = parseHIBPResponse(strings.NewReader(payload), suffix)
	})
}
