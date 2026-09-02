//go:build linux

package keychain

import (
	"os"
	"testing"
)

// TestLinuxKeychain_SaveLoadRoundtrip tests the real D-Bus Secret Service backend.
// Skipped when D-Bus session bus is not available (e.g., in Docker CI).
func TestLinuxKeychain_SaveLoadRoundtrip(t *testing.T) {
	// Skip if no D-Bus session (e.g., headless CI)
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("skipping: D-Bus session bus not available (set DBUS_SESSION_BUS_ADDRESS)")
	}

	k := New()
	svc := "com.passwd.vlt.test"
	acct := "linux-test-key"

	// Clean up any leftover from previous failed test
	_ = k.Delete(svc, acct)

	key := []byte("linux-test-key-32-bytes-xxxxxxx")

	// Save
	if err := k.Save(key, svc, acct); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load
	got, err := k.Load(svc, acct)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if string(got) != string(key) {
		t.Errorf("loaded = %q, want %q", got, key)
	}

	// Delete
	if err := k.Delete(svc, acct); err != nil {
		t.Errorf("Delete: %v", err)
	}

	// Verify deleted
	_, err = k.Load(svc, acct)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// TestLinuxKeychain_MultipleAccounts tests storing multiple keys under different accounts.
func TestLinuxKeychain_MultipleAccounts(t *testing.T) {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("skipping: D-Bus session bus not available")
	}

	k := New()
	svc := "com.passwd.vlt.test.multi"
	acct1 := "key-1"
	acct2 := "key-2"

	// Clean up
	_ = k.Delete(svc, acct1)
	_ = k.Delete(svc, acct2)

	key1 := []byte("key-number-one-32-bytes-xxxx")
	key2 := []byte("key-number-two-32-bytes-xxxx")

	if err := k.Save(key1, svc, acct1); err != nil {
		t.Fatalf("Save 1: %v", err)
	}
	if err := k.Save(key2, svc, acct2); err != nil {
		t.Fatalf("Save 2: %v", err)
	}

	got1, err := k.Load(svc, acct1)
	if err != nil {
		t.Fatalf("Load 1: %v", err)
	}
	if string(got1) != string(key1) {
		t.Errorf("account 1 = %q, want %q", got1, key1)
	}

	got2, err := k.Load(svc, acct2)
	if err != nil {
		t.Fatalf("Load 2: %v", err)
	}
	if string(got2) != string(key2) {
		t.Errorf("account 2 = %q, want %q", got2, key2)
	}

	// Clean up
	_ = k.Delete(svc, acct1)
	_ = k.Delete(svc, acct2)
}

// TestLinuxKeychain_DeleteNonExistent is idempotent.
func TestLinuxKeychain_DeleteNonExistent(t *testing.T) {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("skipping: D-Bus session bus not available")
	}

	k := New()
	err := k.Delete("com.nonexistent.svc", "no-account")
	if err != nil {
		t.Errorf("expected no error deleting non-existent, got %v", err)
	}
}

// TestLinuxKeychain_LoadNonExistent returns ErrNotFound.
func TestLinuxKeychain_LoadNonExistent(t *testing.T) {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("skipping: D-Bus session bus not available")
	}

	k := New()
	_, err := k.Load("com.nonexistent.svc", "no-account")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// TestLinuxKeychain_OpenSessionEncrypted verifies openSession attempts encrypted
// and falls back to plain gracefully.
func TestLinuxKeychain_OpenSessionEncrypted(t *testing.T) {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("skipping: D-Bus session bus not available")
	}

	kc, ok := New().(*linuxKeychain)
	if !ok {
		t.Skip("skipping: no D-Bus session available")
	}

	path, err := kc.openSession()
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty session path")
	}
}
