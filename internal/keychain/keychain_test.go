package keychain

import (
	"testing"
)

// mockKeychain is an in-memory implementation of Keychain for testing.
type mockKeychain struct {
	data map[string][]byte
}

func newMockKeychain() *mockKeychain {
	return &mockKeychain{data: make(map[string][]byte)}
}

func (m *mockKeychain) Save(key []byte, service, account string) error {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	m.data[service+"|"+account] = keyCopy
	return nil
}

func (m *mockKeychain) Load(service, account string) ([]byte, error) {
	key, ok := m.data[service+"|"+account]
	if !ok {
		return nil, ErrNotFound
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return keyCopy, nil
}

func (m *mockKeychain) Delete(service, account string) error {
	delete(m.data, service+"|"+account)
	return nil
}

// ── TDD Cycle 1: Save/Load roundtrip ──

func TestMockKeychain_SaveLoad_Roundtrip(t *testing.T) {
	k := newMockKeychain()
	want := []byte("test-key-32-bytes-for-testing!!!!")
	svc := "com.test.service"
	acct := "master-key"

	err := k.Save(want, svc, acct)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := k.Load(svc, acct)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if string(got) != string(want) {
		t.Errorf("loaded = %q, want %q", got, want)
	}
}

// ── TDD Cycle 2: Triangulate — multiple keys, same account ──

func TestMockKeychain_MultipleServices(t *testing.T) {
	k := newMockKeychain()

	key1 := []byte("key-for-service-a")
	key2 := []byte("key-for-service-b")
	_ = k.Save(key1, "svc-a", "default")
	_ = k.Save(key2, "svc-b", "default")

	got1, _ := k.Load("svc-a", "default")
	got2, _ := k.Load("svc-b", "default")

	if string(got1) != string(key1) {
		t.Errorf("svc-a = %q, want %q", got1, key1)
	}
	if string(got2) != string(key2) {
		t.Errorf("svc-b = %q, want %q", got2, key2)
	}
}

// ── TDD Cycle 3: Delete → Load returns ErrNotFound ──

func TestMockKeychain_Delete_ThenLoad(t *testing.T) {
	k := newMockKeychain()
	key := []byte("delete-me")
	_ = k.Save(key, "svc", "acct")
	_ = k.Delete("svc", "acct")

	_, err := k.Load("svc", "acct")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// ── TDD Cycle 4: Load non-existent returns ErrNotFound ──

func TestMockKeychain_Load_NotFound(t *testing.T) {
	k := newMockKeychain()
	_, err := k.Load("nonexistent", "nobody")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// ── TDD Cycle 5: Save zero-length key ──

func TestMockKeychain_Save_EmptyKey(t *testing.T) {
	k := newMockKeychain()
	err := k.Save([]byte{}, "svc", "acct")
	if err != nil {
		t.Fatalf("Save empty key: %v", err)
	}
	got, err := k.Load("svc", "acct")
	if err != nil {
		t.Fatalf("Load after save empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty loaded key, got %d bytes", len(got))
	}
}

// ── TDD Cycle 6: Delete non-existent is not an error ──

func TestMockKeychain_Delete_NonExistent(t *testing.T) {
	k := newMockKeychain()
	err := k.Delete("no-svc", "no-acct")
	if err != nil {
		t.Errorf("expected no error deleting non-existent, got %v", err)
	}
}
