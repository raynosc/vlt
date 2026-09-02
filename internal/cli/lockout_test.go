package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckLockout_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	lockoutPath := filepath.Join(tmpDir, ".lockout")

	locked, remaining, err := checkLockout(lockoutPath)
	if err != nil {
		t.Fatalf("checkLockout: %v", err)
	}
	if locked {
		t.Error("expected not locked when no file exists")
	}
	if remaining != 0 {
		t.Errorf("expected 0 remaining, got %v", remaining)
	}
}

func TestRecordAndCheckLockout(t *testing.T) {
	tmpDir := t.TempDir()
	lockoutPath := filepath.Join(tmpDir, ".lockout")

	// Record 5 failed attempts
	for i := 0; i < 5; i++ {
		if err := recordAttempt(lockoutPath); err != nil {
			t.Fatalf("recordAttempt %d: %v", i, err)
		}
	}

	// Should be locked out
	locked, remaining, err := checkLockout(lockoutPath)
	if err != nil {
		t.Fatalf("checkLockout: %v", err)
	}
	if !locked {
		t.Fatal("expected locked after 5 attempts")
	}
	if remaining <= 0 {
		t.Errorf("expected positive remaining, got %v", remaining)
	}

	// File should exist with 600 permissions
	info, err := os.Stat(lockoutPath)
	if err != nil {
		t.Fatalf("stat lockout file: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("expected permissions 0600, got %#o", perm)
	}
}

func TestClearLockout(t *testing.T) {
	tmpDir := t.TempDir()
	lockoutPath := filepath.Join(tmpDir, ".lockout")

	_ = recordAttempt(lockoutPath)
	if err := clearLockout(lockoutPath); err != nil {
		t.Fatalf("clearLockout: %v", err)
	}

	locked, _, err := checkLockout(lockoutPath)
	if err != nil {
		t.Fatalf("checkLockout after clear: %v", err)
	}
	if locked {
		t.Error("expected not locked after clear")
	}
}

func TestLockout_SurvivesRestart(t *testing.T) {
	tmpDir := t.TempDir()
	lockoutPath := filepath.Join(tmpDir, ".lockout")

	// Simulate 5 failed attempts
	for i := 0; i < 5; i++ {
		_ = recordAttempt(lockoutPath)
	}

	// Simulate restart by reading file directly
	data, err := os.ReadFile(lockoutPath)
	if err != nil {
		t.Fatalf("read lockout file: %v", err)
	}
	var state lockoutState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal lockout state: %v", err)
	}
	if state.Attempts != 5 {
		t.Errorf("attempts = %d, want 5", state.Attempts)
	}
	if state.LockoutUntil.IsZero() {
		t.Error("expected lockout_until to be set")
	}
}
