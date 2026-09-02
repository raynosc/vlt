package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// lockoutState is persisted to disk as JSON.
type lockoutState struct {
	Attempts     int       `json:"attempts"`
	LockoutUntil time.Time `json:"lockout_until"`
}

// checkLockout returns whether the vault is currently locked out and how much
// time remains. It reads a hidden JSON file in the config directory.
func checkLockout(lockoutPath string) (locked bool, remaining time.Duration, err error) {
	data, err := os.ReadFile(lockoutPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("read lockout file: %w", err)
	}

	var state lockoutState
	if err := json.Unmarshal(data, &state); err != nil {
		return false, 0, fmt.Errorf("parse lockout file: %w", err)
	}

	if state.Attempts < 5 {
		return false, 0, nil
	}

	if time.Now().Before(state.LockoutUntil) {
		return true, time.Until(state.LockoutUntil), nil
	}

	// Lockout expired — clear it
	_ = clearLockout(lockoutPath)
	return false, 0, nil
}

// recordAttempt increments the failed-attempt counter and triggers a lockout
// after 5 consecutive failures. The state is written atomically to lockoutPath.
func recordAttempt(lockoutPath string) error {
	state := lockoutState{Attempts: 0}

	data, err := os.ReadFile(lockoutPath)
	if err == nil {
		_ = json.Unmarshal(data, &state)
	}

	state.Attempts++
	if state.Attempts >= 5 {
		state.LockoutUntil = time.Now().Add(5 * time.Minute)
	}

	// Ensure parent directory exists
	dir := filepath.Dir(lockoutPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create lockout dir: %w", err)
	}

	out, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal lockout state: %w", err)
	}

	if err := os.WriteFile(lockoutPath, out, 0o600); err != nil {
		return fmt.Errorf("write lockout file: %w", err)
	}
	return nil
}

// clearLockout removes the lockout file, resetting the failure counter.
func clearLockout(lockoutPath string) error {
	if err := os.Remove(lockoutPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove lockout file: %w", err)
	}
	return nil
}
