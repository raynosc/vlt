package store

import "testing"

func TestCircuitBreakerState(t *testing.T) {
	dbPath := t.TempDir() + "/cb-test.db"
	s := NewSQLStore()
	if err := s.Init(dbPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Initial state: no PIN, no lock
	cb, err := s.GetCircuitBreakerState()
	if err != nil {
		t.Fatalf("GetCircuitBreakerState failed: %v", err)
	}
	if cb.HasPIN || cb.IsPINChallenge || cb.IsHardLockout {
		t.Errorf("unexpected initial cb state: %+v", cb)
	}

	// Set PIN
	salt := []byte("test_pin_salt_16")
	hash := []byte("test_pin_hash_32_bytes_long_____")
	if err := s.SetPIN(hash, salt); err != nil {
		t.Fatalf("SetPIN failed: %v", err)
	}

	cb, _ = s.GetCircuitBreakerState()
	if !cb.HasPIN {
		t.Fatalf("expected HasPIN to be true")
	}

	// Record 3 failed master attempts
	for i := 1; i <= 3; i++ {
		st, err := s.RecordFailedMasterAttempt()
		if err != nil {
			t.Fatalf("RecordFailedMasterAttempt %d failed: %v", i, err)
		}
		if i == 3 && !st.IsPINChallenge {
			t.Fatalf("expected IsPINChallenge on attempt 3")
		}
	}

	// Record 3 failed PIN attempts
	for i := 1; i <= 3; i++ {
		st, err := s.RecordFailedPINAttempt()
		if err != nil {
			t.Fatalf("RecordFailedPINAttempt %d failed: %v", i, err)
		}
		if i == 3 && !st.IsHardLockout {
			t.Fatalf("expected IsHardLockout on PIN attempt 3")
		}
	}

	// Reset
	if err := s.ResetCircuitBreaker(); err != nil {
		t.Fatalf("ResetCircuitBreaker failed: %v", err)
	}
	cb, _ = s.GetCircuitBreakerState()
	if cb.IsHardLockout || cb.IsPINChallenge || cb.MasterFailedAttempts != 0 || cb.PINFailedAttempts != 0 {
		t.Errorf("expected clean state after reset, got %+v", cb)
	}
}
