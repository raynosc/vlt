package store

import (
	"fmt"
	"strconv"
)

// Circuit breaker config keys.
const (
	ConfigKeyPINHash              = "pin_hash"
	ConfigKeyPINSalt              = "pin_salt"
	ConfigKeyMasterFailedAttempts = "master_failed_attempts"
	ConfigKeyPINFailedAttempts    = "pin_failed_attempts"
	ConfigKeyHardLockout          = "hard_lockout"
	ConfigKeyRecoveryBlob         = "recovery_blob"
)

// CircuitBreakerState represents the current lockout & PIN challenge state of the vault.
type CircuitBreakerState struct {
	HasPIN               bool
	MasterFailedAttempts int
	PINFailedAttempts    int
	IsPINChallenge       bool // true if master failed attempts >= 3 and PIN is configured
	IsHardLockout        bool // true if hard_lockout is set or PIN failed attempts >= 3
}

// GetCircuitBreakerState loads the current circuit breaker status from config.
func (s *SQLStore) GetCircuitBreakerState() (*CircuitBreakerState, error) {
	state := &CircuitBreakerState{}

	pinHash, err := s.ConfigGet(ConfigKeyPINHash)
	state.HasPIN = (err == nil && len(pinHash) > 0)

	if val, err := s.ConfigGet(ConfigKeyMasterFailedAttempts); err == nil {
		if count, err := strconv.Atoi(string(val)); err == nil {
			state.MasterFailedAttempts = count
		}
	}

	if val, err := s.ConfigGet(ConfigKeyPINFailedAttempts); err == nil {
		if count, err := strconv.Atoi(string(val)); err == nil {
			state.PINFailedAttempts = count
		}
	}

	if val, err := s.ConfigGet(ConfigKeyHardLockout); err == nil && string(val) == "1" {
		state.IsHardLockout = true
	}

	if state.PINFailedAttempts >= 3 {
		state.IsHardLockout = true
	} else if state.MasterFailedAttempts >= 3 && state.HasPIN {
		state.IsPINChallenge = true
	}

	return state, nil
}

// RecordFailedMasterAttempt increments the failed master password counter and updates state.
func (s *SQLStore) RecordFailedMasterAttempt() (*CircuitBreakerState, error) {
	state, err := s.GetCircuitBreakerState()
	if err != nil {
		return nil, err
	}

	state.MasterFailedAttempts++
	_ = s.ConfigSet(ConfigKeyMasterFailedAttempts, []byte(strconv.Itoa(state.MasterFailedAttempts)))

	if state.MasterFailedAttempts >= 3 && state.HasPIN {
		state.IsPINChallenge = true
	}

	return state, nil
}

// RecordFailedPINAttempt increments the failed PIN counter and triggers hard lockout if >= 3.
func (s *SQLStore) RecordFailedPINAttempt() (*CircuitBreakerState, error) {
	state, err := s.GetCircuitBreakerState()
	if err != nil {
		return nil, err
	}

	state.PINFailedAttempts++
	_ = s.ConfigSet(ConfigKeyPINFailedAttempts, []byte(strconv.Itoa(state.PINFailedAttempts)))

	if state.PINFailedAttempts >= 3 {
		state.IsHardLockout = true
		_ = s.ConfigSet(ConfigKeyHardLockout, []byte("1"))
	}

	return state, nil
}

// ResetMasterAttempts clears the failed master password counter.
func (s *SQLStore) ResetMasterAttempts() error {
	return s.ConfigDelete(ConfigKeyMasterFailedAttempts)
}

// ResetCircuitBreaker resets all master/PIN attempt counters and hard lockout state.
func (s *SQLStore) ResetCircuitBreaker() error {
	_ = s.ConfigDelete(ConfigKeyMasterFailedAttempts)
	_ = s.ConfigDelete(ConfigKeyPINFailedAttempts)
	_ = s.ConfigDelete(ConfigKeyHardLockout)
	return nil
}

// SetPIN configures or updates the 8-digit PIN hash and salt in config.
func (s *SQLStore) SetPIN(hash, salt []byte) error {
	if len(hash) == 0 || len(salt) == 0 {
		return fmt.Errorf("hash and salt must not be empty")
	}
	if err := s.ConfigSet(ConfigKeyPINSalt, salt); err != nil {
		return fmt.Errorf("set pin salt: %w", err)
	}
	if err := s.ConfigSet(ConfigKeyPINHash, hash); err != nil {
		return fmt.Errorf("set pin hash: %w", err)
	}
	return nil
}

// RemovePIN deletes the PIN configuration from the vault.
func (s *SQLStore) RemovePIN() error {
	_ = s.ConfigDelete(ConfigKeyPINHash)
	_ = s.ConfigDelete(ConfigKeyPINSalt)
	_ = s.ConfigDelete(ConfigKeyPINFailedAttempts)
	return nil
}

// GetPINConfig retrieves the PIN hash and salt if configured.
func (s *SQLStore) GetPINConfig() (hash, salt []byte, err error) {
	hash, err = s.ConfigGet(ConfigKeyPINHash)
	if err != nil {
		return nil, nil, err
	}
	salt, err = s.ConfigGet(ConfigKeyPINSalt)
	if err != nil {
		return nil, nil, err
	}
	return hash, salt, nil
}
