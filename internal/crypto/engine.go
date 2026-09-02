// Package crypto provides all cryptographic operations for passwd.
//
// All operations are pure computation — no I/O, no network, no side effects.
// The package has ZERO dependencies on store, CLI, or TUI packages.
// All random values use crypto/rand exclusively.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// DefaultArgon2Params are the default Argon2id parameters.
// Time: 3 iterations, Memory: 64 MiB, Threads: 4.
var DefaultArgon2Params = Argon2Params{
	Time:    3,
	Memory:  64 * 1024, // 64 MiB in KiB
	Threads: 4,
}

// Argon2Params configures Argon2id key derivation.
type Argon2Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// Engine provides cryptographic operations.
// All methods are safe for concurrent use (no mutable state).
type Engine struct {
	params Argon2Params
}

// EngineOption configures an Engine via functional options.
type EngineOption func(*Argon2Params)

// WithTime sets the Argon2 time parameter.
func WithTime(time uint32) EngineOption {
	return func(p *Argon2Params) {
		p.Time = time
	}
}

// WithMemory sets the Argon2 memory parameter (in KiB).
func WithMemory(memory uint32) EngineOption {
	return func(p *Argon2Params) {
		p.Memory = memory
	}
}

// WithThreads sets the Argon2 threads parameter.
func WithThreads(threads uint8) EngineOption {
	return func(p *Argon2Params) {
		p.Threads = threads
	}
}

// NewEngine creates an Engine with the given parameters.
// If params is nil, DefaultArgon2Params is used.
// Additional options can be provided to override specific fields.
func NewEngine(params *Argon2Params, opts ...EngineOption) *Engine {
	p := DefaultArgon2Params
	if params != nil {
		p = *params
	}
	for _, opt := range opts {
		opt(&p)
	}
	return &Engine{params: p}
}

// DeriveKey derives a 256-bit key from a password and salt using Argon2id.
// password: the master password.
// salt: 16-byte random salt (generated once during init).
// Returns a 32-byte derived key.
func (e *Engine) DeriveKey(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password must not be empty")
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("salt must not be empty")
	}
	return argon2.IDKey(password, salt, e.params.Time, e.params.Memory, e.params.Threads, 32), nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// key must be 32 bytes (256-bit).
// Returns ciphertext (which includes the GCM authentication tag) and the nonce.
func (e *Engine) Encrypt(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("key must be 32 bytes")
	}
	if len(plaintext) == 0 {
		return nil, nil, fmt.Errorf("plaintext must not be empty")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("aes: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("gcm: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the given key and nonce.
// key must be 32 bytes (256-bit).
// ciphertext must include the GCM authentication tag (as returned by Encrypt).
func (e *Engine) Decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext must not be empty")
	}
	if len(nonce) == 0 {
		return nil, fmt.Errorf("nonce must not be empty")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed")
	}
	return plaintext, nil
}
