---
name: vlt-security-auditing
description: Security principles, memory sanitization, and Watchtower vulnerability auditing guidelines for vlt.
---

# vlt Security & Auditing Skill

This skill documents the security checklist and invariants required when contributing code or reviewing changes in `vlt`.

---

## 1. Memory Zeroization Checklist

Every function handling cryptographic keys, plaintext passwords, or raw recovery seeds MUST zeroize them upon completion:

```go
// Example pattern:
key := deriveKey(password, salt)
defer crypto.Zeroize(key)

val, err := readSecretFromStdin()
if err != nil {
    return err
}
defer crypto.Zeroize(val)
```

Never allow secrets to escape to garbage collection without active byte zeroization.

---

## 2. Watchtower Password Auditing (`internal/watchtower`)

Watchtower performs client-side security analysis:
* **Weak Passwords**: Entropy and length checks (<12 chars, low character diversity).
* **Reused Passwords**: Detected by comparing encrypted value equality or hashes without exposing plaintext.
* **Duplicate Secrets**: Exact matching across vault items.
* **Expiring Secrets**: Flagging certificates or tokens nearing expiration.

---

## 3. Cryptographic Invariants

* **KDF**: Argon2id with 64 MB memory, 3 iterations, 4 threads minimum.
* **Symmetric Encryption**: AES-256-GCM with unique 12-byte random nonces generated per encryption via `crypto/rand` and AAD validation.
* **Blind Indexing**: HMAC-SHA256 with key domain separation prefix (`"passwd.name."`).
* **Recovery Phrase**: 24-word BIP-39 mnemonic phrase derived from 256-bit vault master entropy.

## 4. Clipboard Security Invariants (S-06)

* **Detached Auto-Clear**: Clipboard copy spawns a detached subprocess (`vlt __clear-clipboard`) with a 30s timer that runs independently of parent lifecycle.
* **No Argv Exposure**: Sensitive secret payloads MUST be passed exclusively via `stdin` pipe to the child process, NEVER as command-line arguments (`argv`/`ps aux`).
* **Conditional Clear**: The auto-clear process checks if the clipboard still holds the exact copied secret before clearing, preserving user workflow if another string was copied.
* **Zeroize**: In-memory buffers are immediately cleared with `crypto.Zeroize` after copying.

---

## 5. Security-Oriented TDD Workflow (Sec-TDD)

When adding or modifying crypto, store, sync, or parsers:
1. **Red Test**:
   - Write unit tests targeting adversarial attacks (replay, bit-flipping, tampered auth tags, timing attacks).
   - Write memory zeroization assertions verifying target slices contain only `0x00`.
   - Write Fuzz test targets (`Fuzz*`) in `fuzz_test.go` with initial seed corpora.
2. **Green Code**:
   - Implement functionality ensuring constant-time comparisons (`subtle.ConstantTimeCompare`) and strict zeroization (`defer crypto.Zeroize(...)`).
3. **Verify Pipeline**:
   - `make check` (Lint + Gosec + Tests).
   - `make fuzz` (Fuzzing).
   - `make ci` (Race detector + Govulncheck).
