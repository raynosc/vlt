# CLAUDE.md — AI Agent & Developer Directives for `vlt`

Welcome to `vlt`, a production-grade, local-first, zero-knowledge secrets and password manager written in Go.
This file serves as the unified prompt contract for AI agents (Claude Code, Cursor, Copilot, Antigravity) and contributors.

---

## 1. Architectural & Security Invariants (NON-NEGOTIABLE)

1. **Zeroization of Sensitive Memory**:
   - Any buffer (`[]byte`) containing plaintext passwords, derived keys, or tokens MUST be zeroized immediately after use with `defer crypto.Zeroize(slice)` or `crypto.Zeroize(slice)`.
2. **Schema v7 Blind Indexing**:
   - Secret names, notes, and metadata are stored exclusively encrypted.
   - Exact queries use blind indexing: `name_lookup = HMAC-SHA256(masterKey, "passwd.name." + name)`.
   - Never query or store plaintext names in the database.
3. **Cross-Platform Isolation (`//go:build`)**:
   - Any OS-specific CGo API (such as macOS Carbon hotkeys) must have `//go:build darwin` on both implementation and test files.
   - Always maintain a matching no-op stub `_other.go` for Linux and Windows so headless CI runners never panic.
4. **Zero Knowledge in Sync**:
   - Sync payloads (`SyncPayload`) are encrypted client-side with AES-256-GCM + AAD using `sync_encryption_key`.
   - The sync server only sees ciphertext blobs, sequence numbers, and HMAC hashes.
5. **No Credential Leaks in Process Tables**:
   - Never accept or pass passwords as CLI argument flags (`argv`). Use stdin pipes or masked interactive prompts.

---

## 2. Security-Oriented TDD (Sec-TDD) Protocol

Before writing or editing code:
1. **Red (Adversarial Tests First)**:
   - Write unit tests that deliberately verify security invariants: buffer zeroization, timing-attack resistance (`subtle.ConstantTimeCompare`), circuit-breaker lockouts, and malformed inputs.
   - For all parsers and decoders, write or extend fuzz targets (`Fuzz*`).
2. **Green (Secure Implementation)**:
   - Write the minimum secure code necessary to satisfy all tests and invariants.
3. **Verify (Local Quality Gate)**:
   - Always run `make check` locally before finishing. It must report **0 lint errors** and **100% test pass**.

---

## 3. Essential Commands & Quality Gates

```bash
# Mandatory quality gate (format + vet + golangci-lint + gosec + tests)
make check

# Security AST scanner
make sec

# Dependency & Go runtime vulnerability scanner
make vuln

# Mutation fuzz testing suite
make fuzz

# Full CI with race detector
make ci

# Build all local binaries into bin/
make build

# Cross-compile for Windows (with MinGW GUI)
make build-windows
```

---

## 4. Skills & Deep Guides (`.agents/skills/`)

For specialized domain knowledge, consult the skills in `.agents/skills/`:
- [vlt-architecture](file:///.agents/skills/vlt-architecture/SKILL.md): Core cryptographic flow, SQLite schema v7, and GUI/TUI layers.
- [vlt-security-auditing](file:///.agents/skills/vlt-security-auditing/SKILL.md): Memory hygiene rules, sanitization, and Watchtower audits.
- [vlt-sync-ops](file:///.agents/skills/vlt-sync-ops/SKILL.md): `vlt-sync` server operations, mTLS PKI setup, and SSE events.

---

## 5. Mandatory PR Security Review Protocol (Human-in-the-Loop)

When evaluating or reviewing any Pull Request:
1. **Security First**: Verify zero-knowledge invariants (no plaintext in DB/logs/argv), strict memory zeroization (`crypto.Zeroize`), and safe dependencies.
2. **Functionality Second**: Verify `make check` passes with 0 lint errors and all unit tests green.
3. **Human Approval Required**: Always report the structured audit verdict to the human user first. **NEVER** approve, merge, close, or comment on the PR on GitHub without explicit user approval. Always STOP and await human confirmation.
