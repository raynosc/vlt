# Contributing to `vlt`

Welcome! `vlt` is an open-source, local-first, zero-knowledge secrets and password manager written in Go.
We warmly welcome contributions from human engineers and AI-assisted contributors alike.

Because `vlt` safeguards sensitive cryptographic keys and credentials, all contributions must strictly adhere to our non-negotiable architectural and security invariants.

---

## 1. AI Agent & Contributor Manifesto

If you are using an AI coding assistant (Codex, Cursor, Claude Code, GitHub Copilot, Windsurf, Cline, Antigravity, etc.):
1. **The Human Maintainer Leads**: AI assistants execute, but the contributor is 100% accountable for the code submitted.
2. **Read the Repository Manifests First**: Ensure your agent reads [AGENTS.md](AGENTS.md) or [CLAUDE.md](CLAUDE.md) before proposing changes.
3. **No Unverified Claims**: Never assume behavior or accept AI hallucinations without writing verifying tests.
4. **Conventional Commits Only**: Use conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`). Never add "Co-Authored-By" or AI attribution trailers.

---

## 2. Core Security Invariants (NON-NEGOTIABLE)

Every Pull Request is audited against these 5 foundational invariants:

1. **Zeroization of Sensitive Memory**:
   - Every slice (`[]byte`) containing plaintext passwords, derived keys, or recovery words must be zeroized immediately after use:
     ```go
     key := deriveKey(password, salt)
     defer crypto.Zeroize(key)
     ```
2. **Schema v7 Blind Indexing**:
   - Secret names, notes, and metadata are stored exclusively encrypted in SQLite.
   - Exact lookups use HMAC-SHA256 blind indexing (`name_lookup = HMAC-SHA256(masterKey, "passwd.name." + name)`).
   - **Never** write queries matching plaintext names (e.g. `WHERE name = ?` is strictly forbidden).
3. **Cross-Platform Isolation (`//go:build`)**:
   - Any OS-specific CGo implementation (such as macOS Carbon hotkeys) must have `//go:build darwin` on both source and test files.
   - You must always provide a no-op fallback stub (`_other.go`) for Linux and Windows so headless CI environments never fail.
4. **Zero Knowledge in Sync**:
   - Network sync payloads (`SyncPayload`) are encrypted client-side with AES-256-GCM + AAD before transmission.
   - The sync server is blind: it only receives ciphertext blobs, sequence numbers (`seq`), and blind key hashes.
5. **No Credential Leaks in Process Tables**:
   - Passwords and secrets must **never** be passed as CLI flags (`argv`). Use stdin pipes or interactive masked prompts.

---

## 3. Development Workflow (Sec-TDD)

We practice **Security-Oriented Test-Driven Development (Sec-TDD)**:

```
1. RED: Write failing adversarial tests (fuzz targets, zeroization assertions, malformed envelopes).
2. GREEN: Implement the minimum secure code to satisfy invariants.
3. VERIFY: Run the mandatory local quality gate before pushing.
```

### Essential Local Commands

```bash
# Mandatory quality gate (format + vet + golangci-lint + gosec + unit tests)
make check

# Security AST scanner
make sec

# Dependency & Go runtime vulnerability scanner
make vuln

# Mutation fuzz testing suite
make fuzz

# Full CI with race detector
make ci

# Build all local platform binaries into bin/
make build

# Cross-compile for Windows
make build-windows
```

> [!IMPORTANT]
> A Pull Request will not be merged if `make check` reports even a single lint warning or failing test.

---

## 4. Pull Request Submission

When opening a Pull Request:
1. Ensure your branch is rebased on `main`.
2. Fill out the [Pull Request Template](.github/pull_request_template.md) and check every box in the Security Checklist.
3. A maintainer will review your code. Note that all PR reviews follow a **Human-in-the-Loop** model: automated bots and agents are never permitted to autonomously merge code into `main`.

Thank you for helping keep `vlt` safe, fast, and resilient!
