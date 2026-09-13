## Description
<!-- Provide a concise explanation of what this PR introduces or fixes. -->

---

## Security Invariants Checklist (MANDATORY)
<!-- Every contributor (human or AI) MUST verify these items before requesting review. -->

- [ ] **Zero-Leakage**: Plaintext passwords, keys, or recovery words NEVER reach database columns, log messages, sync payloads, or CLI argument flags (`argv`).
- [ ] **Memory Sanitation**: Every buffer (`[]byte`) handling sensitive data is cleared via `defer crypto.Zeroize(slice)` or `crypto.Zeroize(slice)`.
- [ ] **Blind Indexing**: Queries strictly use HMAC-SHA256 blind indexing (`name_lookup`), never plaintext `WHERE name = ...`.
- [ ] **Platform Isolation**: Any OS-specific CGo API uses `//go:build <os>` with matching no-op stubs in `_other.go`.
- [ ] **Constant-Time Verification**: Secret or token comparisons use `subtle.ConstantTimeCompare`.
- [ ] **No Supply-Chain Risks**: No unnecessary external dependencies or hidden telemetry introduced.

---

## Local Verification Quality Gate

- [ ] `make check` passed locally with **0 lint errors** and **100% unit test pass**.
- [ ] Adversarial or Fuzz tests (`Fuzz*`) added or updated if parsing external input or envelopes.
- [ ] Cross-platform compilation passes (`make build` and `make build-windows`).

---

## PR Review Note
This repository enforces a **Strict Human-in-the-Loop** policy: AI agents and automated review bots are not permitted to approve or merge PRs autonomously. A human maintainer will perform the final review.
