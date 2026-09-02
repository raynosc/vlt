# Security Policy

## Supported Versions

We release patches and security fixes for the latest version of `vlt` / `passwd`.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

---

## Zero-Knowledge & Security Architecture

`vlt` is built on a strict **Zero-Knowledge** model:
* **Client-Side Cryptography**: All encryption (AES-256-GCM + AAD) and key derivation (Argon2id) occur exclusively on your client device.
* **Blind Sync Server**: Remote servers store only ciphertext blobs, HMAC-SHA256 blind lookup indexes, and UUIDs. The server never receives master passwords, secret keys, or plaintext data.
* **RAM Sanitization**: Plaintext passwords, derived keys, and entropy buffers are explicitly overwritten in memory (`crypto.Zeroize`) after use.
* **Safe Clipboard**: Clipboard auto-clear subprocesses receive secrets exclusively via `stdin` pipe to prevent leaks in OS process tables (`argv`/`ps aux`).

---

## Reporting a Vulnerability

If you discover a security vulnerability or cryptographic weakness in `vlt`, please report it responsibly. **Do not create public GitHub issues for security vulnerabilities.**

### Preferred Method: GitHub Security Advisories
1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability** to open a private disclosure draft.

### Response Timeline
* **Initial Response**: Within 48 hours.
* **Assessment & Reproduction**: Within 7 business days.
* **Remediation & Patch Release**: Coordinated with the reporter before public disclosure.

---

## Security Verification & Continuous Auditing Pipeline

To guarantee the integrity of our Zero-Knowledge architecture, every commit and release must pass the following local and CI quality gates:

```bash
# 1. AST Security Analysis & Static Checks (gosec + golangci-lint + go vet)
make lint
make sec

# 2. Dependency Vulnerability Analysis (govulncheck)
make vuln

# 3. Dynamic Concurrency & Data Race Detector
make test-all

# 4. Fuzz Testing (Automated Mutation Testing for Parsers & Crypto Envelopes)
make fuzz

# 5. Full Quality Gate Suite
make check   # lint + sec + test
make ci      # lint + sec + vuln + test-all
```

We appreciate the security community's efforts in keeping `vlt` safe for everyone.
