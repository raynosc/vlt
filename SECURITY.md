# Security Policy

## Security Philosophy

`vlt` is built on a **zero-knowledge, local-first** architecture. All encryption and decryption operations occur strictly client-side. The local database and sync server store exclusively ciphertext, HMAC blind indexes, and encrypted blobs. 

We take vulnerability reports seriously and appreciate responsible disclosure.

---

## Supported Versions

Only the latest release receives active security patches and updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

Please **DO NOT** report security vulnerabilities via public GitHub issues, discussions, or social media.

### Preferred Method: Private Vulnerability Reporting (PVR)

Use GitHub's built-in **Private Vulnerability Reporting**:
1. Go to the [Security Advisories](https://github.com/raynosc/vlt/security/advisories) tab of this repository.
2. Click **"Report a vulnerability"** to submit your findings directly to the maintainers in an encrypted, private thread.

### Alternative Method: Email

If you cannot use GitHub Security Advisories, email:
- **Email**: `raynosc@gmail.com`
- **Subject**: `[SECURITY] Vulnerability report in vlt`

Please include:
- A clear description of the issue.
- Proof of Concept (PoC) or reproducible steps.
- The affected component (CLI, GUI, Sync server, Cryptographic primitive).
- Any potential impact or attack vector assessment.

---

## Disclosure Process

1. **Acknowledgment**: We will acknowledge receipt of your report within 48 hours.
2. **Investigation**: We will verify the issue, determine severity, and draft a remediation plan.
3. **Patch & Release**: A security release will be prepared and published alongside a Security Advisory crediting your discovery (unless you prefer anonymity).
