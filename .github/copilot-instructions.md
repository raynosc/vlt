# GitHub Copilot & Codespaces Guidelines for `vlt`

Welcome to `vlt`. Follow these mandatory architectural and security invariants when generating or reviewing code:

1. **Memory Zeroization**: Plaintext passwords, derived keys, and private keys MUST be cleared using `crypto.Zeroize(...)` or `crypto.ZeroizePrivateKey(...)`.
2. **Schema v7 Blind Indexing**: Database stores only ciphertext. Secret names use HMAC-SHA256 blind indexing (`name_lookup`).
3. **Headless & Cross-Platform Safety**: Always include `//go:build darwin` for Carbon/CGo code and maintain no-op stubs in `_other.go` for Linux/Windows.
4. **Security-Oriented TDD**: Write adversarial and fuzz tests before writing implementations.
5. **Quality Gate**: Changes must pass `make check` (0 lint warnings, gosec security scan, and 100% test pass).
