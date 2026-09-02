# Proposal: input-parser-hardening

## Intent

Harden three internal parsers against MEDIUM findings from the security audit (M5/M6/M7).
The threat model is malicious-input files — crafted QR images, hostile PKCS#12 bundles — and
unsafe library callers that pass out-of-range arguments to the public OTP API.
These findings are independent, low-complexity, and fit a single surgical PR (~190 lines).
Fixing them now prevents OOM crashes, memory disclosure, and silent wrong output in the
production CLI.

## Scope

### In Scope

- **M5**: `internal/otp/qr.go` — reject `len(data) > 5 MB` before decode; use
  `image.DecodeConfig` to reject dimensions `> 4096×4096` before `image.Decode`.
- **M6**: `internal/crypto/zeroize.go` — new `ZeroizePrivateKey(key any)` with type-switch for
  `*rsa.PrivateKey`, `*ecdsa.PrivateKey`, `ed25519.PrivateKey`; `internal/parse/pkcs12.go` —
  capture returned private key and `defer crypto.ZeroizePrivateKey(privKey)`.
- **M7**: `internal/otp/otp.go` — validate `digits` in `[5, 8]` in `GenerateHOTP` /
  `GenerateTOTP`; add `len(hs) < offset+4` bounds guard in `truncate` (future-proofing).
- RED → GREEN → refactor test cycle for all three fixes (`strict TDD` active).

### Out of Scope

- Other audit findings: H5, M2, M3, M4, all lows.
- Changing `ParsePKCS12`, `GenerateHOTP`, or `GenerateTOTP` public signatures beyond the
  validation that is already present via their existing `error` returns.
- Non-stdlib image formats for M5.
- Zeroizing keys returned to callers (M6 only covers the discarded key in `pkcs12.go`).

## Capabilities

### New Capabilities

- `crypto-zeroize-private-key`: `ZeroizePrivateKey(any)` — extends existing zeroize API to cover
  RSA/ECDSA/ed25519 private keys.

### Modified Capabilities

- `otp-generation`: `GenerateHOTP` / `GenerateTOTP` now return `error` for out-of-range `digits`
  (signatures already return `error`; behavior change only).
- `qr-decode`: `DecodeQR` now enforces byte-size and dimension caps before delegating to
  `image.Decode`.

## Approach

All three fixes are surgical, contained within existing internal packages, and require no new
dependencies.

**M7 first** (highest risk, cheapest fix): input validation at the top of `GenerateHOTP` /
`GenerateTOTP`. Calibration note: the index-OOB in `truncate` is not reachable today
(SHA1/256/512 produce ≥ 20 bytes; max offset 15 reads index 18 max — safe). The bounds guard is
future-proof only. The real bugs are `digits=0 → "0"` and `digits<0 → divide-by-zero`. Valid
range is `[5, 8]` — must include 5 (Steam uses it via `GenerateSteamCode`). Do NOT narrow to 6/8.

**M5 second**: two-step guard in `DecodeQR` — byte cap then `DecodeConfig` dimension check. No
compat impact (`DecodeQR` is internal).

**M6 third** (touches two packages): add `ZeroizePrivateKey` in `crypto/zeroize.go` then `defer`
it in `pkcs12.go`. `big.Int` zeroize is best-effort (Go runtime may keep a reallocated backing
array) — use `D.SetBytes(make([]byte, len))` rather than `SetInt64(0)`. This is consistent with
the existing `zeroize.go` best-effort caveat and must be documented in a code comment.

Commit order: `M7 → M5 → M6`. Single PR `fix(security): input-parser hardening (M5/M6/M7)`.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `internal/otp/otp.go` | Modified | digits validation in `GenerateHOTP`/`GenerateTOTP`; bounds guard in `truncate` |
| `internal/otp/qr.go` | Modified | byte-size cap + `image.DecodeConfig` dimension cap in `DecodeQR` |
| `internal/parse/pkcs12.go` | Modified | capture + `defer ZeroizePrivateKey` for discarded private key |
| `internal/crypto/zeroize.go` | Modified | new `ZeroizePrivateKey(any)` function |
| `internal/otp/otp_test.go` | Modified | RED tests: invalid digits (0, neg, 9); valid (5, 6, 8) |
| `internal/otp/qr_test.go` | Modified | RED tests: oversized bytes; oversized dimensions |
| `internal/parse/pkcs12_test.go` | Modified | regression test: key discarded after `ParsePKCS12` |
| `internal/crypto/zeroize_test.go` | Modified | RED tests: `ZeroizePrivateKey_{RSA,ECDSA,Ed25519,Nil}` |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| M6 `big.Int` zeroize is best-effort | Certain (known Go limitation) | Document in code comment; accepted per existing `zeroize.go` caveat |
| M5 `DecodeConfig` guard covers stdlib only | Low | Out of scope for this PR; note in code comment |
| M7 range `[5,8]` rejects `digits=9` | Intended | Correct per RFC 4226; no current caller uses 9 |
| Existing callers broken by M7 error | Very Low | All callers pass 6 or 8 — verified in exploration |

## Rollback Plan

All changes are isolated to four internal files. Rolling back is a single `git revert` of the M5,
M6, M7 commits (or the squash). No schema, wire, or public API change — callers are unaffected.
No migration needed.

## Dependencies

- None. All fixes use the Go standard library only.

## Success Criteria

- [ ] `go test ./...` passes (strict TDD — RED tests written first, then implementation).
- [ ] `DecodeQR` returns an error (not OOM) for a 6 MB payload and a synthetic 10000×10000 header.
- [ ] `GenerateHOTP(0, …)` / `GenerateTOTP(0, …)` return an error, not `"0"`.
- [ ] `GenerateHOTP(-1, …)` does not panic.
- [ ] `ZeroizePrivateKey` zeroes the `D` field of an RSA and ECDSA key; handles `nil` safely.
- [ ] `ParsePKCS12` regression test passes.
- [ ] PR diff ≤ 400 lines (forecast ~190).
