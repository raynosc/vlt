# Archive Report: input-parser-hardening

**Change**: input-parser-hardening  
**Archived**: 2026-06-04  
**Status**: Complete and merged to main  
**Project**: passwd  
**Artifact Store Mode**: hybrid (openspec + engram)

---

## Executive Summary

The input-parser-hardening change successfully closed three MEDIUM security-audit findings (M5, M6, M7) by hardening internal parsers against malicious input. PR #9 (commit 98e91cb) is merged to main with all 190 lines of code changes passing strict TDD (RED tests written first, implementation GREEN, REFACTOR cleanup). All test suites pass (`go test ./...` green), code is formatted (`gofmt` clean), and linting is zero-finding (`golangci-lint` passed). No public API breaking changes. CI bumped to Go 1.26.4 (GO-2026-5037/5039) and .gitleaks.toml added.

---

## What Shipped

### M5 — QR Decompression Bomb Guard
- Reject payloads exceeding 5 MB (`len(data) > 5*1024*1024`)
- Check image dimensions via `image.DecodeConfig` before full `image.Decode`
- Return error if dimensions exceed 4096×4096 (prevents OOM from crafted IHDR)
- Two sequential guards: byte-size check first (O(1)), then dimension check (header-only parse)
- Regression tests confirm valid images under limits still decode correctly
- Locus: `internal/otp/qr.go` (internal function, no compat impact)

### M6 — PKCS#12 Private Key Zeroization
- New `crypto.ZeroizePrivateKey(key any)` function with type-switch support:
  - `*rsa.PrivateKey`: zero D, Dp, Dq, Qinv via `big.Int.SetBytes(make(...))`
  - `*ecdsa.PrivateKey`: zero D
  - `ed25519.PrivateKey`: zero all bytes via `clear(k)`
  - Unknown/nil types: silent no-op
- `big.Int` zeroization is best-effort (documented Go runtime limitation; accepted per existing caveat)
- In `internal/parse/pkcs12.go`: capture private key from `pkcs12.DecodeChain`, `defer crypto.ZeroizePrivateKey(privKey)` immediately after error check
- `ParsePKCS12` signature unchanged (no breaking changes)
- Locus: `internal/crypto/zeroize.go` (new export), `internal/parse/pkcs12.go` (defer added)

### M7 — OTP Digits Validation
- Validate `digits` parameter in `[5, 8]` range in both `GenerateHOTP` and `GenerateTOTP`
- Return error (not silent breakage or panic) for `digits=0`, negative, or out-of-range
- Range [5, 8] is correct per RFC 4226; Steam compatibility requires digits=5
- Add bounds guard in `truncate` function: `if len(hs) < offset+4 { return zero-padded string }`
  (future-proof only; not reachable with current SHA1/256/512 algorithms)
- All existing callers pass 6 or 8 (from URI parsing or literals) — no runtime breakage
- Locus: `internal/otp/otp.go` (public function behavior tightened; signature unchanged)

---

## Code Changes Summary

### Files Modified
| File | Type | Description |
|------|------|-------------|
| `internal/otp/otp.go` | Modified | Added digit validation + bounds guard in truncate |
| `internal/otp/qr.go` | Modified | Added byte-size and dimension guards in DecodeQR |
| `internal/crypto/zeroize.go` | Modified | Added ZeroizePrivateKey function and zeroizeBigInt helper |
| `internal/parse/pkcs12.go` | Modified | Capture and defer ZeroizePrivateKey for discarded key |
| `internal/otp/otp_test.go` | Modified | Added RED tests for digit validation + bounds guard |
| `internal/otp/qr_test.go` | Modified | Added RED tests for byte-size and dimension guards |
| `internal/crypto/zeroize_test.go` | Modified | Added RED tests for ZeroizePrivateKey variants |
| `internal/parse/pkcs12_test.go` | Modified | Added regression test for key zeroization |

**Total changed lines**: ~190 (additions + deletions) — well under 400-line review budget.

### Commits (in order)
1. `fix(otp): validate digits range [5,8] in GenerateHOTP and GenerateTOTP` (M7)
2. `fix(otp): reject oversized QR images before decode` (M5)
3. `fix(crypto): add ZeroizePrivateKey; defer key zeroization in ParsePKCS12` (M6)

Each commit is self-contained and passes `go test ./...` independently.

---

## Merged Delta Specs

Delta specs were copied to main specs under `openspec/specs/` (all NEW specs, no existing mains to merge):

| Domain | File | Type | Details |
|--------|------|------|---------|
| qr-decode | `openspec/specs/qr-decode/spec.md` | NEW | M5 byte-size and dimension guard requirements |
| otp-generation | `openspec/specs/otp-generation/spec.md` | NEW | M7 digit validation and truncate bounds guard requirements |
| crypto-zeroize-private-key | `openspec/specs/crypto-zeroize-private-key/spec.md` | NEW | M6 ZeroizePrivateKey and ParsePKCS12 integration requirements |

---

## Artifacts Archived

Archive folder: `openspec/changes/archive/2026-06-04-input-parser-hardening/`

Contents:
- `proposal.md` ✅ — Change intent, scope, approach, risk assessment
- `exploration.md` ✅ — Pre-design findings per M5/M6/M7
- `design.md` ✅ — Architecture decisions (3 ADRs), detailed per-item design specs
- `tasks.md` ✅ — 30 tasks across 3 fixes; all [x] marked complete
- `specs/qr-decode/spec.md` ✅ — Delta spec (copied to main)
- `specs/otp-generation/spec.md` ✅ — Delta spec (copied to main)
- `specs/crypto-zeroize-private-key/spec.md` ✅ — Delta spec (copied to main)

---

## Test Results

- **Strict TDD**: RED tests written first, implementation GREEN, REFACTOR cleanup
- **Test framework**: Pure Go (`testing` + `crypto/*` stdlib); no external test dependencies
- **Coverage**: 
  - M7: digit validation (zero, negative, out-of-range, valid 5/6/8) + truncate bounds guard
  - M5: byte-size cap (6 MB payload) + dimension cap (synthetic 10000×10000 PNG) + regression tests (normal images still work)
  - M6: ZeroizePrivateKey for nil/RSA/ECDSA/Ed25519/unknown types + ParsePKCS12 regression (metadata still correct)
- **Final gate**: 
  - `go test ./...` — all green from repo root
  - `gofmt -l .` — no unformatted files
  - `golangci-lint run ./...` — zero findings (mirrors CI "security" job)
  - No caller changes needed (all existing call sites pass 6 or 8)

---

## Merged PR

| PR | Title | Commits | Lines Changed |
|----|-------|---------|--------|
| #9 | fix(security): input-parser hardening (M5/M6/M7) | M7, M5, M6 | ~190 |

Merged to main at commit 98e91cb. All audit findings closed. CI upgrade: Go 1.26.4 (GO-2026-5037/5039). Config: .gitleaks.toml added.

---

## Known Limitations and Accepted Risks

| Item | Caveat | Mitigation |
|------|--------|-----------|
| M6 `big.Int` zeroization is best-effort | Go GC may move backing arrays after reallocation; we cannot guarantee the original bytes are overwritten in all cases | Document in code comment; accepted per existing `zeroize.go` caveat; consistent with project security posture |
| M5 covers only stdlib PNG/JPEG | Non-stdlib image formats (WEBP, BMP) are not guarded | Out of scope for this PR; note in code comment; can be extended in future if needed |
| M6 does not zero `rsa.PrecomputedValues.CRTValues` | Multi-prime RSA (rare) has additional precomputed values not zeroed | Single-prime RSA (standard) is fully covered; CRTValues is out of scope |
| M7 range [5,8] rejects digits=9 | Outside RFC 4226 spec | Correct and intentional; no current caller uses 9 |

---

## Backward Compatibility

| Change | Compat Impact | Notes |
|--------|---------------|-------|
| M7 digit validation | Zero | Public signature `(string, error)` unchanged; all callers pass 6 or 8 (verified in exploration); new error path is valid in error-handling code already present |
| M5 DecodeQR guards | Zero | DecodeQR is internal; no external callers |
| M6 ZeroizePrivateKey | Zero | New exported function; ParsePKCS12 signature unchanged |
| CI Go version | Info | Bumped to 1.26.4 per GO-2026-5037/5039 |

No public API breaking changes. No database schema changes. No configuration changes. Rollback is a single `git revert`.

---

## Sign-Off Checklist

- [x] Proposal reviewed and accepted
- [x] Spec deltas created (3 new domain specs)
- [x] Design completed (3 ADRs documented)
- [x] Tasks completed (30 tasks, all [x] marked)
- [x] RED tests written first; all failing per spec
- [x] GREEN implementation complete; all tests pass
- [x] REFACTOR cleanup done; gofmt and golangci-lint passed
- [x] PR #9 merged to main (commit 98e91cb)
- [x] Integration tests green (`go test ./...` from repo root)
- [x] Build clean (`go build ./...`)
- [x] Code review passed (HIGH finding fixed during review: RSA primes unzeroed — now covered)
- [x] Delta specs merged into `openspec/specs/` (new domains)
- [x] Archive folder created and change moved

---

## SDD Cycle Complete

The input-parser-hardening change is now fully planned, implemented, verified, and archived. All three MEDIUM audit findings (M5, M6, M7) are closed. Ready for the next SDD change.
