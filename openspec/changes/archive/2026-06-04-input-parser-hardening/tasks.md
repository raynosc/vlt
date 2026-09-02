# Tasks: input-parser-hardening

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~190 (additions + deletions) |
| 400-line budget risk | Low |
| Chained PRs recommended | No |
| Suggested split | Single PR |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: pending
400-line budget risk: Low

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | M7 + M5 + M6 (full change) | PR 1 | ~190 lines total; single PR fits budget |

---

## Commit Order

M7 → M5 → M6 (each commit self-contained; `go test ./...` passes after each)

---

## Phase 1: M7 RED — OTP digits validation tests (internal/otp/otp_test.go)

- [x] 1.1 **RED** — Add `TestGenerateHOTP_InvalidDigits_Zero`: call `GenerateHOTP` with `digits=0`; assert non-nil error and empty string. `go test ./internal/otp/...` MUST fail. (Spec: otp-generation § M7 — digits=0 returns error, not "0")
- [x] 1.2 **RED** — Add `TestGenerateHOTP_InvalidDigits_Negative`: call with `digits=-1`; assert non-nil error and no panic. (Spec: M7 — digits=-1 returns error, no panic)
- [x] 1.3 **RED** — Add `TestGenerateHOTP_InvalidDigits_TooHigh`: call with `digits=9`; assert non-nil error. (Spec: M7 — digits=9 returns error)
- [x] 1.4 **RED** — Add `TestGenerateHOTP_ValidDigits_Five`: call with `digits=5`; assert nil error and 5-character code. (Spec: M7 — digits=5 success)
- [x] 1.5 **RED** — Add `TestGenerateTOTP_InvalidDigits_Zero`, `TestGenerateTOTP_InvalidDigits_Negative`, `TestGenerateTOTP_InvalidDigits_TooHigh`, `TestGenerateTOTP_ValidDigits_Five` — mirror of 1.1–1.4 for TOTP. (Spec: otp-generation § M7 TOTP scenarios)
- [x] 1.6 **RED** — Add `TestTruncate_ShortHMAC`: construct a synthetic `hs` slice shorter than `offset+4`; call the unexported `truncate` via a test-exported wrapper or white-box test; assert no panic and a zero-padded fallback string is returned. (Spec: otp-generation § truncate bounds guard)

## Phase 2: M7 GREEN — OTP digits validation implementation (internal/otp/otp.go)

- [x] 2.1 Add constants `minDigits = 5` and `maxDigits = 8` at the top of `internal/otp/otp.go`, grouped with any existing constants.
- [x] 2.2 In `GenerateHOTP`: insert the validation block `if digits < minDigits || digits > maxDigits { return "", fmt.Errorf(...) }` after the `len(key) == 0` guard, before MAC computation. Exact error format: `"digits must be between %d and %d, got %d"`.
- [x] 2.3 In `GenerateTOTP`: insert identical validation block after the `len(key) == 0` guard, before counter computation.
- [x] 2.4 In `truncate`: insert as **first statement** the bounds guard `if len(hs) < int(hs[len(hs)-1]&0x0F)+4 { return fmt.Sprintf("%0*d", digits, 0) }`. No signature change — return type stays `string`.
- [x] 2.5 **GREEN check**: run `go test ./internal/otp/...`; all 1.1–1.6 tests MUST pass, existing tests MUST NOT regress.

## Phase 3: M7 REFACTOR

- [x] 3.1 Run `gofmt -w internal/otp/otp.go`; verify no diff.
- [x] 3.2 Run `golangci-lint run ./internal/otp/...`; fix any staticcheck findings.
- [x] 3.3 Commit: `fix(otp): validate digits range [5,8] in GenerateHOTP and GenerateTOTP`

---

## Phase 4: M5 RED — QR decode bomb-guard tests (internal/otp/qr_test.go)

- [x] 4.1 **RED** — Add `TestDecodeQR_OversizedBytes`: construct a `make([]byte, 6*1024*1024)` slice; call `DecodeQR`; assert non-nil error whose message contains `"too large"`. (Spec: qr-decode § M5 — byte-size cap rejects oversized payload)
- [x] 4.2 **RED** — Add `TestDecodeQR_OversizedDimensions`: encode a real 1×1 PNG using `image/png`; patch the IHDR width and height fields at byte offsets 16–19 (width) and 20–23 (height) to `0x00002711` (10000, big-endian uint32); recalculate the IHDR CRC at bytes 24–27; call `DecodeQR`; assert non-nil error whose message contains `"dimensions"`. **Note:** PNG IHDR CRC covers bytes 12–23 (chunk type + data); use `hash/crc32` with `crc32.IEEETable`. (Spec: qr-decode § M5 — dimension cap rejects decompression bomb)
- [x] 4.3 **RED** — Confirm `TestDecodeQR_Valid`, `TestDecodeQR_NoQR`, `TestDecodeQR_CorruptImage` still exist and still FAIL only because the new guards are not yet in place (not because tests broke). `go test ./internal/otp/...` MUST fail on 4.1 and 4.2 only.

## Phase 5: M5 GREEN — QR decode bomb-guard implementation (internal/otp/qr.go)

- [x] 5.1 Add constants `maxQRBytes = 5 * 1024 * 1024` and `maxQRDimension = 4096` at package level before `DecodeQR`. No new imports needed (`bytes`, `image`, `image/png`, `image/jpeg` already present).
- [x] 5.2 Replace the body of `DecodeQR` with the exact shape from design §M5: byte-length guard → `image.DecodeConfig(bytes.NewReader(data))` → dimension guard → `image.Decode(bytes.NewReader(data))` → bitmap + reader pipeline. Second `bytes.NewReader` call is intentional (reader consumed after `DecodeConfig`).
- [x] 5.3 **GREEN check**: run `go test ./internal/otp/...`; tests 4.1–4.2 MUST pass; regression tests 4.3 MUST pass.

## Phase 6: M5 REFACTOR

- [x] 6.1 Run `gofmt -w internal/otp/qr.go`; verify no diff.
- [x] 6.2 Run `golangci-lint run ./internal/otp/...`; fix any findings.
- [x] 6.3 Commit: `fix(otp): reject oversized QR images before decode`

---

## Phase 7: M6 RED — ZeroizePrivateKey tests (internal/crypto/zeroize_test.go + internal/parse/pkcs12_test.go)

- [x] 7.1 **RED** — In `internal/crypto/zeroize_test.go`: add `TestZeroizePrivateKey_Nil` — pass `nil`; assert no panic. (Spec: crypto-zeroize § Nil input is safe)
- [x] 7.2 **RED** — Add `TestZeroizePrivateKey_RSA`: generate a 2048-bit `*rsa.PrivateKey` via `rsa.GenerateKey`; call `ZeroizePrivateKey(key)`; assert `key.D.Sign() == 0` and `key.Precomputed.Dp.Sign() == 0`, `Dq.Sign() == 0`, `Qinv.Sign() == 0`. (Spec: crypto-zeroize § RSA key D is zeroed)
- [x] 7.3 **RED** — Add `TestZeroizePrivateKey_ECDSA`: generate `*ecdsa.PrivateKey` (P-256); call `ZeroizePrivateKey(key)`; assert `key.D.Sign() == 0`. (Spec: crypto-zeroize § ECDSA key D is zeroed)
- [x] 7.4 **RED** — Add `TestZeroizePrivateKey_Ed25519`: generate `ed25519.PrivateKey`; call `ZeroizePrivateKey(key)`; assert all bytes are `0x00`. (Spec: crypto-zeroize § Ed25519 key bytes are zeroed)
- [x] 7.5 **RED** — Add `TestZeroizePrivateKey_UnknownType`: pass `"not-a-key"` (string); assert no panic. (Spec: crypto-zeroize § Unknown type is ignored)
- [x] 7.6 **RED** — In `internal/parse/pkcs12_test.go`: add subtest `TestParsePKCS12_KeyZeroizedAfterReturn` — call `ParsePKCS12` with a valid P12 bundle; assert non-nil `Metadata`, nil error, and no panic (regression contract per design §M6). `go test ./internal/crypto/... ./internal/parse/...` MUST fail on 7.1–7.6.

## Phase 8: M6 GREEN — ZeroizePrivateKey implementation

- [x] 8.1 In `internal/crypto/zeroize.go`: add imports `crypto/ecdsa`, `crypto/ed25519`, `crypto/rsa`, `math/big`.
- [x] 8.2 Add the `zeroizeBigInt(b *big.Int)` helper using `b.SetBytes(make([]byte, (b.BitLen()+7)/8))`. Nil guard at top. No-op when `n == 0`.
- [x] 8.3 Add `ZeroizePrivateKey(key any)` with the exact switch from design §M6: `*rsa.PrivateKey` zeros D + Dp/Dq/Qinv (nil-check each precomputed field); `*ecdsa.PrivateKey` zeros D; `ed25519.PrivateKey` calls `clear(k)`. Unknown/nil: silent return.
- [x] 8.4 In `internal/parse/pkcs12.go` line 18: change `_, _, caCerts, err := pkcs12.DecodeChain(...)` to `privKey, _, caCerts, err := pkcs12.DecodeChain(...)`. Add `defer crypto.ZeroizePrivateKey(privKey)` immediately after the err-check block. Add import `"github.com/raynosc/vlt/internal/crypto"`.
- [x] 8.5 **GREEN check**: run `go test ./internal/crypto/... ./internal/parse/...`; all 7.1–7.6 tests MUST pass; existing pkcs12 subtests MUST NOT regress.

## Phase 9: M6 REFACTOR

- [x] 9.1 Run `gofmt -w internal/crypto/zeroize.go internal/parse/pkcs12.go`; verify no diff.
- [x] 9.2 Run `golangci-lint run ./internal/crypto/... ./internal/parse/...`; fix any findings.
- [x] 9.3 Commit: `fix(crypto): add ZeroizePrivateKey; defer key zeroization in ParsePKCS12`

---

## Phase 10: Integration Gate

- [x] 10.1 Run `go test ./...` from repo root; ALL packages MUST be green.
- [x] 10.2 Run `gofmt -l .`; output MUST be empty (no unformatted files).
- [x] 10.3 Run `golangci-lint run ./...` (mirrors CI "security" job: gofmt + staticcheck); zero findings.
- [x] 10.4 Verify no caller changes were needed: `grep -r "GenerateHOTP\|GenerateTOTP" internal/cli internal/tui internal/gui` — all existing call sites pass `6` or `8`; no updates required.
