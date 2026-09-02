# Exploration — input-parser-hardening

Three security-audit MEDIUM findings on untrusted-input parsers. Surgical, low-risk, ~190 lines, fits ONE PR. Pure-Go tests, STRICT TDD. No overlap with active changes.

## M5 — QR decompression bomb (OOM)

**Locus:** `internal/otp/qr.go:19`. Call path: `vlt import <file> --qr` → `cli/import.go:357 otp.DecodeQR(data)` → `image.Decode` with **no dimension cap** → a crafted image (huge IHDR) allocates the full pixel buffer and OOMs. `image.DecodeConfig` (header only) is not used.

**Recommended (Option C):** reject `len(data) > 5MB`, then `image.DecodeConfig` to reject `> 4096×4096` before the full `Decode`. `DecodeQR` is internal — no compat impact.

**RED tests (`qr_test.go`):** oversized dimensions (synthetic 10000×10000 → error, not OOM); oversized bytes (6MB → error before decode).

## M6 — PKCS#12 private key not zeroized

**Locus:** `internal/parse/pkcs12.go:18`. `pkcs12.DecodeChain` returns `(privateKey interface{}, cert, caCerts, err)`; the key is discarded with `_` and lingers in the heap until GC. `crypto.Zeroize` exists but only handles `[]byte`.

**Recommended (Option B):** add `crypto.ZeroizePrivateKey(key any)` in `internal/crypto/zeroize.go` with a type-switch — `*rsa.PrivateKey` (zero `D` + `Precomputed` Dp/Dq/Qinv), `*ecdsa.PrivateKey` (zero `D`), `ed25519.PrivateKey` (`[]byte`). In `pkcs12.go`, capture the key and `defer crypto.ZeroizePrivateKey(privKey)`. `ParsePKCS12` signature unchanged.

**Gotcha:** `big.Int` zeroize is best-effort — a re-allocated backing array may persist (documented Go runtime limitation, consistent with the existing `zeroize.go` caveat). Prefer `D.SetBytes(make([]byte, len))` over `SetInt64(0)`.

**RED tests:** `ZeroizePrivateKey_{RSA,ECDSA,Ed25519,Nil}`; `ParsePKCS12` regression.

## M7 — OTP digits not validated in the public API

**Locus:** `internal/otp/otp.go` — `GenerateHOTP:29`, `GenerateTOTP:50`, `truncate:77`. The public functions take `digits int` unvalidated:
- `digits=0` → `code % math.Pow10(0)=1` → always `"0"` (silently broken).
- `digits<0` → `int(math.Pow10(-1))=0` → **divide-by-zero panic**.
- Short-hash index-OOB in `truncate`: **not reachable** with current algos (SHA1/256/512 ≥ 20 bytes, offset max 15 reads up to index 18 — safe). Future-only risk.

**Gotcha:** valid range is **[5, 8]** — Steam uses `digits=5` (`uri.go:69`) but via `GenerateSteamCode` (`steam.go`), NOT `truncate`; `otpauth://` URIs accept only 6/8 (`uri.go:104`). Do NOT restrict to 6/8 only.

**Recommended (Option C):** validate `digits < 5 || digits > 8` → `error` in both public functions; add a `len(hs) < offset+4` bounds guard in `truncate` (future-proof). Existing callers always pass 6 or 8 — no breaking change.

**RED tests (`otp_test.go`):** zero/negative digits → error (not `"0"`/panic), HOTP+TOTP; `digits=9` → error; `digits=5/6/8` → success.

## Affected files
`internal/otp/qr.go`, `internal/otp/otp.go`, `internal/parse/pkcs12.go`, `internal/crypto/zeroize.go` (+ `qr_test.go`, `otp_test.go`, `parse_test.go`, `zeroize_test.go`).

## Delivery
Single PR `fix(security): input-parser hardening (M5/M6/M7)`, ~190 lines (< 400 budget). Commit order if split: M7 → M5 → M6 (M6 touches `crypto/` + `parse/`).

## Risks
- M6 `big.Int` zeroize is best-effort (Go runtime limitation, accepted).
- M5 `DecodeConfig` guard covers stdlib PNG/JPEG; non-stdlib formats would need extension.
- M7 range [5,8] rejects `digits=9` (outside RFC 4226) — correct, conservative.
