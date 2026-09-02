# Design — input-parser-hardening

## Status

Ready for tasks. Commit order: M7 → M5 → M6.

---

## ADR-01: `truncate` stays `func truncate(hs []byte, digits int) string` — no signature change

**Decision:** `truncate` keeps its current `string` return. A bounds guard is added internally
but no error is surfaced to callers.

**Rationale:** `truncate` is package-private and called only after `GenerateHOTP` /
`GenerateTOTP` have already validated `digits`. The index-OOB risk is future-only (SHA1/256/512
all produce ≥ 20 bytes; `offset = hs[len(hs)-1] & 0x0F` caps at 15, reading at most index 18 —
always safe with current algorithms). Changing `truncate` to `(string, error)` would require
propagating the change through both public functions and their call sites with zero observable
benefit today. The internal guard is cheap insurance.

**Rejected alternative:** change `truncate` to `(string, error)` and bubble it up. Adds churn
to `GenerateHOTP`, `GenerateTOTP`, and every caller (3 production call sites) with no bug being
fixed in practice.

---

## ADR-02: `ZeroizePrivateKey` uses `SetBytes(make(…))` not `SetInt64(0)` for `big.Int` fields

**Decision:** RSA/ECDSA `big.Int` sensitive fields are zeroed via
`D.SetBytes(make([]byte, (D.BitLen()+7)/8))` rather than `D.SetInt64(0)`.

**Rationale:** `SetInt64(0)` may internally allocate a new one-word backing array, leaving the
original bytes in memory until GC collects it. `SetBytes` overwrites the existing backing array
in-place (when the new slice is the same length), maximising the chance of clearing the actual
sensitive bits. This matches the best-effort caveat already documented in `zeroize.go` — the GC
may still move heap objects, but we do not make things worse with a reallocation.

**Rejected alternative:** `SetInt64(0)`. Cheaper but provably reallocates a new backing word.

---

## ADR-03: `DecodeQR` byte-size check precedes `DecodeConfig` — two sequential guards

**Decision:** byte-length check comes first (pure slice-length comparison, zero allocation),
then `image.DecodeConfig` (parses header only), then `image.Decode` (full decode). Both guards
live at the top of `DecodeQR` before any other logic.

**Rationale:** The byte check is O(1) and catches payloads that are too large before we even
open a reader. The dimension check is the second line of defense for crafted images with a
legitimate byte size but a malicious IHDR (e.g., a valid 4 MB PNG with a 50000×50000 header).
Order matters: do cheap first.

**Rejected alternative:** dimension check only (skip byte cap). An attacker could craft a
multi-GB stream that passes the dimension check before OOMing during decode.

---

## M7 — `internal/otp/otp.go`: digits validation

### Constants (add at top of file, grouped with existing constants)

```go
const (
    minDigits = 5
    maxDigits = 8
)
```

### Validation block — exact insertion point

In `GenerateHOTP`, insert **after** the `len(key) == 0` guard, **before** the MAC computation:

```go
if digits < minDigits || digits > maxDigits {
    return "", fmt.Errorf("digits must be between %d and %d, got %d", minDigits, maxDigits, digits)
}
```

In `GenerateTOTP`, insert at the same relative position — after the `len(key) == 0` guard,
before the `counter` computation:

```go
if digits < minDigits || digits > maxDigits {
    return "", fmt.Errorf("digits must be between %d and %d, got %d", minDigits, maxDigits, digits)
}
```

### `truncate` internal bounds guard — exact insertion point

Insert as the **first statement** in `truncate`, before the `offset` computation:

```go
if len(hs) < int(hs[len(hs)-1]&0x0F)+4 {
    // This cannot happen with SHA1/256/512 but guards future algorithm additions.
    return fmt.Sprintf("%0*d", digits, 0)
}
```

Note: the fallback returns a zero-padded string of the correct width rather than panicking.
This matches the defensive intent without surfacing an error from a private function.

### Caller impact

`truncate` signature is **unchanged**. The following production callers of `GenerateHOTP` /
`GenerateTOTP` must handle the new error path — they already do because both functions already
return `(string, error)`:

| File | Line (approx.) | Current behaviour |
|------|----------------|-------------------|
| `internal/cli/totp.go` | 130 | `code, err = otp.GenerateHOTP(…)` — `err` already checked |
| `internal/cli/totp.go` | 141 | `code, err = otp.GenerateTOTP(…)` — `err` already checked |
| `internal/tui/model.go` | 417 | `otp.GenerateTOTP(…)` — `err` already handled in `if err == nil` block |
| `internal/tui/detail.go` | 227 | `otp.GenerateTOTP(…)` — `err` already checked |
| `internal/gui/app.go` | 572 | `otp.GenerateTOTP(…, 6, …)` — `err` already checked; passes literal `6`, always valid |

All production callers pass `uri.Digits` (sourced from parsed `otpauth://` URIs which only accept
6 or 8 per `uri.go:104`) or the literal `6`. No caller will hit the new error at runtime.
The test suite at `internal/otp/otp_test.go` already calls with `digits=6` and `digits=8` — both
remain valid. The `digits=8` test vector in `TestGenerateHOTP_CustomDigits` continues to pass.

### Test additions (RED first — `internal/otp/otp_test.go`)

```
TestGenerateHOTP_InvalidDigits_Zero        → digits=0, expect non-nil error
TestGenerateHOTP_InvalidDigits_Negative    → digits=-1, expect non-nil error (no panic)
TestGenerateHOTP_InvalidDigits_TooHigh     → digits=9, expect non-nil error
TestGenerateHOTP_ValidDigits_Five          → digits=5, expect success
TestGenerateTOTP_InvalidDigits_Zero        → digits=0, expect non-nil error
TestGenerateTOTP_InvalidDigits_Negative    → digits=-1, expect non-nil error (no panic)
TestGenerateTOTP_InvalidDigits_TooHigh     → digits=9, expect non-nil error
TestGenerateTOTP_ValidDigits_Five          → digits=5, expect success
```

---

## M5 — `internal/otp/qr.go`: decompression-bomb guards

### Constants (add at package level, before `DecodeQR`)

```go
const (
    maxQRBytes     = 5 * 1024 * 1024 // 5 MB
    maxQRDimension = 4096            // pixels per side
)
```

### Import verification

`qr.go` already imports `_ "image/jpeg"` and `_ "image/png"` at lines 7–8. These blank imports
register the PNG and JPEG decoders into `image.RegisterFormat`, which is required for both
`image.DecodeConfig` and `image.Decode` to recognise those formats. **No new import is needed.**
`image` itself is already imported at line 6. `bytes` is already imported at line 4 (used for
`bytes.NewReader`).

### Exact code shape for `DecodeQR` (full function after patch)

```go
func DecodeQR(data []byte) (string, error) {
    if len(data) > maxQRBytes {
        return "", fmt.Errorf("image too large: %d bytes (max %d)", len(data), maxQRBytes)
    }

    cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
    if err != nil {
        return "", fmt.Errorf("unable to read image header: %w", err)
    }
    if cfg.Width > maxQRDimension || cfg.Height > maxQRDimension {
        return "", fmt.Errorf("image dimensions %dx%d exceed maximum %dx%d",
            cfg.Width, cfg.Height, maxQRDimension, maxQRDimension)
    }

    img, _, err := image.Decode(bytes.NewReader(data))
    if err != nil {
        return "", fmt.Errorf("unable to decode image: %w", err)
    }

    bmp, err := gozxing.NewBinaryBitmapFromImage(img)
    if err != nil {
        return "", fmt.Errorf("create bitmap: %w", err)
    }

    reader := qrcode.NewQRCodeReader()
    result, err := reader.Decode(bmp, nil)
    if err != nil {
        return "", fmt.Errorf("no QR code found: %w", err)
    }

    return result.GetText(), nil
}
```

Note: `bytes.NewReader(data)` is called **twice** — once for `DecodeConfig`, once for `Decode`.
This is intentional: `io.Reader` is consumed after `DecodeConfig` and cannot be rewound. A second
`NewReader` costs only a struct allocation (no copy of the underlying slice).

### Error messages (exact strings)

| Condition | Error string |
|-----------|-------------|
| byte limit exceeded | `"image too large: N bytes (max 5242880)"` |
| header decode failure | `"unable to read image header: <underlying>"` |
| dimension exceeded | `"image dimensions WxH exceed maximum 4096x4096"` |

### Test additions (RED first — `internal/otp/qr_test.go`)

```
TestDecodeQR_OversizedBytes
    Construct a 6 MB slice of zeros.
    Call DecodeQR; expect non-nil error containing "too large".

TestDecodeQR_OversizedDimensions
    Use image/png encoder to write a minimal valid PNG with a synthetic
    10000×10000 IHDR but zero pixel data (use image.NewNRGBA with a
    10000×10000 rect — but do NOT allocate a full pixel buffer; use
    image.NewGray with a 1×1 image and manually craft the PNG header bytes,
    OR use a helper that encodes a small image but with a falsified IHDR).
    Practical approach: encode a real 1×1 PNG, then patch the width/height
    bytes in the IHDR chunk (bytes 16–23 in a standard PNG stream).
    Call DecodeQR; expect non-nil error containing "dimensions".
```

The existing `TestDecodeQR_Valid`, `TestDecodeQR_NoQR`, and `TestDecodeQR_CorruptImage` continue
to pass without modification.

---

## M6 — `internal/crypto/zeroize.go` + `internal/parse/pkcs12.go`

### New function: `ZeroizePrivateKey`

**File:** `internal/crypto/zeroize.go`

**Required imports to add:** `crypto/ecdsa`, `crypto/ed25519`, `crypto/rsa`, `math/big`

**Exact function signature and body:**

```go
// ZeroizePrivateKey attempts to overwrite sensitive key material in a private key.
// Supported types: *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey.
// Unsupported or nil values are silently ignored.
//
// SECURITY NOTE: For RSA and ECDSA keys, the sensitive exponent is stored as a
// *big.Int. SetBytes overwrites the current backing array in-place (when the
// replacement slice has the same length), but the Go GC may have moved the
// original backing array before this call. Zeroization is therefore best-effort,
// consistent with the caveat documented for Zeroize above.
func ZeroizePrivateKey(key any) {
    if key == nil {
        return
    }
    switch k := key.(type) {
    case *rsa.PrivateKey:
        if k == nil {
            return
        }
        zeroizeBigInt(k.D)
        if k.Precomputed.Dp != nil {
            zeroizeBigInt(k.Precomputed.Dp)
        }
        if k.Precomputed.Dq != nil {
            zeroizeBigInt(k.Precomputed.Dq)
        }
        if k.Precomputed.Qinv != nil {
            zeroizeBigInt(k.Precomputed.Qinv)
        }
    case *ecdsa.PrivateKey:
        if k == nil {
            return
        }
        zeroizeBigInt(k.D)
    case ed25519.PrivateKey:
        clear(k) // ed25519.PrivateKey is []byte — clear uses Go 1.21 built-in
    }
}

// zeroizeBigInt overwrites the backing bytes of b in place.
// b must not be nil.
func zeroizeBigInt(b *big.Int) {
    if b == nil {
        return
    }
    n := (b.BitLen() + 7) / 8
    if n == 0 {
        return
    }
    b.SetBytes(make([]byte, n))
}
```

**RSA `Precomputed` fields being zeroed:**

The `rsa.PrecomputedValues` struct has fields `Dp`, `Dq`, `Qinv` (all `*big.Int`) plus
`CRTValues []CRTValue` for multi-prime RSA. Single-prime RSA (the common case) has
`CRTValues` as nil or empty. For M6 scope we zero the three named fields; `CRTValues` is
explicitly out of scope (rare, and each element's `Exp` / `Coeff` / `R` fields would require
iteration). This is documented in the code comment.

### Change in `internal/parse/pkcs12.go`

**Current line 18:**

```go
_, _, caCerts, err := pkcs12.DecodeChain(data, password)
```

**`pkcs12.DecodeChain` return tuple (verified from go-pkcs12 library):**

```
func DecodeChain(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error)
```

Position 0 is `privateKey interface{}`, position 1 is the leaf `*x509.Certificate` (currently
discarded with the second `_`), position 2 is `caCerts`.

**Patched version:**

```go
privKey, _, caCerts, err := pkcs12.DecodeChain(data, password)
if err != nil {
    if err == pkcs12.ErrIncorrectPassword {
        return nil, ErrWrongPassword
    }
    return nil, fmt.Errorf("corrupted PKCS12 data: %v", err)
}
defer crypto.ZeroizePrivateKey(privKey)
```

`defer` placement: immediately after the `err` check block, before the `certCount` calculation.
This ensures the key is zeroed when `ParsePKCS12` returns in ALL paths (success or any future
early returns added below this point). The `defer` fires after the return value is set.

**Required import to add in `pkcs12.go`:**

```go
"github.com/raynosc/vlt/internal/crypto"
```

### Test additions (RED first)

**`internal/crypto/zeroize_test.go`:**

```
TestZeroizePrivateKey_Nil             → pass nil, no panic
TestZeroizePrivateKey_RSA             → generate *rsa.PrivateKey, call ZeroizePrivateKey,
                                         assert k.D.Sign() == 0
TestZeroizePrivateKey_ECDSA           → generate *ecdsa.PrivateKey, call ZeroizePrivateKey,
                                         assert k.D.Sign() == 0
TestZeroizePrivateKey_Ed25519         → generate ed25519.PrivateKey, call ZeroizePrivateKey,
                                         assert all bytes are zero
TestZeroizePrivateKey_UnknownType     → pass a *rsa.PublicKey (not a private key type),
                                         expect no panic (silent ignore)
```

**`internal/parse/pkcs12_test.go` (regression):**

```
TestParsePKCS12_KeyZeroizedAfterReturn
    After ParsePKCS12 returns successfully, there is no direct handle to the
    private key to inspect. This test validates the regression contract:
    ParsePKCS12 must return (non-nil Metadata, nil error) for a valid bundle.
    The existing TestParsePKCS12/"valid bundle with correct password" subtest
    already covers this. A NEW subtest is added that calls ParsePKCS12 and
    verifies there is no panic and the returned Metadata is valid — ensuring
    the defer does not interfere with the return value.
```

---

## Commit ordering

```
fix(otp): validate digits range [5,8] in GenerateHOTP and GenerateTOTP (M7)
fix(otp): reject oversized QR images before decode (M5)
fix(crypto): add ZeroizePrivateKey; defer key zeroization in ParsePKCS12 (M6)
```

Each commit is self-contained and passes `go test ./...` independently.

---

## Backward-compat surface

| Change | Compat impact |
|--------|--------------|
| M7 digits validation | Zero. All callers pass 6 or 8 (literals or URI-sourced). The `(string, error)` signature is unchanged. |
| M5 `DecodeQR` guards | Zero. `DecodeQR` is `internal`; no external callers. |
| M6 `ZeroizePrivateKey` | Zero. New exported function; `ParsePKCS12` signature unchanged. |

---

## Test strategy summary

All three items follow strict TDD: RED tests are written and committed before any implementation
code is added.

| Item | Test file | RED cases | GREEN requires |
|------|-----------|-----------|----------------|
| M7 | `internal/otp/otp_test.go` | digits 0, -1, 9 → error; digits 5 → success | validation block in both public functions |
| M5 | `internal/otp/qr_test.go` | 6 MB slice → error; synthetic 10000×10000 PNG → error | byte cap + DecodeConfig guard |
| M6 | `internal/crypto/zeroize_test.go` + `internal/parse/pkcs12_test.go` | ZeroizePrivateKey for nil/RSA/ECDSA/Ed25519/unknown; ParsePKCS12 regression | ZeroizePrivateKey function + defer in pkcs12.go |

---

## Open risks

| Risk | Notes |
|------|-------|
| `big.Int` zeroize is best-effort | Go GC may move backing arrays. Accepted per existing `zeroize.go` caveat. Documented in code comment. |
| M5 covers only stdlib PNG/JPEG | Formats registered by `_ "image/jpeg"` and `_ "image/png"`. Non-stdlib formats (WEBP, BMP) are not guarded. Out of scope for this PR. |
| M6 does not zero `CRTValues` in multi-prime RSA | `rsa.PrecomputedValues.CRTValues` for 3+ prime RSA. Single-prime (standard) is fully covered. |
