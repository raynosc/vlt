# Design: OTP Support

## Technical Approach

Pure stdlib TOTP/HOTP generation in `internal/otp/` with zero I/O. URI parsing via regex. QR decode via gozxing, terminal QR via `skip2/go-qrcode` ASCII render. HOTP counter persisted in `PasswordMetadata.HOTPCounter` with a new `UpdateMetadata` store method. CLI `vlt totp` mirrors existing command patterns. TUI detail uses `tea.Tick` (same pattern as existing inactivity timer).

## Architecture Decisions

| Decision | Options | Choice | Rationale |
|----------|---------|--------|-----------|
| QR decode lib | gozxing, go-qrcode/v2 | gozxing | Mature pure-Go decoder, handles multiple formats (PNG/JPEG), Apache 2.0 |
| QR display lib | gozxing writer, skip2/go-qrcode, manual | `skip2/go-qrcode` | Built-in ASCII rendering, zero additional rendering code |
| HOTP counter storage | Config table, Metadata JSON field, New column | `PasswordMetadata.HOTPCounter` | No schema migration; keeps OTP state co-located with the URI |
| Store mutation for counter | Delete+Store, New `UpdateMetadata` | New `UpdateMetadata(name, metadata)` | Minimal interface addition, targeted SQL UPDATE, no re-encryption needed |
| URI parser | regexp, manual string split | `regexp` | Handles all URI variants with one pattern; Go stdlib, no deps |

## Data Flow

```
CLI: vlt totp <name>
  → GetByName(name)
  → UnmarshalPasswordMetadata → extract OTPAuth + HOTPCounter
  → otp.ParseURI(otpauth) → uri.OTPConf
  → otp.GenerateTOTP(secret, time) or otp.GenerateHOTP(secret, counter)
  → Store.UpdateMetadata(name, incrementedCounter)
  → Print code + remaining seconds

CLI: vlt import --qr <file>
  → os.ReadFile → otp.DecodeQR(bytes) → URI string
  → otp.ParseURI(uri) → extract label, secret
  → Encrypt + store as new secret with OTPAuth in Metadata

TUI: detail view with otpauth://
  → viewDetail() checks PasswordMetadata.OTPAuth != ""
  → Build OTP section with countdown bar
  → tea.Tick every 1s → updateDetail handles tick msg
  → On state change (backToList): ticker cancelled via tea.Batch
```

### OTP Package Internals

```
otp.GenerateTOTP(secret []byte, t time.Time, opts Options) (string, error)
otp.GenerateHOTP(secret []byte, counter uint64, opts Options) (string, error)
otp.ParseURI(raw string) (*OTPConf, error)
otp.DecodeQR(data []byte) (string, error)
otp.QRDisplay(uri string) (string, error)   ← ASCII QR string

type OTPConf struct {
    Type      string // totp, hotp
    Secret    []byte // decoded base32
    Issuer    string
    Account   string
    Digits    int    // default 6
    Period    int    // default 30
    Algorithm string // SHA1, SHA256, SHA512
    Counter   uint64 // for hotp
    IsSteam   bool
}
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `internal/otp/otp.go` | Create | `GenerateTOTP`, `GenerateHOTP`, `Options`, Steam alphabet |
| `internal/otp/uri.go` | Create | `ParseURI`, `OTPConf`, regex patterns for otpauth/duo/steam |
| `internal/otp/qr.go` | Create | `DecodeQR` (gozxing), `QRDisplay` (skip2/go-qrcode) |
| `internal/otp/otp_test.go` | Create | RFC 4226/6238 test vectors, URI round-trips |
| `internal/cli/totp.go` | Create | `newTotpCmd`, `runTotp`, --clipboard flag |
| `internal/cli/root.go` | Modify | Add `root.AddCommand(newTotpCmd())` |
| `internal/cli/import.go` | Modify | Add `--qr` flag, QR decode path in `runImport` |
| `internal/tui/detail.go` | Modify | OTP section in `viewDetail`, ticker in `updateDetail` |
| `internal/tui/model.go` | Modify | Add `otpCode`, `otpCountdown`, `otpPeriod` fields |
| `internal/secret/secret.go` | Modify | Add `HOTPCounter uint64` to `PasswordMetadata` |
| `internal/store/store.go` | Modify | Add `UpdateMetadata(name, metadata string) error` to `Store` interface |
| `go.mod` | Modify | Add `github.com/makiuchi-d/gozxing`, `github.com/skip2/go-qrcode` |

## Interfaces / Contracts

```go
// Additions to store.Store interface:
UpdateMetadata(name, metadata string) error

// New type in internal/secret:
type PasswordMetadata struct {
    URL         string `json:"url,omitempty"`
    Username    string `json:"username,omitempty"`
    OTPAuth     string `json:"otpauth,omitempty"`
    HOTPCounter uint64 `json:"hotp_counter,omitempty"`  // NEW
}
```

The store's `UpdateMetadata` issues: `UPDATE secrets SET metadata = ?, updated_at = datetime('now') WHERE name = ?`. No re-encryption, no key needed.

## Testing Strategy (STRICT TDD)

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit — otp | TOTP with RFC 6238 test vectors, HOTP with RFC 4226 App D, Steam alphabet, URI parse all 3 formats, edge cases (base32 padding, custom digits) | Pure function tests, no mocks |
| Unit — qr | QR decode valid/corrupt/no-qr images, QR display string length > 0 | File-based test fixtures for images |
| CLI — totp | Secret with otpauth://, unknown secret, no OTP URI, --clipboard flag | `mockStore` + `executeCmd` pattern from existing `cli_test.go` |
| CLI — import --qr | Valid QR image, no QR, corrupt image | File-based test fixtures |
| TUI — detail | OTP section shown/hidden, ticker lifecycle, countdown expiry | `mockStore` with OTP metadata, `newTestModel` pattern |
| Integration | Full round-trip: import via QR output → parse → generate code | Not in short mode (existing convention) |

## Migration / Rollout

No migration. HOTP counter is stored in the metadata JSON — imported secrets already have `Metadata` set (with OTPAuth). When the counter field is absent (zero value), `GenerateHOTP` uses the counter from the URI, then persists the incremented value.

## Open Questions

- [ ] QR terminal: confirm `skip2/go-qrcode` license (MIT) is acceptable, or switch to pure manual rendering with a smaller QR encoding lib
- [ ] DUO URI format varies (`duo://otp/...`) — confirm regex covers all known variants
