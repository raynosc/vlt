# Tasks: OTP Support

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~620 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1: OTP engine + URI parser → PR 2: QR + CLI → PR 3: TUI |
| Delivery strategy | auto-chain |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | OTP engine + URI parser + RFC vectors | PR 1 | Base → main. `internal/otp/` only, zero project deps |
| 2 | QR decode/display, CLI totp + import --qr | PR 2 | Depends on PR 1; adds gozxing, modifies root/import/store/secret |
| 3 | TUI detail countdown | PR 3 | Depends on PR 1 (otp package); modifies detail.go + model.go |

## Phase 1: OTP Engine + URI Parser (PR 1)

- [x] 1.1 RED: Write `internal/otp/otp_test.go` with RFC 4226 App D HOTP vectors, RFC 6238 TOTP vectors, Steam alphabet tests
- [x] 1.2 GREEN: Implement `internal/otp/otp.go` — `GenerateHOTP`, `GenerateTOTP`, `Options`, Steam custom alphabet
- [x] 1.3 REFACTOR: Add edge cases — invalid base32, custom digits, SHA256/SHA512
- [x] 1.4 RED: Write `internal/otp/uri_test.go` — `otpauth://totp/hotp`, `duo://`, `steam://`, error cases
- [x] 1.5 GREEN: Implement `internal/otp/uri.go` — `ParseURI`, `OTPConf`, regex patterns for all 3 schemes
- [x] 1.6 Add `HOTPCounter` field to `PasswordMetadata`, add `UpdateMetadata` to `Store` interface + `SQLStore`

## Phase 2: QR + CLI Commands (PR 2)

- [x] 2.1 Add `gozxing` + `go-qrcode` deps to `go.mod`
- [x] 2.2 RED: Write QR decode/display tests — valid QR, no QR, corrupt image, ASCII render length
- [x] 2.3 GREEN: Implement `internal/otp/qr.go` — `DecodeQR` (gozxing), `QRDisplay` (skip2/go-qrcode ASCII)
- [x] 2.4 RED: Write CLI `vlt totp` tests — valid OTP secret, unknown secret, no URI, --clipboard
- [x] 2.5 GREEN: Create `internal/cli/totp.go` — `newTotpCmd`, `runTotp` with --clipboard, register in root
- [x] 2.6 RED: Write CLI `vlt import --qr` tests — valid QR PNG, no QR, corrupt image
- [x] 2.7 GREEN: Add `--qr` flag to `import.go`, wire QR decode path in `runImport`

## Phase 3: TUI Detail Countdown (PR 3)

- [x] 3.1 RED: Write TUI detail OTP tests — OTP section shown, non-OTP hidden, ticker lifecycle, countdown expiry
- [x] 3.2 GREEN: Add `otpCode`, `otpCountdown`, `otpPeriod` fields to `model.go`
- [x] 3.3 GREEN: Add OTP section in `viewDetail`, `tea.Tick` in `updateDetail`, cancel on `backToList`
