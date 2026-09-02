# Proposal: OTP Support

## Intent

Imported secrets frequently carry OTPAuth URIs in `PasswordMetadata.OTPAuth`, but passwd can't generate codes from them. Users need TOTP/HOTP code generation, QR enrollment, and live TUI display — turning passwd into a full authenticator.

## Scope

### In Scope
- `internal/otp/` — RFC 6238 TOTP + RFC 4226 HOTP generation (pure stdlib)
- URI parsing: `otpauth://totp`, `otpauth://hotp`, `duo://`, `steam://`
- QR decode: `vlt import --qr file.png` extracts URI from image
- QR display: terminal block-char QR for phone scan via `vlt totp --qr <name>`
- `vlt totp <name>` — show current code + 30s countdown
- `vlt totp --clipboard <name>` — copy code via existing clipboard dep
- TUI detail view: live TOTP code with countdown progress bar
- Steam Guard: TOTP with custom alphabet (A-Z/2-7), 5 characters

### Out of Scope
- DUO Push (proprietary cloud protocol)
- SMS/Call OTP delivery
- Hardware token (FIDO/U2F) enrollment

## Capabilities

### New Capabilities
- `otp-codes`: TOTP/HOTP code generation from stored secrets
- `otp-uri-parse`: OTPAuth URI parsing and validation
- `otp-qr`: QR image decode and terminal QR rendering

### Modified Capabilities
- `tui-browser`: detail view must detect `otpauth://` in secret metadata and show live TOTP code with countdown

## Approach

Pure Go stdlib: `crypto/hmac`, `crypto/sha1`, `crypto/sha256`, `encoding/base32` for HOTP (RFC 4226) and TOTP (RFC 6238). QR decode via `gozxing` (mature pure-Go QR decoder). QR display via terminal block characters using existing Bubble Tea renderer. CLI: new `totp` subcommand matching existing command patterns. TUI: detect `otpauth://` in `PasswordMetadata.OTPAuth`, render live countdown with `time.Ticker`.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `internal/otp/` | New | Core OTP algorithms + URI parsing |
| `internal/cli/totp.go` | New | `vlt totp` subcommand |
| `internal/cli/import.go` | Modified | Add `--qr` flag |
| `internal/tui/detail.go` | Modified | OTP live countdown view |
| `go.mod` | Modified | Add gozxing dep |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| QR decode lib quality | Low | gozxing is mature, pure-Go, Apache 2.0 |
| Steam Guard alphabet edge cases | Low | Test with reference Steam secrets |
| TUI ticker goroutine leak | Low | Ensure view switch / quit cancels ticker |

## Rollback Plan

Revert `go.mod` to remove gozxing. Delete `internal/otp/`. Remove `newTotpCmd()` from root command. Revert `import.go` `--qr` flag. Revert `detail.go` OTP view additions.

## Dependencies

- `github.com/makiuchi-d/gozxing` — QR decode (pure Go, Apache 2.0)
- Stdlib: `crypto/hmac`, `crypto/sha1`, `crypto/sha256`, `encoding/base32`, `time`

## Success Criteria

- [ ] TOTP codes match Google Authenticator / Authy for same secret
- [ ] HOTP codes match RFC 4226 Appendix D test vectors
- [ ] Steam Guard codes match Steam mobile app output
- [ ] QR decode extracts valid `otpauth://` URI from PNG screenshot
- [ ] `vlt totp --clipboard <name>` copies code to clipboard
- [ ] TUI detail shows live countdown bar that updates every second
- [ ] `internal/otp/` is pure Go, no CGO, no external deps beyond gozxing
