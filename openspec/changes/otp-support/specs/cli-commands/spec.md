# Delta for cli-commands

## ADDED Requirements

### Requirement: TOTP Code Display
**Priority**: P0

The system MUST provide a `vlt totp <name>` command displaying the current TOTP code, algorithm, and a 30s countdown. Unknown names and secrets without `otpauth://` MUST produce errors.

- **Scenario**: Show TOTP — GIVEN secret "example" with valid `otpauth://totp` URI, WHEN `vlt totp example` is run, THEN the current 6-digit code, algorithm, remaining seconds, and countdown bar are displayed.
- **Scenario**: Unknown secret — GIVEN no secret "unknown", WHEN `vlt totp unknown` is run, THEN error "Secret not found: unknown" is shown.
- **Scenario**: No OTP URI — GIVEN secret "note" without `otpauth://` URI, WHEN `vlt totp note` is run, THEN error "No OTP URI found for secret: note" is shown.

### Requirement: Clipboard Copy
**Priority**: P0

The system MUST support `vlt totp --clipboard <name>` to copy the current TOTP code to the clipboard using the existing clipboard dependency.

- **Scenario**: Copy — GIVEN a secret with valid `otpauth://` URI, WHEN `vlt totp --clipboard example` is run, THEN the current code is copied to clipboard and a confirmation message is printed.

### Requirement: QR Import
**Priority**: P1

The system MUST support `vlt import --qr file.png` to decode a QR image, extract the `otpauth://` URI, parse the secret, and store it. Invalid images and missing QRs MUST produce errors.

- **Scenario**: Import — GIVEN a PNG with QR containing `otpauth://totp/Label?secret=...`, WHEN `vlt import --qr file.png` is run, THEN the secret is stored with the label from the URI and success is printed.
- **Scenario**: No QR — GIVEN a PNG with no QR code, WHEN `vlt import --qr noqr.png` is run, THEN error "No QR code found in image" is shown.
- **Scenario**: Corrupt image — GIVEN a corrupted file, WHEN `vlt import --qr bad.png` is run, THEN error "Unable to decode image" is shown.
