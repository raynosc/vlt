# Delta for tui-browser

## ADDED Requirements

### Requirement: Live OTP Display in Detail View
**Priority**: P0

When a secret has an `otpauth://` URI in `PasswordMetadata.OTPAuth`, the system MUST show a live TOTP code with a countdown progress bar that refreshes every second.

- **Scenario**: OTP shown — GIVEN a secret with valid `otpauth://totp` URI in metadata, WHEN the detail view is displayed, THEN the current 6-digit TOTP code and a progress bar indicating remaining seconds in the 30s window are rendered.
- **Scenario**: Non-OTP secret — GIVEN a secret without `otpauth://` in metadata, WHEN the detail view is displayed, THEN no OTP section is rendered and existing detail layout is unaffected.
- **Scenario**: Ticker lifecycle — GIVEN an active OTP detail view, WHEN the user navigates away or quits, THEN the TOTP update ticker is cancelled (no goroutine leak).
- **Scenario**: Countdown expiry — GIVEN an active OTP detail view, WHEN the countdown reaches 0, THEN a new code is generated and the progress bar resets to full.
