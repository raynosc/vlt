# Delta for tui-gui

## MODIFIED Requirements

### Requirement: Graceful Quit

The system MUST exit cleanly on Ctrl+C or `q` (non-input screens). On quit during a decryption view, plaintext MUST be cleared from memory by zeroizing the underlying `[]byte` buffer before release.
(Previously: Required plaintext clearing from memory without specifying the buffer type or zeroization mechanism.)

#### Scenario: Quit

- GIVEN an active TUI session
- WHEN Ctrl+C or `q` is pressed on non-input screens
- THEN the TUI exits cleanly with no DB corruption

#### Scenario: During decryption view

- GIVEN a decrypted value is displayed in a `[]byte` buffer
- WHEN the user quits
- THEN the TUI exits and the `[]byte` buffer is overwritten with zeros before release

## ADDED Requirements

### Requirement: Memory-Safe Plaintext Storage

The TUI MUST store decrypted plaintext exclusively in `[]byte` and explicitly zeroize the buffer before deallocation.

#### Scenario: Decrypt on demand

- GIVEN a selected secret
- WHEN decrypted for display
- THEN the plaintext SHALL be held in a `[]byte` buffer

#### Scenario: Buffer zeroization

- GIVEN a `[]byte` buffer containing plaintext
- WHEN the buffer is no longer needed
- THEN every byte SHALL be overwritten with `0x00` before release

### Requirement: TOTP Goroutine Lifecycle

The GUI MUST cancel TOTP background goroutines via a cancellable context when the TOTP view is dismissed or the application exits.

#### Scenario: View dismissed

- GIVEN an active TOTP display with a background goroutine
- WHEN the user navigates away
- THEN the goroutine SHALL be cancelled via context and terminate

#### Scenario: Application exit

- GIVEN active TOTP goroutines
- WHEN the application window closes
- THEN all TOTP goroutines SHALL terminate promptly
