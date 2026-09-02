# Delta for tui-browser

**Change**: tui-parity

## ADDED Requirements

### Requirement: Inspect Certificate/Key Metadata
**Priority**: P0

The system MUST display parsed cert/SSH key metadata via `i`. Non-inspectable kinds and malformed metadata MUST show an error. The secret value MUST NOT be decrypted.

- **Scenario**: Certificate metadata — GIVEN a `certificate` secret with valid metadata JSON, WHEN the user presses `i`, THEN issuer, subject, expiry, days-until-expiry, and SANs are displayed.
- **Scenario**: SSH key metadata — GIVEN an `ssh_key` secret with valid metadata JSON, WHEN the user presses `i`, THEN key type, fingerprint, and comment are displayed.
- **Scenario**: Non-inspectable kind — GIVEN a `password` or `api_key` secret, WHEN the user presses `i`, THEN "No metadata available for this secret type" is shown.
- **Scenario**: Malformed metadata — GIVEN unparseable metadata JSON, WHEN the user presses `i`, THEN "Error: Unable to parse metadata" is shown and the TUI returns to list state.

### Requirement: Secret Creation — Kind Selector
**Priority**: P0

The system MUST allow selecting a secret kind during creation. The selector SHALL cycle: password → certificate → ssh_key → api_key → note → other. Default SHALL be password. Cancel MUST NOT persist data.

- **Scenario**: Cycle kind — GIVEN the add form, WHEN the kind selector is activated, THEN the kind advances to the next value.
- **Scenario**: Store with kind — GIVEN a selected kind (e.g., `ssh_key`), WHEN the user fills the value and saves, THEN the secret is stored with that kind.
- **Scenario**: Cancel — GIVEN the add form, WHEN the user presses Escape, THEN the form is dismissed, list view restored, and no secret created.

### Requirement: Secret Creation — File Import
**Priority**: P0

The system MUST support file import as the secret value: read bytes, detect format via `parse.Detect`, auto-set kind and metadata, encrypt, zeroize. File errors SHALL display a message without closing the form.

- **Scenario**: Import certificate — GIVEN file mode in add form, WHEN the user enters a valid `.pem` path, THEN kind is auto-set to `certificate`, metadata parsed, value encrypted, bytes zeroized.
- **Scenario**: Import text — GIVEN file mode, WHEN the user enters a plain text path, THEN kind is auto-set to `password` and stored without metadata.
- **Scenario**: File not found — GIVEN file mode, WHEN the user enters a non-existent path, THEN "Error: File not found" is shown and the form stays open.
- **Scenario**: Unreadable — GIVEN file mode, WHEN the path lacks read permissions, THEN "Error: Unable to read file" is shown and the form stays open.

## MODIFIED Requirements

### Requirement: Secret List with Navigation
**Priority**: P0
(Previously: ↑/↓/j/k navigation only. No kind filter or expiring view.)

The system MUST display a navigable secret list with ↑/↓/j/k. The user SHALL filter by kind via `f` and toggle expiring certificate view via `e`.

- **Scenario**: Navigate — GIVEN 10 secrets, WHEN the list is shown, THEN ↑/↓/j/k navigate with highlighted selection.
- **Scenario**: Empty — GIVEN no secrets, WHEN the list is shown, THEN "No secrets found" is displayed.
- **Scenario**: Cycle kind — GIVEN secrets of multiple kinds, WHEN the user presses `f`, THEN the filter cycles All → certificate → ssh_key → api_key → password → note → other → All and the list filters.
- **Scenario**: Client-side filter — GIVEN an active kind filter, WHEN the list renders, THEN filtering is client-side on `m.secrets` without a store query.
- **Scenario**: Reset kind — GIVEN an active kind filter, WHEN cycling back to All, THEN all secrets are shown.
- **Scenario**: Toggle expiring — GIVEN expiring and non-expiring certificates, WHEN the user presses `e`, THEN expiring mode shows only certificates expiring within N days.
- **Scenario**: Expiring empty — GIVEN no expiring certificates, WHEN expiring mode is active, THEN "No expiring certificates" is shown.
- **Scenario**: Expiring off — GIVEN active expiring mode, WHEN `e` is pressed again, THEN all secrets are restored.
