# Design: passwd tui-parity

## Technical Approach

Additive TUI-only changes — 5 features layered on the existing state machine without touching `internal/*` business logic packages. Each feature calls existing store, parse, or crypto APIs. Zero new business logic in `internal/tui`.

The existing pattern (state machine with `update*`/`view*` methods in separate files) is followed exactly: new state → new file (`inspect.go`), existing states → extended files (`add.go`, `list.go`), model fields → `model.go`.

## Architecture Decisions

| Decision | Choice | Alternatives | Rationale |
|----------|--------|-------------|-----------|
| Inspect state vs overlay | New `stateInspect` (full screen) | Modal overlay | Matches existing pattern (stateDetail), gives room for metadata display; overlay would fight search which already uses overlay |
| Kind cycle key | `t` (plain rune) | `tea.KeyCtrlT` | Ctrl+T may conflict with terminal; `t` is unused. Spec says `ctrl+t` or `t` — prefer `t` for portability |
| File import toggle | `o` (plain rune) | `tea.KeyCtrlF` | Ctrl+F can be intercepted by terminal. `o` ("open") is mnemonic |
| Kind filter scope | Client-side filter on `m.secrets` | Store query per kind | No new store methods needed; `m.secrets` already in memory. Store is file-backed, avoid extra queries |
| Expiring days | Hardcoded `30` | Config value | Follows spec (30). Config overengineering for this scope; revisit if user requests |
| Inspect metadata parse | `encoding/json.Unmarshal` + `parse.Metadata` | Custom display-only struct | `parse.Metadata` already exists, has `IsExpired()`/`DaysUntilExpiry()`. Reuse, don't duplicate |
| `mockStore.ListExpiring` | Return filtered mock data | Keep stub | Must return real data for integration tests. Filter on stored mock secrets matching kind + metadata |

## Data Flow

```
── Inspect ──────────────────────────────────────
  List 'i' key → stateInspect → sec.Metadata JSON
       → json.Unmarshal → parse.Metadata
       → viewInspect() displays fields (IsExpired, DaysUntilExpiry, etc.)
       → Esc returns to list. No decrypt. No state mutation.

── Add: Kind Selector ───────────────────────────
  Add form 't' key → m.addKindIndex++ % len(ValidKinds())
       → saveNewSecret() uses ValidKinds()[m.addKindIndex] instead of KindPassword

── Add: File Import ─────────────────────────────
  Add form 'o' key → m.addFileMode = !m.addFileMode
       → When fileMode && save:
         os.ReadFile(path) → parse.Detect(data)
         → parse.ParseX509 / ParseSSH / plain text
         → auto-set Kind + Metadata + EncryptedValue
         → crypto.Zeroize(data) after encrypt

── List: Kind Filter ────────────────────────────
  List 'f' key → cycle kindFilter: "" → "certificate" → "ssh_key" → ...
       → viewList() filters m.secrets client-side: sec.Kind == m.kindFilter

── List: Expiring ───────────────────────────────
  List 'e' key → toggle expiringMode
       → if on: m.secrets = m.st.ListExpiring(30)
       → if off: m.secrets = m.st.List()
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `internal/tui/inspect.go` | Create | `stateInspect` update/view: load metadata JSON, render cert/ssh fields, non-inspectable message |
| `internal/tui/model.go` | Modify | Add `stateInspect` enum, `inspectSecret` field, `addKindIndex`, `addFileMode`/`addFilePath`, `kindFilter`, `expiringMode`, `addFileInput` textinput |
| `internal/tui/add.go` | Modify | Add `t` key for kind cycle, `o` key for file mode toggle, file read+detect+encrypt in `saveNewSecret` |
| `internal/tui/list.go` | Modify | Add `f` key for kind filter cycle, `e` key for expiring toggle, `i` key for inspect transition, update footer |
| `internal/tui/tui_test.go` | Modify | Tests for all 5 features |

## Interfaces / Contracts

No new interfaces. All changes consume existing APIs:

```go
// Existing — unchanged
store.Store.ListExpiring(days int) ([]secret.Secret, error)

// Existing — unchanged
parse.Detect(data []byte) (Format, error)
parse.ParseX509(data []byte) (*Metadata, error)
parse.ParseSSH(data []byte) (*Metadata, error)

// Existing — unchanged
secret.ValidKinds() []Kind

// Existing — unchanged
parse.Metadata.IsExpired() bool
parse.Metadata.DaysUntilExpiry() int

// Existing — unchanged
crypto.Zeroize(buf []byte)
crypto.Engine.Encrypt(plaintext, key) (ciphertext, nonce, error)
```

### New model fields

```go
type model struct {
    // existing fields...

    // ── Inspect state ──
    inspectSecret secret.Secret

    // ── Add state ──
    addKindIndex int          // index into secret.ValidKinds()
    addFileMode  bool         // when true, show file path input instead of value
    addFileInput textinput.Model

    // ── List state ──
    kindFilter   string       // "" = no filter, "certificate", "ssh_key", etc.
    expiringMode bool         // when true, show expiring certs only
}
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | Inspect transitions (`i` on cert, ssh_key, password) | `tea.KeyRunes` → assert state, metadata rendered |
| Unit | Kind filter cycles (`f` key) | Assert `kindFilter` changes through correct sequence |
| Unit | Kind filter filters list | Multiple secrets of different kinds → assert only matching shown |
| Unit | Expiring toggle (`e` key) | Assert `expiringMode` toggle, `ListExpiring` called |
| Unit | Add kind selector (`t` key) | Assert `addKindIndex` cycles through `ValidKinds()` |
| Unit | Add file mode toggle (`o` key) | Assert `addFileMode` toggles, file input shown |
| Unit | File import save | Mock `os.ReadFile` (via `os` package), detect/parse/encrypt flow |
| Unit | `mockStore.ListExpiring` | Update mock to filter by kind + metadata (test helper) |
| Integration | Full add+list flow | Add with kind/file → list shows it → inspect → filter finds it |
| E2E | `go test ./internal/tui/... -count=1` | Full TUI test suite pass |

### mockStore updates

`mockStore.ListExpiring` must be updated from stub to real filtering:

```go
func (m *mockStore) ListExpiring(days int) ([]secret.Secret, error) {
    // Filter m.secrets by kind == "certificate" with non-empty metadata
    // Parse metadata, check NotAfter within next N days
    // Return matching metadata-only copies
}
```

## Migration / Rollout

No migration required. Additive TUI-only changes. Schema untouched. Rollback: revert commits in reverse order.

## Open Questions

- [ ] File import: should file mode auto-fill the name field from filename? (Spec doesn't specify; defer to implementation choice)
- [ ] Expiring: configurable days via config table or hardcoded 30? (Spec says 30; hardcode for now)
