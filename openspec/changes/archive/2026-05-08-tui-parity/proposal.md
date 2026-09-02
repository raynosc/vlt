# Proposal: passwd tui-parity

## Intent

CLI has 8 operations but TUI only covers 5 states. Missing: inspect, type-aware add, file import, kind filter, expiring view. TUI is interface adapter — all business logic already exists in `internal/store`, `internal/crypto`, `internal/parse`.

## Scope

### In Scope
1. **TUI inspect**: new `stateInspect`, triggered by `i` on cert/ssh_key secrets. Displays parsed metadata from stored JSON. Read-only — no decrypt.
2. **TUI add --type**: kind selector in add form (cycle). Default: password.
3. **TUI add --file**: file path input in add form. Reads file, calls `parse.Detect` + parser, auto-sets kind and metadata.
4. **TUI list --kind**: filter toggle. `f` to cycle kinds: All → certificate → ssh_key → api_key → password → note → other → All.
5. **TUI list --expiring**: `e` toggles expiring mode. Shows certs expiring within N days.

### Out of Scope
- No new CLI features, schema changes, crypto/parse changes, `--overwrite` flag

## Capabilities

### New Capabilities
- `tui-inspect`: Certificate/key metadata viewing in the TUI
- `tui-add`: Secret creation with kind selection and file import
- `tui-list`: List filtering by kind and expiring certificates view

### Modified Capabilities
None — existing `cert-parsing` spec is unchanged.

## Approach

Additive TUI states only — no schema, no core changes. Each feature calls existing APIs:

1. **Inspect**: new `stateInspect` + `viewInspect()`. Calls `parse.Metadata` methods (`IsExpired`, `DaysUntilExpiry`) on stored metadata JSON. Read-only, never decrypts the value.

2. **Add --type**: cycle focus through a kind selector before the value field. The `saveNewSecret()` path uses the selected kind instead of hardcoded `KindPassword`.

3. **Add --file**: extend add model with `addFilePath` input + `addFileMode` bool. When in file mode: reads file bytes → `parse.Detect` → `parse.Parse*` → auto-sets kind, metadata JSON, and encrypted file bytes. Plaintext zeroized after encrypt.

4. **List --kind**: add `activeKindFilter` field. `f` cycles through kinds. Filter applied client-side on `m.secrets`. No store query change.

5. **List --expiring**: add `expiringMode` field + `expiringDays` config. `e` toggles. Calls `store.ListExpiring(days)` when active.

Zero business logic in TUI layer — all calls delegate to existing packages.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `internal/tui/model.go` | Modified | New states, add/list model fields |
| `internal/tui/list.go` | Modified | Kind filter, expiring mode |
| `internal/tui/add.go` | Modified | Kind selector, file import |
| `internal/tui/inspect.go` | New | Inspect state + view |
| `internal/tui/tui_test.go` | Modified | New tests for all 5 features |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| File import reads plaintext into TUI memory | Med | Zeroize file bytes after encrypt; don't keep in model struct |
| mockStore missing ListExpiring | Low | Already stubbed — update to return filtered mock data |
| TUI model struct grows large | Low | State machine pattern keeps it bounded |

## Rollback Plan

Revert additive TUI commits. No schema changes — no migration needed. `git revert` the feature commits in reverse order.

## Dependencies

- Internal: `internal/crypto`, `internal/store`, `internal/parse`, `internal/secret` — all exist
- External: Bubble Tea + Bubbles — already in `go.mod`

## Success Criteria

- [ ] TDD: tests written BEFORE implementation for every new state
- [ ] Security: no plaintext in TUI state longer than necessary; file bytes zeroized after encrypt
- [ ] `go test ./... -count=1` passes with no regressions
- [ ] `go build ./cmd/vlt-tui` compiles
- [ ] All 5 features work end-to-end via TUI interaction
