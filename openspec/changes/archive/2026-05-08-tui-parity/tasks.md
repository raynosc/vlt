# Tasks: passwd tui-parity

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~550-650 |
| 400-line budget risk | Medium |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (tests+model+inspect) → PR 2 (kind+filter) → PR 3 (expiring+file) |
| Delivery strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: Medium

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Tests + model fields + inspect state | PR 1 | Main branch base. Self-contained: inspect compiles and runs, remaining tests fail |
| 2 | Kind selector + kind filter | PR 2 | Main. Adds addKindIndex + kindFilter, add.go + list.go changes |
| 3 | Expiring toggle + file import | PR 3 | Main. Adds expiringMode + addFileMode, list.go + add.go changes |

## Phase 1: TDD — Test Suite First (Task 1)

- [x] 1.1 Add 17 test cases to `tui_test.go`: inspect cert metadata, inspect ssh metadata, inspect non-inspectable, inspect malformed, kind selector cycle, store with kind, add cancel, file import cert, file import text, file not found, file unreadable, kind filter cycle, client-side filter, filter reset, expiring toggle on, expiring empty, expiring off
- [x] 1.2 Update `mockStore.ListExpiring` from stub to filter on `m.secrets` by kind + metadata JSON

## Phase 2: Model Fields & State (prerequisite for Tasks 2-6)

- [x] 2.1 Add `stateInspect` to `appState` constants in `model.go`
- [x] 2.2 Add all new fields: `inspectSecret`, `addKindIndex`, `addFileMode`, `addFileInput`, `kindFilter`, `expiringMode`
- [x] 2.3 Wire `stateInspect` into `Update()` dispatch and `View()` switch

## Phase 3: Inspect State (Task 2)

- [x] 3.1 Add `i` key in `list.go` to transition to `stateInspect` with the selected secret
- [x] 3.2 Create `inspect.go`: `updateInspect` parses `sec.Metadata` JSON → `parse.Metadata`, `viewInspect` renders cert fields (issuer, subject, expiry, SANs) or ssh fields (type, fingerprint, comment)
- [x] 3.3 Non-inspectable kinds (password, api_key) show "No metadata available" — no crash
- [x] 3.4 Malformed metadata JSON shows "Error: Unable to parse metadata" and returns to list on Esc

## Phase 4: Kind Selector in Add (Task 3)

- [x] 4.1 Add `t` key handler in `add.go`: cycle `addKindIndex` through `secret.ValidKinds()`
- [x] 4.2 Modify `saveNewSecret` to use `ValidKinds()[addKindIndex]` instead of hardcoded `KindPassword`
- [x] 4.3 Update `viewAdd()` to show current kind label (e.g. "Kind: certificate")

## Phase 5: Kind Filter in List (Task 4)

- [x] 5.1 Define kind filter cycle: `""` → `"certificate"` → `"ssh_key"` → `"api_key"` → `"password"` → `"note"` → `"other"` → `""` (All)
- [x] 5.2 Add `f` key handler in `list.go`: advance `kindFilter` through the cycle
- [x] 5.3 Apply filter in `viewList()`: skip secrets where `sec.Kind != m.kindFilter` (when non-empty)
- [x] 5.4 Update `listFooter()` to show active filter (e.g. `· filter: certificate`)

## Phase 6: Expiring Toggle in List (Task 5)

- [x] 6.1 Add `e` key handler in `list.go`: toggle `expiringMode`, call `m.st.ListExpiring(30)` when active else `m.st.List()`
- [x] 6.2 Show "No expiring certificates" when expiring mode returns empty
- [x] 6.3 Update `listFooter()` to show expiring status (e.g. `· expiring only`)

## Phase 7: File Import in Add (Task 6)

- [x] 7.1 Add `o` key toggle in `add.go`: switch `addFileMode`, show file `textinput` instead of value input
- [x] 7.2 Extend `saveNewSecret` file mode: `os.ReadFile` → `parse.Detect` → `parse.ParseX509`/`ParseSSH`/plain text → auto-set `Kind` + `Metadata` → encrypt → `crypto.Zeroize(fileBytes)`
- [x] 7.3 File errors (not found, unreadable) set `m.err` and keep form open — no crash
- [x] 7.4 Update `viewAdd()` to show file input + detected kind when in file mode
