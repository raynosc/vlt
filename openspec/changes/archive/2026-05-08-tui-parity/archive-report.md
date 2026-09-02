# Archive Report: tui-parity

**Date**: 2026-05-08
**Change**: TUI parity — closing 5 gaps between CLI and TUI capabilities

## Summary

Delivered 5 new TUI features to reach feature parity with CLI: inspect metadata view, kind selector on add, file import on add, kind filter on list, and expiring certs toggle on list. All features implemented as additive TUI states with zero new business logic in `internal/tui`. Strict TDD enforced — all 17 new tests written before implementation. Clean Architecture maintained: all calls delegate to existing `internal/store`, `internal/parse`, and `internal/crypto` packages.

## What Was Built

| Feature | State | Files | Description |
|---------|-------|-------|-------------|
| Inspect metadata | `stateInspect` | `inspect.go` (new) | Press `i` on cert/ssh_key secrets to view parsed metadata. Read-only — never decrypts the value. |
| Kind selector | Add form field | `add.go` (mod) | Press `t` to cycle kind: password → certificate → ssh_key → api_key → note → other. Default: password. |
| File import | Add file mode | `add.go` (mod) | Press `o` to toggle file input. Reads file → auto-detect → parse → auto-set kind+metadata → encrypt → zeroize. |
| Kind filter | List filter | `list.go` (mod) | Press `f` to cycle filter: All → certificate → ssh_key → api_key → password → note → other → All. Client-side filtering on `m.secrets`. |
| Expiring toggle | List filter | `list.go` (mod) | Press `e` to toggle expiring-only mode. Calls `store.ListExpiring(30)`. "No expiring certificates" when empty. |

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Inspect as full-screen state vs overlay | New `stateInspect` (full screen) | Matches existing `stateDetail` pattern; overlay would conflict with search overlay |
| Kind cycle key | `t` (plain rune) | Ctrl+T may conflict with terminal; `t` is unused |
| File import key | `o` (plain rune, "open") | Ctrl+F intercepted by terminal; `o` is mnemonic |
| Kind filter scope | Client-side on `m.secrets` | No new store methods; secrets already in memory |
| Expiring days | Hardcoded `30` | Follows spec; config overengineering for this scope |
| Metadata parse | `encoding/json.Unmarshal` + `parse.Metadata` | `parse.Metadata` already exists with `IsExpired()`/`DaysUntilExpiry()`; reuse, don't duplicate |
| mockStore.ListExpiring | Real filtering (not stub) | Must return data for integration tests; filters in-memory mock secrets |

## Specs Synced

| Domain | Action | Details |
|--------|--------|---------|
| tui-browser | **Updated** | Modified "Secret List with Navigation" (6 new scenarios: kind filter + expiring); added 3 new requirements (Inspect — 4 scenarios, Kind Selector — 3 scenarios, File Import — 4 scenarios) |

## Tests

- **48 tests total** (all pass)
- **17 new tests**: inspect cert metadata, inspect ssh metadata, inspect non-inspectable, inspect malformed, kind selector cycle, store with kind, add cancel, file import cert, file import text, file not found, file unreadable, kind filter cycle, client-side filter, filter reset, expiring toggle on, expiring empty, expiring off
- **Strict TDD**: all tests written before implementation
- **Coverage**: >70% across `internal/tui/`

## Delivery

- **Single PR** merged to `main`
- **~1327 lines added**, 23 removed
- **7 tasks** across 4 phases — all complete
- **Tagged**: `v0.2.1`

## Archive Contents

- proposal.md ✅
- specs/ ✅ (tui-browser/spec.md)
- design.md ✅
- tasks.md ✅ (7/7 tasks complete)
- archive-report.md ✅

## SDD Cycle Complete

The change has been fully planned, implemented, verified, and archived. Ready for the next change.
