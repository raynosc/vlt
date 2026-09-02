# breach-alerts Specification

## Purpose

Local breach-detection subsystem: on-demand download of a breach password corpus
(HIBP Pwned Passwords SHA-1 sorted list), local cache, integrity verification at
download and on load, SHA-1 password lookup via binary search over a memory-light
sparse index, and surfacing of breach hits from `internal/watchtower` into `vlt check`
and the GUI Watchtower panel. Network lookup is FORBIDDEN — privacy is local-only.

## Threat Model

- **Threat**: A user reuses a password that has appeared in a known breach; an online
  attacker who acquired that breach corpus can credential-stuff the user's accounts.
- **Privacy threat (counter-intuitive)**: querying a remote breach API with the user's
  password reveals the password to that third party. Even SHA-1 k-anonymity API queries
  expose a 5-char prefix + network metadata.
- **Integrity threat**: a tampered/swapped corpus on disk could suppress a real breach
  hit (false negative) or fabricate hits (false positive), degrading trust or hiding a
  compromised password.
- **Size/availability threat**: the corpus is several GB; bundling is infeasible and a
  corrupt download must never be used.
- **Mitigations**: corpus is downloaded ONLY on explicit `vlt breach update` (opt-in);
  lookup computes SHA-1(password) locally and binary-searches the local corpus — no
  password or hash ever leaves the machine; archive SHA-1 checked at download, extracted
  corpus SHA-256 verified on load; tamper fails closed (no corpus = no false "safe").
- **Residual risk**: stale corpus if user never re-runs `breach update`; mitigated by
  surfacing corpus age in `vlt check` output.

## Requirements

### Requirement: Breach Corpus Download Is Explicit Opt-In

The system MUST NOT download the breach corpus automatically. Download SHALL be
triggered only by an explicit user action (`vlt breach update`). An opt-in settings
toggle MAY enable update reminders; auto-download in the background is FORBIDDEN.

#### Scenario: Default install has no corpus

- GIVEN a fresh install that has never run `vlt breach update`
- WHEN any breach lookup is attempted
- THEN the system SHALL report "corpus not present" and SHALL NOT perform any network request
- AND SHALL direct the user to run `vlt breach update` to opt in

#### Scenario: Manual update triggers download

- GIVEN the user invokes `vlt breach update`
- WHEN the command runs
- THEN the system SHALL download the corpus archive once
- AND SHALL verify archive integrity before extracting

### Requirement: Breach Corpus Integrity Verification

The downloader MUST verify the archive's published SHA-1 at download time. The extracted
corpus MUST have its SHA-256 verified on every load. A tampered or corrupt corpus MUST
be refused and the lookup MUST fail closed (no results).

#### Scenario: Tampered archive rejected at download

- GIVEN a download whose bytes do not match the expected archive SHA-1
- WHEN the download completes
- THEN the system SHALL discard the archive
- AND SHALL report an integrity error
- AND SHALL NOT extract it

#### Scenario: Tampered corpus rejected on load

- GIVEN a corpus on disk whose SHA-256 does not match the bundled expected value
- WHEN `OpenCorpus` is called
- THEN it SHALL return an integrity error
- AND SHALL NOT build a lookup index from the tampered data

#### Scenario: Valid corpus loads

- GIVEN a corpus on disk whose SHA-256 matches the expected value
- WHEN `OpenCorpus` is called
- THEN an in-memory sparse index SHALL be built
- AND `Lookup` SHALL become callable

### Requirement: Breach Lookup Is Local and Privacy-Preserving

`Lookup(password)` MUST compute `SHA-1(password)` locally, binary-search the cached
sorted corpus with the in-memory sparse index, and return a boolean. The system MUST NOT
transmit the password, its SHA-1, or any prefix thereof over the network at any time.

#### Scenario: Breached password found

- GIVEN an open corpus and a password whose full SHA-1 is present in the corpus
- WHEN `Lookup(password)` is called
- THEN the lookup SHALL return true

#### Scenario: Clean password not found

- GIVEN an open corpus and a password whose SHA-1 is absent from the corpus
- WHEN `Lookup(password)` is called
- THEN the lookup SHALL return false
- AND SHALL NOT make any network request

#### Scenario: Lookup performance within budget

- GIVEN an open corpus on the order of 850M hashes
- WHEN `Lookup(password)` is called
- THEN the binary search SHALL resolve within 1–2 sparse-index block reads plus a final
  block read (target ≤ a few disk reads, not an O(n) scan)

### Requirement: Watchtower Surfaces Breach Hits

`watchtower.Analyze` MUST decrypt each secret's password, run `breach.Lookup` against
the open corpus, and attach a `BreachPasswordFinding`/`BreachedPasswords` result to its
output. When no corpus is loaded, the watchtower SHALL explicitly report "breach check
skipped (no corpus)" rather than implying safety.

#### Scenario: Watchtower surfaces breached password

- GIVEN an unlocked vault with a secret whose password is in the loaded corpus
- WHEN `watchtower.Analyze` runs
- THEN the result SHALL include a breach finding naming the secret (or its id)
- AND the password itself SHALL NOT be echoed in the finding text

#### Scenario: No corpus yields explicit skip notice

- GIVEN an unlocked vault and no corpus loaded
- WHEN `watchtower.Analyze` runs
- THEN the result SHALL state breach check was skipped
- AND SHALL NOT report "no breached passwords"

### Requirement: CLI `vlt check` Surfaces Breach Hits

`vlt check` MUST render breach findings from watchtower output. When corpus age exceeds
a staleness threshold, the output SHALL warn the corpus may be stale.

#### Scenario: Breach hit in CLI output

- GIVEN a vault with a breached password and a loaded corpus
- WHEN `vlt check` runs (after unlock)
- THEN the output SHALL list the secret(s) whose passwords are breached
- AND SHALL NOT print the breach-corpus password itself

#### Scenario: Stale corpus warning

- GIVEN a loaded corpus whose last update was older than the staleness threshold
- WHEN `vlt check` runs
- THEN the output SHALL include a warning that breach data may be stale

### Requirement: GUI Watchtower Panel Surfaces Breach Hits

The GUI Watchtower panel MUST render a `BREACHED PASSWORDS` section sourced from
`WatchtowerResult.BreachedPasswords`. The panel SHALL surface corpus-absent and
stale-corpus states distinctly from a clean result.

#### Scenario: Panel lists breach hits

- GIVEN an unlocked GUI with a loaded corpus and breached passwords present
- WHEN the Watchtower panel is rendered
- THEN a `BREACHED PASSWORDS` section SHALL list the affected secrets
- AND SHALL NOT display the actual breached passwords

#### Scenario: Panel distinguishes no-corpus from clean

- GIVEN the GUI with no corpus loaded
- WHEN the Watchtower panel is rendered
- THEN the panel SHALL show a "breach check skipped — corpus not installed" notice
- AND SHALL NOT show an empty/zero breach count implying safety