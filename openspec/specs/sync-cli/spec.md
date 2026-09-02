# sync-cli Specification

## Purpose

CLI subcommands under `vlt sync` (init, status, push, pull) that manage the sync lifecycle, configure the sync server, and report sync state to the user.

## Requirements

### Requirement: sync init

`vlt sync init` MUST configure the sync server URL and generate an API key, storing both in the vault configuration.

#### Scenario: First-time setup

- GIVEN a vault with no sync configured
- WHEN the user runs `vlt sync init --server https://sync.example.com`
- THEN the CLI SHALL generate a new API key
- AND SHALL store the server URL and key in config

#### Scenario: Re-init with existing config

- GIVEN a vault with existing sync configuration
- WHEN the user runs `vlt sync init --server https://new.example.com`
- THEN the CLI SHALL replace the existing URL and generate a new key
- AND SHALL warn the user about the change

### Requirement: sync status

`vlt sync status` MUST display sync state: last sync time, pending push count, pending pull count, and any unresolved conflicts.

#### Scenario: Show sync status

- GIVEN a sync-configured vault
- WHEN the user runs `vlt sync status`
- THEN the output SHALL include last sync timestamp
- AND SHALL list pending push changes
- AND SHALL list pending pull changes

#### Scenario: Sync not configured

- GIVEN a vault with no sync configuration
- WHEN the user runs `vlt sync status`
- THEN the CLI SHALL report sync is not configured

### Requirement: sync push

`vlt sync push` MUST upload local changes to the server.

#### Scenario: Successful push

- GIVEN a vault with pending local changes
- WHEN the user runs `vlt sync push`
- THEN the CLI SHALL push changes
- AND SHALL report the number of secrets pushed

#### Scenario: Push fails

- GIVEN a vault with pending changes but no network
- WHEN the user runs `vlt sync push`
- THEN the CLI SHALL report the error
- AND SHALL NOT modify the local vault

### Requirement: sync pull

`vlt sync pull` MUST download and apply remote changes to the local vault.

#### Scenario: Successful pull

- GIVEN a vault with newer remote changes
- WHEN the user runs `vlt sync pull`
- THEN the CLI SHALL apply remote changes
- AND SHALL report the number of secrets updated

#### Scenario: Pull with conflicts

- GIVEN remote changes that overwrite local edits
- WHEN the user runs `vlt sync pull`
- THEN the CLI SHALL report which secrets were overwritten
- AND SHALL indicate conflicts are logged for review

### Requirement: Error Reporting

The CLI MUST report sync errors clearly, distinguishing network, auth, and server errors.

#### Scenario: Auth error reported

- GIVEN an invalid or revoked API key
- WHEN the user runs any sync command
- THEN the CLI SHALL report "authentication failed"
- AND SHALL suggest re-running `vlt sync init`

#### Scenario: Server error reported

- GIVEN the server returns 5xx
- WHEN the user runs `vlt sync push`
- THEN the CLI SHALL report the server error
- AND SHALL suggest retrying later
