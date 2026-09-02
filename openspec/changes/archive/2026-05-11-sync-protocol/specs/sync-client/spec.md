# sync-client Specification

## Purpose

Local sync engine that diffs vault state against server state, pushes/pulls encrypted snapshots, merges via last-writer-wins, and logs conflicts — all without exposing plaintext to the network.

## Requirements

### Requirement: Offline-first Operation

The client MUST open and operate on the local vault without any network connectivity.

#### Scenario: Vault opens offline

- GIVEN the device has no network connectivity
- WHEN the user opens the vault
- THEN the vault opens successfully
- AND sync commands report "unavailable" without crashing

### Requirement: Diff Detection

The client MUST compute which secrets were added, modified, or deleted since the last sync by comparing local against the last-synced snapshot.

#### Scenario: Detect pending push

- GIVEN a secret created or modified after the last successful sync
- WHEN `vlt sync status` is invoked
- THEN the output SHALL list the secret as pending push

#### Scenario: Detect pending pull

- GIVEN the server has a newer blob version than the local vault
- WHEN `vlt sync status` is invoked
- THEN the output SHALL report available remote changes

### Requirement: Encrypted Push

The client MUST serialize the full vault (all secrets with metadata) into an encrypted opaque blob and upload it to the server.

#### Scenario: Push succeeds

- GIVEN a vault with pending changes and valid API key
- WHEN the client pushes
- THEN the server SHALL store the blob
- AND the client SHALL update local SyncedAt for all pushed secrets

#### Scenario: Push fails on auth

- GIVEN an invalid API key
- WHEN the client attempts to push
- THEN the client SHALL report authentication failure
- AND SHALL NOT modify local SyncedAt

### Requirement: Encrypted Pull

The client MUST download the latest server blob, decrypt it locally using the master key, and apply changes to the local store.

#### Scenario: Pull applies remote changes

- GIVEN the server has a newer blob
- WHEN the client pulls
- THEN the client SHALL apply remote changes to the local store
- AND update local SyncedAt for affected secrets

#### Scenario: Pull with no changes

- GIVEN local and server are in sync
- WHEN the client pulls
- THEN the client SHALL report no changes

### Requirement: LWW Merge with Conflict Log

The client MUST apply last-writer-wins per secret using SyncedAt. When a local change is overwritten, the previous value SHALL be logged.

#### Scenario: Local edit overwritten

- GIVEN a local secret with older SyncedAt than the server version
- WHEN the client pulls
- THEN the server version SHALL replace the local version
- AND the old value SHALL be recorded in the conflict log

### Requirement: Master Key Isolation

The client MUST NOT transmit the master key, any derived key, or any plaintext secret to the server.

#### Scenario: Zero-knowledge push

- GIVEN the client pushes to the server
- THEN the blob SHALL consist solely of opaque ciphertext
- AND the server SHALL be unable to decrypt it
