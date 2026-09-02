# structural-constants Specification

## Purpose

Centralized constants for version, exit codes, and API paths to ensure consistency across all binaries.

## Requirements

### Requirement: Single Version Source of Truth

All binaries MUST report the same version string derived from a single shared constant.

#### Scenario: Version consistency

- GIVEN any binary (`vlt`, `sync-server`, etc.)
- WHEN `--version` is invoked
- THEN the output SHALL match the shared version constant

### Requirement: Named Exit Code Constants

All process exits MUST use named constants instead of raw integers.

#### Scenario: Error exit uses constant

- GIVEN a CLI command fails
- WHEN the process exits
- THEN the exit code SHALL be a named constant (e.g., `ExitCodeError`)

### Requirement: API Path Constants

The sync server MUST define all route paths as constants. Route handlers SHALL reference these constants.

#### Scenario: Routes use constants

- GIVEN the sync server router
- WHEN handling requests
- THEN paths like `/v1/vaults` SHALL be referenced via a constant

#### Scenario: Route constant consistency

- GIVEN a route constant is changed
- WHEN the server is rebuilt
- THEN all references SHALL use the updated value
