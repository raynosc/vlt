# Delta for daemon-hardening

## ADDED Requirements

### Requirement: Panic Recovery in Connection Handler

The daemon MUST recover from panics in per-connection handlers using `recover()`. The daemon process SHALL remain alive and the affected connection SHALL be closed cleanly.

#### Scenario: Panic in handler

- GIVEN a panic injected in a connection handler
- WHEN the connection is processed
- THEN the daemon SHALL survive
- AND the connection SHALL be closed without crashing the process

### Requirement: Progressive Lockout

The daemon MUST enforce a minimum 300-second lockout after 5 consecutive failed authentication attempts. The lockout duration MUST persist across connections from the same client.

#### Scenario: Five failed attempts trigger lockout

- GIVEN 5 consecutive failed authentication attempts
- WHEN a 6th attempt is made
- THEN the daemon SHALL reject the attempt
- AND the client SHALL remain locked out for at least 300 seconds

#### Scenario: Lockout resets after success

- GIVEN a client with 4 failed attempts
- WHEN the 5th attempt succeeds
- THEN the failure counter SHALL reset to zero

### Requirement: Master Password Zeroization

The daemon MUST zeroize the master password `[]byte` immediately after key derivation. The password buffer SHALL be overwritten with zeros before release.

#### Scenario: Password cleared after unlock

- GIVEN an unlock request with a master password
- WHEN the key is derived
- THEN the request password buffer SHALL be overwritten with zeros

### Requirement: TOCTOU-Safe Socket Creation

The daemon MUST verify the socket path is not a symlink before binding. If a symlink or unexpected file exists at the socket path, the daemon SHALL refuse to start.

#### Scenario: Symlink at socket path

- GIVEN a symlink exists at the configured socket path
- WHEN the daemon starts
- THEN it SHALL detect the symlink
- AND exit with an error before binding
