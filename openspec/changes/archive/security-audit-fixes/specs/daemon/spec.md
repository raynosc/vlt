# Delta for daemon

## ADDED Requirements

### Requirement: macOS Peer Authentication Fail-Closed

The daemon on macOS MUST reject peer connections when peer authentication cannot be verified.

#### Scenario: Peer auth failure

- GIVEN macOS peer authentication fails
- WHEN a peer connection is attempted
- THEN the daemon SHALL reject the connection

#### Scenario: Valid peer accepted

- GIVEN valid macOS peer credentials
- WHEN a peer connection is attempted
- THEN the connection SHALL be accepted

### Requirement: Connection Close Guard

The daemon MUST guard connection close operations with `sync.Once` to prevent double-close panics.

#### Scenario: Concurrent close

- GIVEN an active connection
- WHEN `Close` is invoked multiple times concurrently
- THEN the operation SHALL complete without panic

#### Scenario: Idempotent close

- GIVEN a closed connection
- WHEN `Close` is invoked again
- THEN it SHALL return without error or panic

### Requirement: Child Process Reaping

The quick-start command MUST reap spawned child processes via `cmd.Wait()` to prevent zombie processes.

#### Scenario: Child exits

- GIVEN a spawned child process
- WHEN the child exits
- THEN the parent SHALL call `Wait()` to reap it

#### Scenario: Multiple children

- GIVEN multiple spawned child processes
- WHEN all children exit
- THEN no zombie processes SHALL remain
