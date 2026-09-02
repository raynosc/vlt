# gui-auto-lock Specification

## Purpose

Standalone idle/blur auto-lock for the GUI (`vlt-gui`), independent of the daemon. Today
the daemon auto-locks the vault on idle; a user running `vlt-gui` directly (no daemon)
gets no auto-lock. This capability locks the vault from the GUI itself after an idle
timeout or when the window loses focus, dismissing sensitive state from the UI.

## Threat Model

- **Threat**: User unlocks the vault in `vlt-gui`, walks away (or switches apps), the
  vault stays unlocked on screen. A passerby reads secrets, or a screen-share /
  screenshot tool captures them.
- **Asset**: The unlocked in-GUI vault view showing decrypted secret metadata and values.
- **Mitigations**: Idle timer keyed off GUI input activity; window-hidden / focus-lost
  event; configurable timeout with a sensible default; on lock, the GUI drops all
  decrypted state and shows the unlock screen.
- **Residual risk**: A passerby within the idle window read; mitigated by a low default
  timeout and lock-on-window-hide. Focus-lost on Wayland/some WMs may not fire — idle
  timer is the primary guarantee.

## Requirements

### Requirement: U-07 Standalone GUI Auto-Lock

The GUI MUST auto-lock the vault after a configurable idle timeout when no daemon is
running, without depending on the daemon's auto-lock. The default idle timeout SHALL be 5
minutes. The user MAY configure the timeout (including disabling it via 0).

#### Scenario: Idle timeout auto-locks vault

- GIVEN `vlt-gui` is running unlocked with no daemon, idle timeout set to 5 minutes
- WHEN the user is inactive for 5 minutes
- THEN the vault SHALL lock
- AND the GUI SHALL navigate to the unlock screen
- AND decrypted secret/metadata state SHALL be cleared from the UI

#### Scenario: User activity resets the idle timer

- GIVEN an unlocked GUI idle timer near expiry
- WHEN the user interacts with the canvas (key/mouse)
- THEN the idle timer SHALL reset to the full timeout
- AND SHALL NOT lock prematurely

#### Scenario: Custom timeout honored

- GIVEN a user-configured idle timeout of 1 minute
- WHEN the user is inactive for 1 minute
- THEN the vault SHALL lock

#### Scenario: Disabled timeout does not auto-lock

- GIVEN the idle timeout set to 0 (disabled)
- WHEN the user is inactive indefinitely
- THEN the GUI SHALL NOT auto-lock on idle

### Requirement: U-07 Lock on Window Hide

The GUI MUST lock the vault when its window is hidden (minimized, switched away, or loses
focus to another application), unless the user has explicitly disabled lock-on-hide.

#### Scenario: Window hidden locks vault

- GIVEN an unlocked GUI
- WHEN the window is hidden or loses focus
- THEN the vault SHALL lock and clear sensitive UI state

#### Scenario: Lock-on-hide disabled keeps vault open

- GIVEN the user disabled lock-on-hide
- WHEN the window is hidden and restored
- THEN the vault SHALL remain unlocked

### Requirement: U-07 Auto-Lock Menu and Status

The GUI MUST expose an auto-lock menu item showing the current timeout and a way to
change it. The menu SHALL indicate whether auto-lock is enforced by the standalone GUI
or by the daemon (so users running both understand which is active).

#### Scenario: Menu shows current timeout

- GIVEN an unlocked GUI with idle timeout = 5 minutes
- WHEN the user opens the auto-lock menu
- THEN the active timeout SHALL be displayed

#### Scenario: Menu indicates enforcement source

- GIVEN `vlt-gui` running with no daemon
- WHEN the user opens the auto-lock menu
- THEN the menu SHALL indicate standalone-GUI enforcement

#### Scenario: Menu lets user change timeout

- GIVEN the auto-lock menu open
- WHEN the user selects a different timeout
- THEN the idle timer SHALL be updated to the new value without restarting the GUI