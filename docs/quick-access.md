# Quick Access — Floating Search Window

[English](quick-access.md) | [Español](es/quick-access.md)

Quick Access provides a compact floating search window for quickly finding and
copying secret values to the clipboard. It is built directly into the native desktop
application (`vlt-gui --quick`) and designed to be bound to a global hotkey
(e.g., `Shift+Cmd+K` or `Shift+Cmd+Space`) for instant access from anywhere.

## Usage

```bash
# Launch Quick Access popup:
vlt-gui --quick

# Or via Makefile:
make run-quick

# From macOS application bundle:
/Applications/vlt.app/Contents/MacOS/vlt --quick
```

## Keybindings

| Key              | Action                                       |
|------------------|----------------------------------------------|
| Type             | Search secrets (live filtering)              |
| ↑ / ↓            | Navigate matching results                    |
| Enter            | Copy selected secret value to clipboard      |
| Esc              | Close / cancel popup                         |

## How It Works

1. `vlt-gui --quick` connects via a lightweight local IPC socket (`/tmp/vlt-gui.sock`). If the GUI is already running, it brings the Quick Access popup to the foreground instantly. If not running, it starts in Quick Access mode directly.
2. If the vault is locked, the popup prompts for the master password right in the compact window without opening the full desktop dashboard.
3. Secrets are loaded into a compact list with live search-as-you-type filtering.
4. Pressing **Enter** copies the secret value to the system clipboard and initiates secure auto-clearing via `vlt __clear-clipboard`.
5. The window automatically closes upon copying or when pressing **Esc**.

## Setting Up a Global Hotkey (macOS)

### Option 1: macOS Shortcuts App (Recommended)

1. Open the **Shortcuts** app.
2. Create a new shortcut with action **Run Shell Script**:
   ```bash
   /usr/local/bin/vlt-gui --quick
   # or for .app bundle:
   /Applications/vlt.app/Contents/MacOS/vlt --quick
   ```
3. Switch to the **Info** tab (the ⓘ icon).
4. Check **Use as Quick Action**.
5. Set **Workflow receives** to `no input` in `any application`.
6. Go to **System Settings → Keyboard → Keyboard Shortcuts → Services**.
7. Find your shortcut under **General** and assign `Shift+Cmd+K`.

### Option 2: Raycast

1. Open Raycast → **Extensions** → **Create Script Command**.
2. Name: `vlt Quick Access`.
3. Script:
   ```bash
   #!/bin/bash
   /usr/local/bin/vlt-gui --quick
   ```
4. Assign hotkey `Shift+Cmd+K` in Raycast settings.

### Option 3: Alfred

1. Open Alfred → **Preferences** → **Workflows** → Create a new workflow.
2. Add a **Hotkey** trigger (e.g. `Shift+Cmd+K`).
3. Add a **Run Script** action:
   ```bash
   /usr/local/bin/vlt-gui --quick
   ```
4. Set script type to `/bin/bash` with `with input as argv`.

### Option 4: Hammerspoon

```lua
-- ~/.hammerspoon/init.lua
hs.hotkey.bind({"shift", "cmd"}, "K", function()
  hs.task.new("/usr/local/bin/vlt-gui", {"--quick"}):start()
end)
```

### Option 5: Karabiner-Elements

Create a complex modification in `~/.config/karabiner/assets/complex_modifications/`:

```json
{
  "title": "Launch vlt Quick Access",
  "rules": [
    {
      "description": "Shift+Cmd+K → vlt Quick Access",
      "manipulators": [
        {
          "type": "basic",
          "from": {
            "key_code": "k",
            "modifiers": {
              "mandatory": ["left_shift", "left_command"]
            }
          },
          "to": [
            {
              "shell_command": "/usr/local/bin/vlt-gui --quick"
            }
          ]
        }
      ]
    }
  ]
}
```

## Requirements

- `vlt-gui` installed (via Homebrew `brew install --cask raynosc/vlt/vlt`, package bundle, or `make build`).
- macOS: `pbcopy` (built-in).
- Linux: `xclip` or `wl-clipboard`.
