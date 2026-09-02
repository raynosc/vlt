# Quick Access — Floating Search Window

[English](quick-access.md) | [Español](es/quick-access.md)

`vlt-quick` provides a compact search-as-you-type window for quickly finding and
copying secret values to the clipboard. It's designed to be bound to a global
hotkey (e.g., Shift+Cmd+K) for instant access.

## Usage

```bash
# Via the vlt CLI:
vlt quick

# Standalone binary:
vlt-quick

# Custom socket path:
vlt quick --socket /tmp/myapp.sock
vlt-quick --socket /tmp/myapp.sock
```

### Exit Codes

| Code | Meaning              |
|------|----------------------|
| 0    | Secret copied        |
| 1    | Cancelled (Esc)      |
| 2    | Error                |

## Keybindings

| Key              | Action              |
|------------------|---------------------|
| Type             | Search secrets      |
| ↑ / ↓            | Navigate results    |
| Ctrl+J / Ctrl+K  | Navigate results    |
| Enter            | Copy to clipboard   |
| Esc              | Close / cancel      |

## How It Works

1. `vlt-quick` connects to the vlt daemon via Unix socket (`/tmp/vlt.sock` by default)
2. If the daemon is not running, it auto-starts it in the background
3. If the vault is locked, it prompts for the master password
4. Secrets are loaded into a compact TUI with a search bar
5. Type to filter secrets by name (case-insensitive)
6. Press Enter to copy the selected secret to clipboard
7. The window auto-closes after 1 second showing "Copied!"

## Setting Up a Global Hotkey (macOS)

### Option 1: macOS Shortcuts App (Recommended)

1. Open the **Shortcuts** app
2. Create a new shortcut with action **Run Shell Script**:
   ```bash
   /path/to/vlt-quick
   ```
   (Use the full path, e.g. `~/go/bin/vlt-quick` or `/usr/local/bin/vlt-quick`)
3. Switch to the **Info** tab (the ⓘ icon)
4. Check **Use as Quick Action**
5. Set **Workflow receives** to `no input` in `any application`
6. Go to **System Settings → Keyboard → Keyboard Shortcuts → Services**
7. Find your shortcut under **General** and assign Shift+Cmd+K

### Option 2: Raycast

1. Open Raycast → Extensions → Create Script Command
2. Name: `vlt-quick`
3. Script:
   ```bash
   #!/bin/bash
   /path/to/vlt-quick
   ```
4. Assign hotkey Shift+Cmd+K in Raycast settings

### Option 3: Alfred

1. Open Alfred → Preferences → Workflows → Create a new workflow
2. Add a **Hotkey** trigger (set to Shift+Cmd+K)
3. Add a **Run Script** action (set to `/path/to/vlt-quick`)
4. Set script type to `/bin/bash` with `with input as argv`

### Option 4: Hammerspoon

```lua
-- ~/.hammerspoon/init.lua
hs.hotkey.bind({"shift", "cmd"}, "P", function()
  hs.task.new("/path/to/vlt-quick", nil):start()
end)
```

### Option 5: Karabiner-Elements

Create a complex modification in
`~/.config/karabiner/assets/complex_modifications/`:

```json
{
  "title": "Launch vlt-quick",
  "rules": [
    {
      "description": "Shift+Cmd+K → vlt-quick",
      "manipulators": [
        {
          "type": "basic",
          "from": {
            "key_code": "p",
            "modifiers": {
              "mandatory": ["left_shift", "left_command"]
            }
          },
          "to": [
            {
              "shell_command": "/path/to/vlt-quick"
            }
          ]
        }
      ]
    }
  ]
}
```

## Requirements

- The `vlt` binary must be installed (for daemon auto-start)
- The `vlt-quick` binary must be on PATH (or in the same directory as `vlt`)
- macOS: `pbcopy` (built-in)
- Linux: `xclip` or `wl-clipboard`
