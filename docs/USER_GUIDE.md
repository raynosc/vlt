# vlt User Guide

[English](USER_GUIDE.md) | [Español](es/USER_GUIDE.md)

`vlt` is a local-first, zero-knowledge secrets manager for developers. This guide will take you from installation to advanced use of all its interfaces.

## Table of Contents

1.  [Installation](#installation)
2.  [Getting Started](#getting-started)
3.  [Key Concepts](#key-concepts)
4.  [Using the CLI (`vlt`)](#using-the-cli-vlt)
5.  [Using the GUI (`vlt-gui`)](#using-the-gui-vlt-gui)
6.  [Using the TUI (`vlt-tui`)](#using-the-tui-vlt-tui)
7.  [Synchronization](#synchronization)
8.  [Troubleshooting](#troubleshooting)

---

## Installation

### Option 1: Pre-compiled Binaries

Download the binaries from the GitHub repository's releases page and place them in your `PATH`.

### Option 2: With `go install`

If you have Go 1.26+ installed:

```bash
go install github.com/raynosc/vlt/cmd/vlt@latest
go install github.com/raynosc/vlt/cmd/vlt-gui@latest
go install github.com/raynosc/vlt/cmd/vlt-tui@latest
```

### Option 3: Build from Source

```bash
git clone https://github.com/raynosc/vlt.git
cd vlt
make build
```

This will generate the binaries in the `bin/` directory.

---

## Getting Started

### 1. Initialize the Vault

The first time you use `vlt`, you need to initialize your vault:

```bash
./bin/vlt init
```

You will be asked to create a secure **master password**. This password is the only key to access all your secrets. **DO NOT forget it.**

### 2. Unlock the Vault

Every time you use `vlt`, you will be asked for the master password to unlock the vault. You can also use the `PASSWD_MASTER_PASSWORD` environment variable for scripts (with caution).

### 3. Store your First Secret

```bash
./bin/vlt add my-github-token --value "ghp_xxxxxxxxxxxx"
./bin/vlt list
```

---

## Key Concepts

*   **Master Password:** The password that protects your entire vault. It derives the actual encryption key (Argon2id) and is never stored on disk.
*   **Vault:** Encrypted SQLite file (`vault.sqlite`) that stores all your secrets. Location: `~/.config/passwd/` (Linux), `~/Library/Application Support/passwd/` (macOS).
*   **Secret:** Basic storage unit. Each secret has a name, a (encrypted) value, and metadata (type, tags, notes).
*   **Zero-Knowledge Encryption:** The value of each secret is individually encrypted with AES-256-GCM. Decryption happens only on your device, using your master password.

---

## Using the CLI (`vlt`)

`vlt` is the primary command-line interface. Run `./bin/vlt` or `vlt` (if it's in your PATH).

### Adding Secrets

*   **Interactive:**
    ```bash
    vlt add my-secret
    # You will be prompted for: Name, Value, Notes (optional)
    ```

*   **Non-interactive (scripts / CI):** the value is read from `stdin`, never as an argument (so it doesn't end up in your history or process list).
    ```bash
    echo "sk-xxx" | vlt add my-api-key --stdin --type api_key
    ```

*   **With metadata:**
    ```bash
    vlt add github --type password --tags "work,git" --notes "company account"
    ```

*   **From a file (certificate, SSH key):** auto-detects format; if you omit the name, it uses the filename.
    ```bash
    vlt add --file cert.pem
    vlt add --file ~/.ssh/id_ed25519
    # For PKCS#12 (.p12 bundle) with decryption password:
    vlt add --file bundle.p12 --password p12pass
    ```

**`add` flags:** `--type` (`password`, `api_key`, `certificate`, `ssh_key`, `note`, `other`) · `--tags` (comma-separated) · `--notes` · `--stdin` · `--file` · `--password` (only with `--file`) · `--overwrite`.

### Listing and Searching Secrets

```bash
# List all secrets
vlt list

# Filter by type (values: password, api_key, certificate, ssh_key, note, other)
vlt list --kind certificate
vlt list --kind password
vlt list --kind ssh_key

# Filter by tag, or list all tags with their count
vlt list --tag production
vlt list --tags

# Search by name
vlt search github

# List secrets about to expire (in days)
vlt list --expiring 30
```

### Getting and Showing Secrets

```bash
# Show the secret's value
vlt get my-secret

# Copy to clipboard (auto-clears after 30s, only if you didn't copy something else)
vlt get my-secret --copy

# Show the secret in JSON
vlt get my-secret --json
```

### Editing and Deleting Secrets

```bash
# Edit interactively
vlt edit my-secret

# Delete
vlt rm my-secret
```

### Generating Secure Passwords

```bash
# Generate a random password (24 characters by default)
vlt generate

# Options:
vlt generate --length 32        # or -l 32
vlt generate --no-symbols       # exclude symbols
vlt generate --copy             # copy to clipboard instead of printing (or -c)
```

### Import and Export

#### Import

`vlt import <file>` detects the format from the **file extension**:

```bash
# CSV or JSON (standard export schema: each record needs name + password)
vlt import passwords.csv
vlt import data.json

# Validate the file WITHOUT saving anything (recommended before real import)
vlt import passwords.csv --dry-run

# Replace existing secrets with the same name
vlt import passwords.csv --overwrite

# Import a TOTP from a QR code image (otpauth://)
vlt import qr-code.png --qr
```

> Only `.csv` and `.json` extensions are accepted (or an image with `--qr`). Any other extension results in an error. Records without a name or password are skipped. The OTP seed is stored encrypted inside the secret's value, never in plaintext metadata.

**`import` flags:** `--dry-run` · `--overwrite` · `--qr`.

#### Export

```bash
# Export all passwords to CSV or JSON
vlt export --format csv --force
vlt export --format json --force

# Export only one type of secret
vlt export --kind password --format json --force

# Export certificates/keys to files in a directory
vlt export --kind certificate --output ./backup --force
```

**`export` flags:** `--format` (`csv` | `json`) · `--kind` (`password`, `api_key`, `certificate`, `ssh_key`, …; empty = all) · `--output` (directory for certificates/keys) · `--force` (skips confirmation; required in non-interactive use).

> ⚠️ An export places your secrets in **plaintext** on disk. Delete it as soon as you're done and never upload it to a repository or backup unencrypted.

### Multiple Vaults (environments on the same machine)

If you want to separate secrets by context — for example, `work`, `personal`, `client-X` — you can have **several independent vaults** on the same machine. Each is a separate SQLite file with its own master password.

```bash
# List available vaults and see which one is active
vlt vault list

# Create a new vault
vlt vault create work

# Switch active vault (the following commands operate on it)
vlt vault switch work

# Delete a vault
vlt vault remove client-X
```

> Each vault is unlocked with ITS OWN master password and does not share secrets with the others. To share the same set of secrets across **different devices**, do not use separate vaults: use synchronization (see below).

### Inspection (Without Storing)

Analyze a file without saving it to the vault:

```bash
vlt inspect cert.pem
vlt inspect --json cert.pem
```

### Security Audit

Verify your vault's health:

```bash
vlt audit
```

### Locking and Unlocking

*   **Lock (close the vault / forget daemon session):**
    ```bash
    vlt lock
    ```

*   **Unlock:** there is no separate command. Unlocking is requested **automatically** the first time a command needs to access the vault (prompts for the master password, or uses Touch ID in the macOS GUI).

### Environment Variables

*   `PASSWD_MASTER_PASSWORD`: For scripts and CI.
    ```bash
    PASSWD_MASTER_PASSWORD=my-pass vlt list
    ```
*   `--no-env`: Ignore the environment variable for security.

---

## Using the GUI (`vlt-gui`)

`vlt-gui` offers a native graphical interface using Fyne.

### Starting the GUI

```bash
./bin/vlt-gui
# or
vlt-gui
```

### Unlocking

Upon starting, an unlock screen is displayed. On macOS, you can use **Touch ID** to unlock without typing the master password.

### Main Interface

The interface is divided into three columns:

1.  **Left Sidebar:** List of secret categories (All, Passwords, API Keys, Certificates, SSH, Notes) and access to multiple vaults (if you use them).
2.  **Central Column:** List of secrets in the selected category.
3.  **Right Panel:** Selected secret details. Allows editing name, user, URL, password (with show/hide button), TOTP (with counter), and notes.

### Adding a Secret

*   Click the **"+"** button or use the keyboard shortcut.
*   Select the secret type (Password, API Key, Certificate, SSH, Note).
*   Fill in the fields. You can generate a secure password with the dice button (🎲).

### Watchtower

Access the security dashboard from the "shield" icon in the sidebar. It identifies:
*   Weak or duplicated passwords.
*   Secrets without TOTP enabled.
*   Certificates about to expire.

### Quick Access (`vlt-quick`)

For ultra-fast access:
1.  Run `./bin/vlt-gui --quick` or activate the popup from the system tray.
2.  Bind a global keyboard shortcut (e.g., `Shift+Cmd+K`) with tools like **macOS Shortcuts**, **Raycast**, or **Alfred**.
3.  Type the secret's name and press Enter to copy it to the clipboard.

### Preferences

*   **Theme:** Dark (default).
*   **Auto-lock:** Configurable (inactivity time before locking).

---

## Using the TUI (`vlt-tui`)

`vlt-tui` is an interactive terminal user interface for those who prefer to work from the command line without leaving the terminal.

### Starting the TUI

```bash
./bin/vlt-tui
```

### Navigation

*   Use **arrow keys** to navigate the secret list.
*   Press **Enter** to view the selected secret details.
*   Press **Tab** to switch between panels.
*   Press **Esc** to go back or close dialogs.

### Actions

*   **a**: Add a new secret.
*   **e**: Edit the selected secret.
*   **d**: Delete the selected secret.
*   **Ctrl+f**: Search secrets.
*   **Ctrl+l**: Lock the vault.
*   **q**: Quit the TUI.

---

## Synchronization (multiple environments)

`vlt` synchronizes the same vault across multiple devices in a **zero-knowledge** manner against a self-hostable `vlt-sync` server.

### Concepts

*   **`vlt-sync` server:** self-hostable server that only stores one **encrypted blob** per vault. It never sees your plaintext secrets.
*   **`sync_encryption_key`:** AES-256 key that encrypts the blob. It is generated on your device during `sync init` and saved **inside your vault**, wrapped with your master password.
*   **API key:** generated on the client during `sync init` (the server only stores its SHA-256 hash). Used to authenticate your `push`/`pull` requests.
*   **Trust model:** the client does not trust the server. A malicious server cannot read your secrets, resurrect a deleted one (tombstones), or force you back to an old state (monotonic sequence check).

### Quick path

```bash
# 1. (Once) Configure sync on the FIRST device
vlt sync init --server https://your-server.com

# 2. Push local state to the server
vlt sync push

# 3. Later / on another device, pull changes
vlt sync pull

# 4. View sync status
vlt sync status
```

> For HTTP without TLS (trusted networks / testing only), add `--insecure`. In production, always use `https://`.

### Configuring a second device (same vault)

The `sync_encryption_key` and API key live **inside the vault file**. Therefore, to sync the **same** set of secrets on another machine, do **not** run `vlt init` or `sync init` again (this would create a different vault, and a repeated `sync init` is rejected by the server). Instead:

1.  Copy the vault file (`*.sqlite`) from the first device to the second, to the same config path (see [Key Concepts](#key-concepts)). For example, with `scp`.
2.  On the second device, unlock with the **same master password** and pull the changes:
    ```bash
    vlt sync pull
    ```
3.  From then on, both devices share the vault: `push` to upload, `pull` to download.

> The copied vault already contains the `vault_uuid`, `sync_encryption_key`, and API key (all encrypted with your master key), so the second device is ready without re-registering anything.

### Recover API key

```bash
vlt sync show-key
```

### Command reference

| Command | What it does |
|---|---|
| `vlt sync init --server <url>` | Generates the vault UUID, `sync_encryption_key`, and API key; registers the vault on the server. |
| `vlt sync push` | Encrypts the vault and uploads it (optimistic concurrency via sequence number). |
| `vlt sync pull` | Downloads the blob, verifies integrity and sequence, and merges (last-writer-wins with tombstones). |
| `vlt sync status` | Shows sync status (accepts `--json`). |
| `vlt sync show-key` | Reveals the stored API key. |

To deploy the server (Docker, TLS/Caddy, certificates), consult [docs/SYNC-DEPLOYMENT.md](SYNC-DEPLOYMENT.md), [docs/SYNC_API.md](SYNC_API.md), and [docs/TLS-CERTIFICATES.md](TLS-CERTIFICATES.md).

---

## Troubleshooting

### Vault won't unlock

*   Forgot your master password?
    *   If you have a **Recovery Kit** (24 words), use it to restore access.
    *   If not, the vault is unrecoverable. **We never store the password.**
*   Are you using the `PASSWD_MASTER_PASSWORD` variable and `--no-env` at the same time?

### `vlt-gui` does not show Touch ID

*   Make sure the binary is **code signed**. On macOS, Touch ID requires specific Entitlements applied during code signing.
*   Check that the Keychain has the correct entry.

### Import error

*   **"unsupported file format":** `import` only accepts `.csv` or `.json` files (or an image with `--qr`). Rename or convert the file.
*   **Skipped records:** each record needs at least a name and a password; those without them are discarded. First run `vlt import file.csv --dry-run` to see what would be imported without saving anything.

### Sync fails

*   Is the `vlt-sync` server running and accessible at the configured URL?
*   **"rollback detected":** the server returned an older state than the local one. This is an anti-rollback protection; verify you are pointing to the correct server and there isn't an outdated blob.
*   **Sequence conflict (409):** someone pushed changes before you. `push` performs an automatic `pull` and retries once; if it fails again, manually run `vlt sync pull` and try again.
*   **Second device does not see secrets:** ensure you have **copied the vault file** (not run `sync init` again) and unlock with the same master password.

### Diagnostic Commands

*   **Version:**
    ```bash
    vlt version
    ```
*   **Check vault health:**
    ```bash
    vlt check
    ```
*   **Linting and testing:**
    ```bash
    make lint
    make test
    ```
