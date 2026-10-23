# secure-oc

A Python wrapper that securely stores and injects API keys into
[opencode](https://opencode.ai) and manages the lifecycle of its local server.

Your API keys are encrypted with **AES-256-GCM** (authenticated encryption)
using a key derived with **Argon2id** (falling back to scrypt/PBKDF2 when
`argon2-cffi` is unavailable), protected by a master password you type at
runtime. The encrypted keys live in a single file under your home directory,
never in the project you are working on.

The server password is kept out of the state file entirely: it lives in your
**OS keyring** (Windows Credential Manager, macOS Keychain, freedesktop Secret
Service), or DPAPI on Windows, and is never passed on the command line.

## Requirements

- **Python 3.9+**
- [opencode](https://opencode.ai) installed and available in `PATH`
- `cryptography` (required)
- `argon2-cffi`, `keyring`, `psutil` (recommended — see below)

## Install

```sh
python -m pip install -r requirements.txt
```

or, as an editable package that provides a `secure-oc` entry point:

```sh
python -m pip install -e ".[full]"
```

The `oc`, `oc.cmd` and `oc.ps1` launchers in this directory run the package
without installing it, as long as Python is on `PATH`.

| Platform | Launcher |
|----------|----------|
| Linux / macOS | `./oc` |
| Windows (PowerShell) | `.\oc` or `.\oc.ps1` |
| Windows (cmd.exe) | `oc.cmd` |

## Commands

| Command | Description |
|---------|-------------|
| `oc` | Start or attach to opencode (starts the background server if needed) |
| `oc serve` | Start a persistent server in the **foreground** |
| `oc serve --background` | Start a persistent server as a **background daemon** |
| `oc serve --status` | Show server status (mode, sessions, idle timer) |
| `oc serve --restart` | Kill and restart the server with a new password |
| `oc encrypt` | Encrypt and store API keys |
| `oc decrypt` | List stored API key names |
| `oc reveal` | Copy key values to the **clipboard** (never to stdout) |
| `oc reveal --print` | Print key values (asks for confirmation) |
| `oc stop` | Stop the running server |
| `oc --dir <path>` | Attach with a specific working directory |
| `oc session [args..]` | Manage opencode sessions |
| `oc model [args..]` | List AI models |
| `oc --help` | Show help |

The old `-Dir` / `-Background` / `-Status` / `-Restart` spellings are still
accepted; the long `--flag` forms are preferred.

## Quick start

### 1. Encrypt your API keys

```sh
oc encrypt
```

You are prompted for a **master password** (twice) and then for one or more
key name/value pairs (e.g. `OPENROUTER_API_KEY`). **Values are hidden while
you type.** Leave the key name empty to finish.

### 2. List stored keys

```sh
oc decrypt
```

To move the values to the clipboard instead of the terminal:

```sh
oc reveal
```

### 3. Launch opencode

```sh
oc
```

- **First run:** prompts for your master password, starts a password-protected
  background `opencode serve`, and attaches your TUI session.
- **Later runs:** detects the running server and attaches directly — **no
  master password prompt**.
- Use `oc stop` when you are done.

### 4. Persistent server

```sh
oc serve --background   # daemon, survives closing the terminal
oc serve                # foreground, shows logs, Ctrl+C to stop
```

Background servers auto-stop after **15 minutes without an active session**.

### 5. Inspect and restart

```sh
oc serve --status     # mode, sessions, idle countdown
oc serve --restart    # kill and restart with a NEW password
```

## Security model

### Key store

| Property | Value |
|----------|-------|
| Cipher | AES-256-GCM (authenticated) |
| Key derivation | Argon2id (t=3, m=64 MiB, p=4), else scrypt, else PBKDF2-SHA256 (600k) |
| Location | `~/.oc/keys.dat` (`%USERPROFILE%\.oc\keys.dat` on Windows) |
| Permissions | `0600` on POSIX, current-user-only ACL on Windows |
| Container | `SOC2` magic + JSON header authenticated as AEAD associated data |

The JSON header records the KDF and its parameters and is authenticated, so a
downgrade of the KDF parameters makes decryption fail instead of silently
weakening the file. The master password is **never stored** and is only held
in memory while the keys are decrypted.

### Server protection

- A fresh **random password** is generated each time the server starts.
- The password is **not stored in the state file**. It lives in the OS keyring
  (or DPAPI / a `0600` key file as a last resort).
- The state file is protected by **HMAC-SHA256** using a key that is
  independent of the server password — tampering is detected instead of being
  silently accepted.
- `oc attach` passes the password via the `OPENCODE_SERVER_PASSWORD`
  environment variable, **never** as a command-line argument.
- The server process working directory is your **home directory**, so the
  project folder is never locked.

### What changed versus the PowerShell version

- **No `-ShowValues` on stdout.** `oc reveal` copies to the clipboard by
  default; printing requires an explicit `--print` and a confirmation.
- **No plaintext fallback.** On systems without a keyring, the server password
  is encrypted with a `0600` key file and the backend is reported in `--help`.
- **No circular HMAC.** The integrity key no longer derives from the password
  stored next to it.
- **Key values are hidden while typing** (`getpass`) instead of echoed by
  `Read-Host`.
- **The key store is outside the repository**, so it cannot be committed by
  accident.

### Honest limitations

- API keys must still be handed to `opencode serve` through its environment.
  Any process running as your user can read a process environment, so this is
  not a boundary against a local attacker with your privileges — it protects
  the keys at rest.
- The fallback key-file backend (headless POSIX without a keyring) only
  protects against casual file reads.

## State files

Everything lives under `~/.oc/`:

| Path | Purpose |
|------|---------|
| `keys.dat` | AES-256-GCM encrypted API keys |
| `server-state.json` | Mode, PID, idle timestamp, HMAC (no password) |
| `secrets/` | Backend files when no OS keyring is available |

Set `SECURE_OC_HOME` to relocate the whole directory, and `SECURE_OC_PORT` to
change the server port (default `4096`).

## Migrating from the PowerShell version

The container format changed, so old `api-keys.dat` files are **not** read.
Re-run `oc encrypt` once and delete the old `api-keys.dat`.

## License

MIT
