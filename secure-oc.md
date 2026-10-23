# secure-oc — Architecture & Internals

## What it is

`secure-oc` is a Python wrapper around [opencode](https://opencode.ai) that:

1. **Stores API keys securely** — Argon2id + AES-256-GCM, protected by a master
   password typed at runtime.
2. **Manages the opencode server lifecycle** — starts, stops and switches
   between foreground/background modes while preserving the server password.
3. **Protects the server** — a random password per server instance, kept out of
   the state file and out of the command line.

It replaces the original single-file `oc.ps1` implementation.

## Module map

| Module | Responsibility |
|--------|----------------|
| `secure_oc/cli.py` | Argument parsing, commands, prompts, attach |
| `secure_oc/crypto.py` | Container format, KDF, AES-256-GCM |
| `secure_oc/secrets_store.py` | At-rest protection of small secrets (keyring/DPAPI/key file) |
| `secure_oc/state.py` | Server state file, HMAC integrity, password reference |
| `secure_oc/server.py` | opencode resolution, process/port management, watchdog |
| `secure_oc/paths.py` | Directory layout and permission hardening |
| `secure_oc/ui.py` | Coloured console output |
| `secure_oc/errors.py` | Exception hierarchy |

## Key store

### Container format (`keys.dat`)

```
┌──────────┬────────────┬──────────────┬────────┬─────────┬──────────────────────┐
│ magic    │ header_len │ header       │ salt   │ nonce   │ ciphertext ‖ tag     │
│ "SOC2"   │ uint32 BE  │ UTF-8 JSON   │ 16 B   │ 12 B    │ AES-256-GCM ‖ 16 B   │
└──────────┴────────────┴──────────────┴────────┴─────────┴──────────────────────┘
```

The header records the version, cipher and KDF parameters, for example:

```json
{"alg":"AES-256-GCM","kdf":"argon2id","m":65536,"nonce_len":12,"p":4,"salt_len":16,"t":3,"v":2}
```

`magic ‖ header` is passed to AES-GCM as **associated data**, so the KDF
parameters cannot be downgraded without failing authentication.

### Key derivation

```
Master password + salt
        │
        ├─ Argon2id (t=3, m=64 MiB, p=4)      ← preferred (argon2-cffi)
        ├─ scrypt   (n=2^16, r=8, p=1)        ← fallback (stdlib)
        └─ PBKDF2-SHA256 (600 000 iterations) ← last resort (stdlib)
        │
    32-byte AES key
        │
   AES-256-GCM decrypt(nonce, ciphertext, tag, aad = magic ‖ header)
        │
   JSON: { "OPENROUTER_API_KEY": "sk-..." }
```

The algorithm actually used is recorded in the header, so a file written on a
machine with Argon2id stays readable (or fails with a clear message) elsewhere.

## Secret store (`secrets_store.py`)

Small secrets — the server password and the state HMAC key — are stored under
a label, protected by the strongest backend available:

| Order | Backend | Notes |
|-------|---------|-------|
| 1 | OS keyring | Windows Credential Manager, macOS Keychain, Secret Service |
| 2 | Windows DPAPI | via `ctypes` (`CryptProtectData`), bound to user + machine |
| 3 | Local key file | random 32-byte key at `secrets/.key` (`0600`) encrypting the secret with AES-GCM |

Each stored file carries a one-byte scheme prefix so retrieval is unambiguous.
The active backend is reported by `oc --help`.

## Server state (`state.py`)

`~/.oc/server-state.json`:

```json
{
  "mode": "foreground|background|transition",
  "pid": 12345,
  "transition": false,
  "hmac": "<base64 HMAC-SHA256>",
  "lastActivity": 1792756237
}
```

| Field | Purpose |
|-------|---------|
| `mode` | Current server mode (`transition` while switching) |
| `pid` | Process ID of the `opencode serve` process |
| `transition` | `true` during a mode switch, to suppress stale cleanup |
| `hmac` | HMAC-SHA256 over the canonical form of the fields, keyed by an **independent** secret from the keyring |
| `lastActivity` | Unix timestamp refreshed on attach and by the watchdog |

**The password is not in this file.** It is fetched from the secret store by
label. This removes the previous design where the HMAC key was derived from the
very password stored in the same file — a circular scheme that did not protect
against an attacker able to decrypt the file.

Writes are atomic (`write_private`: temp file → `os.replace`) and the file is
hardened (`0600` / current-user ACL).

## Server modes

| Mode | Entered with | Blocking | Password changes |
|------|--------------|----------|------------------|
| Foreground | `oc serve` | Yes (terminal blocks) | On fresh start or restart |
| Background | `oc` / `oc serve --background` | No (daemon) | On fresh start or restart |

Mode switches **preserve the password** so active `opencode attach` sessions
stay authenticated. A `transition` flag is written *before* killing the old
process, closing the race where the dying process's cleanup could delete the
new server's state.

## Process management

### opencode resolution

```python
path = shutil.which("opencode")
# CreateProcess cannot run a .ps1 wrapper; npm ships a .cmd sibling
if path.endswith(".ps1") and exists(path[:-4] + ".cmd"):
    return path[:-4] + ".cmd"
```

### Launching

`subprocess.Popen([opencode, "serve", "--port", PORT], cwd=Path.home(), env=...)`

- **Background:** `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW`
  on Windows, `start_new_session=True` on POSIX, with stdio to `DEVNULL`.
- **Foreground:** a normal child process; the parent blocks on `wait()`.
- The environment is the parent's plus the injected API keys and
  `OPENCODE_SERVER_PASSWORD`; the parent's own environment is never modified.
- The working directory is the home directory so the project folder is not
  locked.

### PID correction

When the npm `.cmd` wrapper is used, the returned PID is `cmd.exe`, not
`opencode`. After the port is listening, `listener_pid()` (psutil, else
`netstat`/`ss`) finds the real owner and the state file is corrected.

### Stopping

Priority: state-file PID → the process owning the server port. The server is
never matched **by name** (which would kill attach clients too). Uses psutil
`terminate()`/`kill()`, else `taskkill /PID /T /F` (Windows) or `SIGTERM`.

## Idle watchdog

`oc serve --background` spawns a detached `python -m secure_oc __watchdog`
process (no base64-encoded script, unlike the PowerShell version). Every 60 s
it:

1. reads `lastActivity`;
2. if the idle time exceeds the timeout, re-checks the PID has not changed;
3. counts established connections — if any (or if the count is **unknown**), it
   refreshes `lastActivity` and keeps the server alive;
4. otherwise stops the server and clears the state.

Being conservative when the connection count is unknown prevents the watchdog
from killing a server that is actually busy.

## CLI

```
oc                          Start opencode (start server if needed, attach)
oc serve [--background|--status|--restart]
oc encrypt
oc decrypt
oc reveal [--print]
oc stop
oc session [args..]
oc model [args..]
oc --dir <path>
oc --help
```

- Secrets are read with `getpass` (hidden) on a TTY; when stdin is not a TTY
  they are read as a line, so the tool can be scripted and tested.
- `oc reveal` copies values to the clipboard; it never prints them unless
  `--print` is given **and** the user confirms.

## Key files

| Path | Purpose |
|------|---------|
| `secure_oc/` | Python package |
| `build.py` | Builds the standalone binary (the workflow packages it) |
| `packaging/oc.spec` | PyInstaller spec |
| `packaging/entrypoint.py` | Entry point used by the frozen binary |
| `~/.oc/keys.dat` | Encrypted API keys |
| `~/.oc/server-state.json` | Server state (no password) |
| `~/.oc/secrets/` | Secret-store files when no keyring is available |
| `README.md` | Usage documentation |
| `secure-oc.md` | This document |

## Requirements

- Python 3.9+
- `cryptography` (required); `argon2-cffi`, `keyring`, `psutil` (recommended)
- opencode available in `PATH`
