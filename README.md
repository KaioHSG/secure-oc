# secure-oc

A PowerShell wrapper that securely stores and injects API keys into [OpenCode](https://opencode.ai), the AI coding assistant.

Your API keys are encrypted with **AES-256-GCM** (authenticated encryption) using **PBKDF2** (600,000 iterations, SHA-256) with a random salt and nonce, protected by a master password. The encrypted keys live in a single `api-keys.dat` file.

## Commands

| Command | Description |
|---------|-------------|
| `oc` | Start or attach to OpenCode (starts background server if needed) |
| `oc serve` | Start a persistent server in the **foreground** |
| `oc serve -Background` | Start a persistent server as a **background daemon** |
| `oc serve -Status` | Show server status (mode, password hint) |
| `oc serve -Restart` | Kill and restart the server with a new password |
| `oc encrypt` | Encrypt and store API keys |
| `oc decrypt` | List stored API key names |
| `oc decrypt -ShowValues` | Show key values (use with care!) |
| `oc stop` | Stop the running server |
| `oc -Dir <path>` | Attach with a specific working directory |
| `oc -Help` | Show help |

## Server modes

The server can run in two modes, and you can switch between them:

| Mode | Command to enter | Persistence |
|------|------------------|-------------|
| **Foreground** | `oc serve` | Runs in the current terminal, shows logs, Ctrl+C to stop |
| **Background** | `oc` or `oc serve -Background` | Runs as a daemon, auto-stops after 15 min without an active session — use `oc stop` to shut down sooner |

### Mode switching rules

- **`oc serve -Background`** on a foreground server → restarts it as a background server (keeps password)
- **`oc serve -Background`** on a background server → no-op (server already in background mode)
- **`oc serve`** on a background server → restarts it as a foreground server (keeps password)

When switching modes, the **server password is preserved** so active attach sessions stay authenticated. The password only changes on a fresh start or explicit restart (`oc serve -Restart`).

## Quick start

### 1. Encrypt your API keys

```powershell
.\oc.ps1 encrypt
```

You will be prompted for:
- A **master password** (used to encrypt the file)
- One or more **key name/value pairs** (e.g. `OPENROUTER_API_KEY`, `OPENAI_API_KEY`)

Leave the key name empty to finish. An `api-keys.dat` file is created.

### 2. List stored keys

```powershell
.\oc.ps1 decrypt
```

Shows the names of all keys stored in the file. To also reveal the values (use with care):

```powershell
.\oc.ps1 decrypt -ShowValues
```

### 3. Launch OpenCode

```powershell
.\oc.ps1
```

- **First run:** prompts for your master password, starts a password-protected headless `opencode serve`, and attaches your TUI session. When you exit, the server stays alive.
- **Subsequent runs:** detect the existing server and attach directly — **no master password prompt**. You can attach from multiple terminals simultaneously.
- Use `oc stop` to shut down the server when you're done.

### 4. Foreground persistent server

```powershell
.\oc.ps1 serve
```

Runs the server in the current terminal, showing OpenCode's logs. Close the terminal or press Ctrl+C to stop. Other terminals can still attach.

### 5. Background persistent server (daemon)

```powershell
.\oc.ps1 serve -Background
```

Runs the server in the background, surviving terminal closure. Stop it manually:

```powershell
.\oc.ps1 stop
```

### 6. Inspect and restart

```powershell
.\oc.ps1 serve -Status     # Show mode, password hint
.\oc.ps1 serve -Restart    # Kill and restart with a NEW password
```

## Server lifecycle

| Scenario | Behavior |
|----------|----------|
| First `oc` in any terminal | Starts password-protected server (asks master password), attaches, server persists after exit |
| Subsequent `oc` in any terminal | Attaches directly (no master password), server stays alive |
| `oc serve` (foreground) | Server runs in this terminal; closes when terminal closes |
| `oc serve -Background` | Persistent daemon — auto-stops after 15 min idle, or `oc stop` shuts it down immediately |
| `oc stop` | Kills the server immediately |

## Security

The OpenCode server is protected by an **auto-generated random password** created each time the server starts:

- Password is generated from a cryptographically random GUID
- Set via `OPENCODE_SERVER_PASSWORD` environment variable in the server process only (never in the parent session)
- Stored in `%USERPROFILE%\.oc\server-state.json` encrypted with **DPAPI** (Windows Data Protection API — bound to the current user and machine)
- State file includes **HMAC-SHA256** integrity protection against tampering
- State directory and files have **restrictive ACLs** (current user only)
- `oc attach` passes the password via `OPENCODE_SERVER_PASSWORD` environment variable (never as a CLI argument)
- Other processes on the same machine **cannot connect** without the password
- Background servers run an **idle watchdog**: after 15 minutes without an active session, the server is stopped and the state file is removed

The master password for `api-keys.dat` is **never stored** — it is prompted each time a server starts.

## State files

All runtime state lives in `%USERPROFILE%\.oc\`:

| Path | Purpose |
|------|---------|
| `server-state.json` | Current mode, DPAPI-encrypted password, process PID, transition flag, HMAC integrity hash |

## Requirements

- PowerShell 5+ (`pwsh` recommended)
- [OpenCode](https://opencode.ai) installed and available in `PATH`
