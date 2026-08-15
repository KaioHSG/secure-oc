# secure-oc — Architecture & Internals

## What it is

`secure-oc` is a PowerShell wrapper around [opencode](https://opencode.ai) that:

1. **Stores API keys securely** — encrypts them with AES-256 + PBKDF2, protected by a master password you type at runtime
2. **Manages the opencode server lifecycle** — starts, stops, and switches between foreground/background modes while preserving the server password
3. **Protects the server** — auto-generates a random password for each server instance so other processes on the same machine cannot connect without it

---

## How the encryption works

### Key storage file: `api-keys.dat`

```
┌───────────────────────────────────────────────────────────────┐
│ Salt (16 bytes) │ Nonce (12 bytes) │ Ciphertext │ Tag (16 B)  │
└───────────────────────────────────────────────────────────────┘
```

- **Salt** — random, generated once per file via `RandomNumberGenerator`
- **Nonce** — random 12-byte nonce, generated per file
- **Ciphertext** — AES-256-GCM encrypted JSON of key-value pairs
- **Tag** — 16-byte GCM authentication tag; tampering is detected on decrypt

### Key derivation

```
Master Password + Salt
        ↓
  PBKDF2 (SHA-256, 600,000 iterations)
        ↓
   32-byte AES key
        ↓
  AES-256-GCM decrypt(Nonce, Ciphertext, Tag)
        ↓
  JSON: { "OPENROUTER_API_KEY": "sk-...", "OPENAI_API_KEY": "sk-..." }
```

GCM provides both confidentiality and integrity: any modification to the
file (or a wrong password) makes decryption fail with an authentication
error. The master password is **never stored** — it is prompted at runtime
via `Get-Credential` and erased from memory immediately after use.

---

## Server modes

The server runs in one of two modes, tracked in the state file:

| Mode | `state.mode` | Blocking? | Password changes? |
|------|-------------|-----------|-------------------|
| Foreground | `"foreground"` | Yes (terminal blocks) | On fresh start or restart |
| Background | `"background"` | No (daemon) | On fresh start or restart |

Background servers are watched by an **idle watchdog** (a detached `pwsh`
process spawned at server start). It refreshes `lastActivity` while
established connections exist and, once the last session has been closed
for `$idleTimeoutSecs` (default 15 minutes), stops the server and removes
the state file. Foreground servers are unaffected — closing the terminal
is what ends them.

### State file: `%USERPROFILE%\.oc\server-state.json`

```json
{
  "mode": "foreground|background|transition",
  "passwordEnc": "<DPAPI-encrypted base64>",
  "pid": 12345,
  "transition": false,
  "hmac": "<HMAC-SHA256 base64>",
  "lastActivity": 1755100000
}
```

| Field | Purpose |
|-------|---------|
| `mode` | Current server mode (or `"transition"` during a mode switch) |
| `passwordEnc` | Server password encrypted via **DPAPI** (Windows Data Protection API, bound to current user + machine). On non-Windows, falls back to plaintext with a warning. |
| `pid` | Process ID of the `opencode serve` process |
| `transition` | `true` while a mode switch is in progress (prevents stale cleanup) |
| `hmac` | HMAC-SHA256 for **integrity verification**. Tampered state files are detected and flagged with a warning. |
| `lastActivity` | Unix timestamp of the last attach / active session (updated by `oc` on attach and by the watchdog while sessions are connected). |

The state file and its parent directory have **restrictive ACLs** applied, leaving only the current user (FullControl). This prevents other local accounts from reading the file.

---

## Mode switching

Switching between modes is designed to be **seamless** and **preserve active sessions**:

```
    foreground ────── serve -Background ──────→ background
         │
         └──── (kill) ───────── serve ──────────────→ foreground
```

### How a switch works (foreground → background example)

```
Terminal A (foreground server)         Terminal B (oc serve -Background)
──────────────────────────────         ──────────────────────────────────
opencode serve (PID=F)                 
                                      1. Read state (mode=foreground, pid=F, pw)
                                      2. Ask master password, decrypt keys
                                      3. Write state → transition=true
                                      4. Stop-ServerProcess → kill PID=F
Process F dies ←──────────────────────
WaitForExit() returns
  read state (mode=transition)
  → transition=true → skip cleanup
                                                                          
                                      5. Start-ServerProcess → PID=B
                                      6. Write state → mode=background,
                                         pid=B, transition=false
                                      7. Server running in background
```

### Why the transition flag is needed

Without it, a race condition occurs:

1. Terminal B kills PID F (step 4)
2. Terminal A's cleanup runs at the same time as Terminal B's step 5
3. If Terminal A reads the state before Terminal B writes it (step 6), the state still shows `pid=F`. Since `F == myPid`, the cleanup would **delete the state**, corrupting the new server.

The `transition` marker closes this window: Terminal B writes `transition=true` **before** killing, so Terminal A's cleanup sees `transition=true` and skips cleanup regardless of PID.

---

## Process management

### Background server (`Start-ServerProcess`)

```
[System.Diagnostics.ProcessStartInfo]
  FileName = "opencode"
  Arguments = "serve --port 4096"
  UseShellExecute = false
  CreateNoWindow = true
  EnvironmentVariables = parent env + API keys + OPENCODE_SERVER_PASSWORD
        ↓
[System.Diagnostics.Process]::Start($psi)
        ↓
PID stored in $script:serverPid + state file
```

- The process is **independent** of the PowerShell session — survives terminal closure
- No stdout/stderr redirection (avoids buffer deadlock)
- Environment includes parent's PATH + injected API keys (ONLY in the child process — parent session is never polluted)

### Foreground server (`Start-ForegroundProcess`)

```
[System.Diagnostics.ProcessStartInfo]
  FileName = "opencode"
  Arguments = "serve --port 4096"
  UseShellExecute = false
  CreateNoWindow = false
  EnvironmentVariables = parent env + API keys + OPENCODE_SERVER_PASSWORD
        ↓
[System.Diagnostics.Process]::Start($psi)
$process.WaitForExit()  ← blocks the terminal
```

- Shares the current console window (shows logs). Uses the same `ProcessStartInfo` approach as background mode — **API keys never touch the parent PowerShell session's environment**.
- PID is stored in the state file so `Stop-ServerProcess` from another terminal can find it
- When the process exits (Ctrl+C), cleanup removes state

### Stopping a server (`Stop-ServerProcess`)

```powershell
$targetPid = $script:serverPid ?? $state.pid ?? Get-NetTCPConnection(port 4096)
Get-Process -Id $targetPid | Kill
```

Priority:
1. `$script:serverPid` — in-session PID (for background servers started in this session)
2. `$state.pid` — PID from the state file (cross-session)
3. `Get-NetTCPConnection` — fallback by finding the process on port 4096

Never falls back to `Get-Process -Name "opencode" | Stop-Process` (which would kill all opencode processes including attach clients).

---

## Password management

| Event | Password behavior |
|-------|-------------------|
| Fresh `oc` (no server) | New password generated |
| `oc serve` (fresh) | New password generated |
| `oc serve -Background` (fresh) | New password generated |
| Mode switch (fore↔back) | **Same password preserved** |
| `oc serve -Restart` | New password generated |
| `oc stop` | Server killed, no new password |

When switching modes, the password is kept the same so that active `opencode attach` sessions remain authenticated. The new server process is started with `OPENCODE_SERVER_PASSWORD` set to the existing password.

---

## Key files

| Path | Purpose |
|------|---------|
| `oc.ps1` | Main script (PowerShell) |
| `oc` | Shell launcher for Linux/macOS (`exec pwsh oc.ps1 "$@"`) |
| `api-keys.dat` | Encrypted API key storage |
| `README.md` | Usage documentation |
| `%USERPROFILE%\.oc\server-state.json` | Server state (mode, DPAPI-encrypted password, PID, HMAC) |

## Requirements

- PowerShell 5+ (`pwsh` 7+ recommended for best compatibility)
- [opencode](https://opencode.ai) installed and available in `PATH`
- Windows (primary target; Linux/macOS via `oc` shell script with `pwsh`)