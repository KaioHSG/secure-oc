"""Server state: mode, PID, idle clock and password reference.

Compared with the PowerShell version, the server password is **not** in
this file at all — it lives in the OS secret store and the state file only
holds a reference to it. Integrity is protected with HMAC-SHA256 using a
key that is independent of the server password, which removes the previous
circular scheme where the HMAC key was derived from the password stored
in the same file.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmaclib
import json
import os
import time
from dataclasses import dataclass

from . import paths, secrets_store

HMAC_LABEL = "state-hmac"
PASSWORD_LABEL = "server-password"
HMAC_KEY_LEN = 32

VALID_MODES = {"foreground", "background", "transition"}


@dataclass
class ServerState:
    mode: str
    pid: int
    transition: bool
    last_activity: int | None
    password: str | None
    integrity_ok: bool = True


def _hmac_key() -> bytes:
    key = secrets_store.unprotect(HMAC_LABEL)
    if not key or len(key) != HMAC_KEY_LEN:
        key = os.urandom(HMAC_KEY_LEN)
        secrets_store.protect(HMAC_LABEL, key)
    return key


def _canonical(mode: str, pid: int, transition: bool, last_activity: int | None) -> bytes:
    payload = {
        "mode": mode,
        "pid": int(pid),
        "transition": bool(transition),
        "lastActivity": int(last_activity or 0),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(mode: str, pid: int, transition: bool, last_activity: int | None) -> str:
    mac = hmaclib.new(_hmac_key(), _canonical(mode, pid, transition, last_activity), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode("ascii")


def _read_raw() -> dict | None:
    if not paths.STATE_PATH.exists():
        return None
    try:
        return json.loads(paths.STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def load() -> ServerState | None:
    """Read the state file, verifying its integrity and fetching the password."""
    raw = _read_raw()
    if not raw:
        return None

    mode = str(raw.get("mode", "unknown"))
    pid = int(raw.get("pid") or 0)
    transition = bool(raw.get("transition"))
    last_activity = raw.get("lastActivity")

    integrity_ok = True
    stored = raw.get("hmac")
    if stored:
        integrity_ok = hmaclib.compare_digest(
            stored, _sign(mode, pid, transition, last_activity)
        )

    secret = secrets_store.unprotect(PASSWORD_LABEL)
    password = secret.decode("utf-8") if secret else None

    return ServerState(
        mode=mode,
        pid=pid,
        transition=transition,
        last_activity=last_activity,
        password=password,
        integrity_ok=integrity_ok,
    )


def save(mode: str, password: str, pid: int, transition: bool = False) -> None:
    """Persist the state, storing the password in the OS secret store."""
    if mode not in VALID_MODES:
        raise ValueError(f"invalid mode: {mode!r}")

    paths.ensure_state_dir()
    secrets_store.protect(PASSWORD_LABEL, password.encode("utf-8"))

    last_activity = int(time.time())
    payload = {
        "mode": mode,
        "pid": int(pid),
        "transition": bool(transition),
        "hmac": _sign(mode, pid, transition, last_activity),
        "lastActivity": last_activity,
    }
    paths.write_private(
        paths.STATE_PATH,
        json.dumps(payload, indent=2).encode("utf-8"),
    )


def set_activity() -> None:
    """Refresh the idle clock without touching the password or PID."""
    raw = _read_raw()
    if not raw:
        return
    mode = str(raw.get("mode", "unknown"))
    pid = int(raw.get("pid") or 0)
    transition = bool(raw.get("transition"))
    last_activity = int(time.time())
    raw["lastActivity"] = last_activity
    raw["hmac"] = _sign(mode, pid, transition, last_activity)
    try:
        paths.write_private(
            paths.STATE_PATH,
            json.dumps(raw, indent=2).encode("utf-8"),
        )
    except Exception:
        pass


def clear() -> None:
    """Remove the state file and forget the server password.

    The HMAC key is intentionally kept so it stays stable across restarts.
    """
    try:
        if paths.STATE_PATH.exists():
            paths.STATE_PATH.unlink()
    except Exception:
        pass
    secrets_store.forget(PASSWORD_LABEL)
