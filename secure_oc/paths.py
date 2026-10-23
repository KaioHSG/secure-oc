"""Filesystem layout and permission hardening.

Everything lives under a single state directory (``~/.oc`` by default)
instead of the repository, so a stray ``git add -f`` cannot publish the
encrypted key store. Set ``SECURE_OC_HOME`` to relocate it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _state_dir() -> Path:
    override = os.environ.get("SECURE_OC_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".oc"


STATE_DIR = _state_dir()
KEYS_PATH = STATE_DIR / "keys.dat"
STATE_PATH = STATE_DIR / "server-state.json"
SECRETS_DIR = STATE_DIR / "secrets"

_IS_WINDOWS = os.name == "nt"


def ensure_state_dir() -> Path:
    """Create the state directory tree with restrictive permissions."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    harden(STATE_DIR, is_dir=True)
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    harden(SECRETS_DIR, is_dir=True)
    return STATE_DIR


def harden(path: Path, is_dir: bool = False) -> None:
    """Best-effort lockdown of a file or directory to the current user.

    On POSIX this is ``chmod 0600``/``0700``. On Windows inheritance is
    removed and only the current account is granted FullControl. Failures
    are ignored: the store still works, it is just less isolated.
    """
    try:
        if _IS_WINDOWS:
            user = os.environ.get("USERNAME")
            if not user:
                return
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            os.chmod(path, 0o700 if is_dir else 0o600)
    except Exception:
        pass


def write_private(path: Path, data: bytes) -> None:
    """Atomically write *data* to *path* with restrictive permissions."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    harden(tmp, is_dir=False)
    os.replace(tmp, path)
    harden(path, is_dir=False)
