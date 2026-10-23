"""opencode server process management.

Resolves the real opencode binary, launches it in foreground or as a
detached daemon, finds the PID that owns the server port (needed when the
npm ``.cmd`` wrapper hides the real process), and runs the idle watchdog.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from .errors import ConfigError

_IS_WINDOWS = os.name == "nt"

CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200

STILL_ACTIVE = 259


def _psutil():
    try:
        import psutil  # type: ignore

        return psutil
    except Exception:
        return None


# --------------------------------------------------------------------------
# opencode resolution
# --------------------------------------------------------------------------


def find_opencode() -> str:
    path = shutil.which("opencode")
    if not path:
        raise ConfigError("'opencode' not found in PATH. Install it: https://opencode.ai")
    # CreateProcess cannot execute a .ps1 wrapper; npm ships a .cmd sibling.
    if path.lower().endswith(".ps1"):
        candidate = path[:-4] + ".cmd"
        if os.path.exists(candidate):
            return candidate
    return path


def build_env(keys: dict, server_password: Optional[str]) -> dict:
    """Parent environment plus injected API keys and the server password.

    The keys are only ever placed in the child process environment; the
    caller's own environment is never modified.
    """
    env = dict(os.environ)
    for name, value in keys.items():
        env[str(name).upper()] = str(value)
    if server_password:
        env["OPENCODE_SERVER_PASSWORD"] = server_password
    return env


# --------------------------------------------------------------------------
# launching
# --------------------------------------------------------------------------


def _detach_kwargs() -> dict:
    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if _IS_WINDOWS:
        kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True
    return kwargs


def start(keys: dict, password: str, port: int, *, background: bool) -> subprocess.Popen:
    """Start ``opencode serve`` and return the Popen handle."""
    binary = find_opencode()
    args = [binary, "serve", "--port", str(port)]
    env = build_env(keys, password)
    cwd = str(Path.home())

    if background:
        return subprocess.Popen(args, cwd=cwd, env=env, **_detach_kwargs())
    return subprocess.Popen(args, cwd=cwd, env=env)


def spawn_watchdog(state_path, port: int, timeout_secs: int) -> bool:
    """Launch a detached process that stops an idle background server.

    Works both when running from source (``python -m secure_oc``) and from a
    frozen PyInstaller binary, where ``sys.executable`` is the binary itself
    and the ``-m secure_oc`` form does not apply.
    """
    if getattr(sys, "frozen", False):
        args = [
            sys.executable,
            "__watchdog",
            "--state",
            str(state_path),
            "--port",
            str(port),
            "--timeout",
            str(int(timeout_secs)),
        ]
        env = dict(os.environ)
    else:
        args = [
            sys.executable,
            "-m",
            "secure_oc",
            "__watchdog",
            "--state",
            str(state_path),
            "--port",
            str(port),
            "--timeout",
            str(int(timeout_secs)),
        ]
        env = dict(os.environ)
        package_root = str(Path(__file__).resolve().parent.parent)
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = package_root + (os.pathsep + existing if existing else "")

    try:
        # Drop PyInstaller's extraction-dir variables so the child extracts
        # (and later cleans up) its own temp directory instead of pinning the
        # parent's, which would make the parent's cleanup fail.
        for key in [k for k in env if k.startswith("_MEI") or k.startswith("_PYI")]:
            env.pop(key, None)
        subprocess.Popen(args, cwd=str(Path.home()), env=env, **_detach_kwargs())
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# process / port inspection
# --------------------------------------------------------------------------


def port_is_listening(port: int, timeout: float = 2.0) -> bool:
    import socket

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def _win_pid_alive(pid: int) -> bool:
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    ps = _psutil()
    if ps is not None:
        try:
            return ps.pid_exists(pid)
        except Exception:
            pass
    if _IS_WINDOWS:
        try:
            return _win_pid_alive(pid)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def listener_pid(port: int) -> Optional[int]:
    """PID of the process listening on *port*, or ``None``."""
    ps = _psutil()
    if ps is not None:
        try:
            for conn in ps.net_connections(kind="tcp"):
                if conn.status == "LISTEN" and conn.laddr and conn.laddr.port == port:
                    return conn.pid
        except Exception:
            pass

    try:
        if _IS_WINDOWS:
            out = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[1].endswith(f":{port}") and parts[3].upper() == "LISTENING":
                    return int(parts[4])
        else:
            out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                if f":{port}" in line:
                    marker = "pid="
                    idx = line.find(marker)
                    if idx != -1:
                        return int(line[idx + len(marker) :].split(",")[0])
    except Exception:
        pass
    return None


def established_count(port: int) -> int:
    """Number of established connections to *port*.

    Returns ``-1`` when it cannot be determined, so callers can choose to
    stay conservative instead of stopping a busy server.
    """
    ps = _psutil()
    if ps is not None:
        try:
            count = 0
            for conn in ps.net_connections(kind="tcp"):
                if conn.status == "ESTABLISHED" and conn.laddr and conn.laddr.port == port:
                    count += 1
            return count
        except Exception:
            pass

    try:
        if _IS_WINDOWS:
            out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=10).stdout
        else:
            out = subprocess.run(["ss", "-tn"], capture_output=True, text=True, timeout=10).stdout
        count = 0
        for line in out.splitlines():
            upper = line.upper()
            if f":{port}" in line and "ESTABLISHED" in upper:
                count += 1
        return count
    except Exception:
        return -1


def stop(pid: int) -> bool:
    """Terminate the process with *pid*. Never matches by process name."""
    if not pid or pid <= 0:
        return False

    ps = _psutil()
    if ps is not None:
        try:
            proc = ps.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            return True
        except Exception:
            pass

    try:
        if _IS_WINDOWS:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                timeout=15,
                check=False,
            )
        else:
            os.kill(pid, signal.SIGTERM)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# idle watchdog
# --------------------------------------------------------------------------


def run_watchdog(state_path, port: int, timeout_secs: int, interval: int = 60) -> None:
    """Detached monitor: stop the background server after *timeout_secs* idle.

    While established connections exist the idle clock is refreshed, so it
    only counts down after the last session closes. If the number of
    connections cannot be determined it refreshes rather than risk killing
    an active session.
    """
    from . import state as state_mod

    state_path = Path(state_path)
    while True:
        time.sleep(interval)
        if not state_path.exists():
            return
        try:
            raw = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception:
            return

        last_activity = raw.get("lastActivity")
        if not last_activity:
            return
        if time.time() - last_activity <= timeout_secs:
            continue

        current = state_mod.load()
        if current is None or current.pid != raw.get("pid"):
            continue

        established = established_count(port)
        if established != 0:
            state_mod.set_activity()
            continue

        stop(int(raw.get("pid") or 0))
        state_mod.clear()
        return
