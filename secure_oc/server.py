"""opencode server process management.

Resolves the real opencode binary, launches it in foreground or as a
detached daemon, finds the PID that owns the server port (needed when the
npm ``.cmd`` wrapper hides the real process), and runs the idle watchdog.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from .errors import ConfigError

_IS_WINDOWS = os.name == "nt"

CREATE_NO_WINDOW = 0x08000000
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


ENV_OPENCODE = "SECURE_OC_OPENCODE"

# npm, pnpm and bun ship opencode as a shim beside the payload. On Windows that
# is a .cmd (with a .ps1 sibling the shell prefers); CreateProcess cannot run a
# .ps1, which is why `_normalize_opencode` swaps it for the .cmd.
_OPENCODE_NAMES = (
    ("opencode.exe", "opencode.cmd", "opencode.bat", "opencode.ps1", "opencode")
    if _IS_WINDOWS
    else ("opencode",)
)


def _normalize_opencode(path: str) -> str:
    # CreateProcess cannot execute a .ps1 wrapper; npm ships a .cmd sibling.
    if path.lower().endswith(".ps1"):
        candidate = path[:-4] + ".cmd"
        if os.path.exists(candidate):
            return candidate
    return path


def _registry_path_dirs() -> list[str]:
    """``PATH`` entries stored in the registry (Windows only).

    Explorer, shortcuts and Task Scheduler hand their children the environment
    they captured at logon, so entries added later (a fresh npm install, fnm,
    scoop, ...) never reach a double-clicked executable.
    """
    if not _IS_WINDOWS:
        return []
    try:
        import winreg
    except ImportError:  # pragma: no cover - only on exotic builds
        return []

    locations = (
        (winreg.HKEY_CURRENT_USER, "Environment"),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ),
    )
    dirs: list[str] = []
    for hive, subkey in locations:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                value, kind = winreg.QueryValueEx(key, "Path")
        except OSError:
            continue
        if not isinstance(value, str):
            continue
        if kind == winreg.REG_EXPAND_SZ:
            value = os.path.expandvars(value)
        dirs.extend(part for part in value.split(os.pathsep) if part)
    return dirs


def _version_key(name: str) -> list[int]:
    return [int(part) for part in re.findall(r"\d+", name)]


def _fnm_node_dirs() -> list[str]:
    """Node installations managed by fnm, default alias first then newest.

    fnm only puts its shims on ``PATH`` through a per-shell hook, so there is
    no stable directory to add to the user environment.
    """
    bases = [b for b in (os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA")) if b]
    preferred = None
    versions: list[Path] = []
    for base in bases:
        alias = Path(base, "fnm", "aliases", "default")
        try:
            preferred = alias.read_text(encoding="utf-8").strip() or preferred
        except OSError:
            pass
        root = Path(base, "fnm", "node-versions")
        if root.is_dir():
            versions.extend(entry for entry in root.iterdir() if entry.is_dir())

    versions.sort(key=lambda path: _version_key(path.name), reverse=True)
    if preferred:
        versions.sort(key=lambda path: path.name != preferred)
    return [str(entry / "installation") for entry in versions]


def _local_app_dir(*parts: str) -> str:
    base = os.environ.get("LOCALAPPDATA")
    return str(Path(base, *parts)) if base else ""


def _version_manager_dirs() -> list[str]:
    """Shim directories owned by a toolchain manager.

    These come before the generic package-manager prefixes: a version manager
    is what a shell would resolve, and the npm prefix often holds a leftover
    install of a different release line.
    """
    home = Path.home()
    dirs: list[str] = []
    if _IS_WINDOWS:
        dirs.extend(
            [
                os.environ.get("NVM_SYMLINK") or "",
                _local_app_dir("Volta", "bin"),
                _local_app_dir("pnpm"),
            ]
        )
        dirs.extend(_fnm_node_dirs())
    dirs.append(str(home / ".bun" / "bin"))
    if not _IS_WINDOWS:
        dirs.extend(
            [str(home / ".local" / "bin"), str(home / "bin"), "/opt/homebrew/bin"]
        )
    return [directory for directory in dirs if directory and os.path.isdir(directory)]


def _package_manager_dirs() -> list[str]:
    """Global shim directories of npm, scoop, winget and friends."""
    home = Path.home()
    env = os.environ
    dirs: list[str] = []
    if _IS_WINDOWS:
        for base, sub in (
            (env.get("APPDATA"), ("npm",)),
            (env.get("LOCALAPPDATA"), ("npm",)),
            (env.get("ProgramData"), ("chocolatey", "bin")),
            (env.get("ProgramFiles"), ("nodejs",)),
        ):
            if base:
                dirs.append(str(Path(base, *sub)))
        dirs.append(str(home / "scoop" / "shims"))
        if env.get("LOCALAPPDATA"):
            dirs.append(str(Path(env["LOCALAPPDATA"], "Microsoft", "WinGet", "Links")))
    else:
        dirs.append("/usr/local/bin")
    return [directory for directory in dirs if directory and os.path.isdir(directory)]


def _search_extra_dirs() -> list[str]:
    """Directories probed when ``PATH`` does not resolve opencode.

    Order: the registry's ``PATH`` (what a fresh login would see), then
    toolchain managers, then global package-manager prefixes.
    """
    dirs = _registry_path_dirs() if _IS_WINDOWS else []
    dirs.extend(_version_manager_dirs())
    dirs.extend(_package_manager_dirs())

    seen = set()
    unique = []
    for directory in dirs:
        key = os.path.normcase(os.path.abspath(directory))
        if key in seen:
            continue
        seen.add(key)
        unique.append(directory)
    return unique


def _which_outside_path() -> str | None:
    for directory in _search_extra_dirs():
        for name in _OPENCODE_NAMES:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def find_opencode(explicit: str | None = None) -> str:
    """Resolve the opencode binary.

    Order of precedence: the explicit path (``--opencode``), the
    ``SECURE_OC_OPENCODE`` environment variable, ``PATH``, and finally the
    install locations that ``PATH`` misses when the process was not started
    from a shell (see ``_search_extra_dirs``).
    """
    for source, candidate in (
        ("--opencode", explicit),
        (ENV_OPENCODE, os.environ.get(ENV_OPENCODE)),
    ):
        if not candidate:
            continue
        if not os.path.exists(candidate):
            raise ConfigError(f"{source} points to a file that does not exist: {candidate}")
        return _normalize_opencode(candidate)

    found = shutil.which("opencode")
    if found:
        return _normalize_opencode(found)

    found = _which_outside_path()
    if found:
        return _normalize_opencode(found)

    raise ConfigError(
        "'opencode' not found in PATH. Install it: https://opencode.ai\n"
        "Or point at it with --opencode <path> / SECURE_OC_OPENCODE."
    )


def ensure_on_path(env: dict, binary: str) -> dict:
    """Prepend *binary*'s directory to ``env["PATH"]``.

    A binary found by ``_which_outside_path`` lives in a directory that is not
    on the inherited ``PATH``, and npm's shims look up ``node`` through
    ``PATH``, so the child process needs it there as well.
    """
    directory = os.path.dirname(os.path.abspath(binary))
    entries = [part for part in env.get("PATH", "").split(os.pathsep) if part]
    if any(
        os.path.normcase(os.path.abspath(part)) == os.path.normcase(directory)
        for part in entries
    ):
        return env
    env["PATH"] = os.pathsep.join([directory, *entries])
    return env


def build_env(keys: dict, server_password: str | None) -> dict:
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
    """Popen kwargs that detach the child without ever showing a window.

    ``DETACHED_PROCESS`` is deliberately avoided: on Windows it makes a
    visible ``PseudoConsoleWindow`` pop up for every detached spawn (one
    for the server, one for the watchdog). ``CREATE_NO_WINDOW`` plus a
    hidden ``STARTUPINFO`` keeps the child detached and window-less while
    still surviving the parent process.
    """
    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if _IS_WINDOWS:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        kwargs["creationflags"] = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        kwargs["startupinfo"] = startupinfo
    else:
        kwargs["start_new_session"] = True
    return kwargs


def start(
    keys: dict,
    password: str,
    port: int,
    *,
    background: bool,
    opencode: str | None = None,
) -> subprocess.Popen:
    """Start ``opencode serve`` and return the Popen handle."""
    binary = find_opencode(opencode)
    args = [binary, "serve", "--port", str(port)]
    env = ensure_on_path(build_env(keys, password), binary)
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


def _process_description(pid: int) -> str | None:
    """Best-effort lowercase ``name + command line`` for *pid*, or ``None``.

    Prefers psutil; falls back to ``tasklist`` (Windows) / ``ps`` (POSIX).
    Returns ``None`` when the process cannot be inspected at all.
    """
    ps = _psutil()
    if ps is not None:
        try:
            proc = ps.Process(pid)
            parts = [proc.name() or "", *(proc.cmdline() or [])]
            return " ".join(parts).strip().lower()
        except Exception:
            return None

    try:
        if _IS_WINDOWS:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
        else:
            out = subprocess.run(
                ["ps", "-p", str(pid), "-o", "comm=,args="],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
    except Exception:
        return None
    return out.strip().lower() or None


def pid_looks_like_opencode(pid: int) -> bool:
    """Heuristic: does *pid* look like opencode (or the npm wrapper around it)?

    Guards the two destructive operations — adopting a PID into the state
    file and killing a process — so an unrelated program that merely happens
    to own the server port is never touched. When the process cannot be
    inspected, returns ``False`` (stay conservative: never kill blindly).
    """
    if pid <= 0:
        return False
    description = _process_description(pid)
    if not description:
        return False
    return "opencode" in description


def listener_pid(port: int) -> int | None:
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
                if (
                    len(parts) >= 5
                    and parts[1].endswith(f":{port}")
                    and parts[3].upper() == "LISTENING"
                ):
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
            out = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True, timeout=10
            ).stdout
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
            # A different server (or none) now owns the state file: this
            # watchdog is stale, so exit instead of piling up alongside the
            # watchdog that was spawned for the replacement server.
            return

        established = established_count(port)
        if established != 0:
            state_mod.set_activity()
            continue

        stop(int(raw.get("pid") or 0))
        state_mod.clear()
        return
