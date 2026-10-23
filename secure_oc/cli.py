"""Command-line interface for secure-oc."""

from __future__ import annotations

import getpass
import json
import os
import shutil
import subprocess
import sys
import time
from typing import Optional

from . import crypto, paths, secrets_store, server, state, ui
from .errors import ConfigError, CryptoError, SecureOcError, WrongPasswordError

PORT = int(os.environ.get("SECURE_OC_PORT", "4096"))
URL = f"http://localhost:{PORT}"
IDLE_TIMEOUT_MIN = 15

_FLAG_ALIASES = {
    "-dir": "dir",
    "--dir": "dir",
    "-opencode": "opencode",
    "--opencode": "opencode",
    "-showvalues": "show_values",
    "--show-values": "show_values",
    "-background": "background",
    "--background": "background",
    "-status": "status",
    "--status": "status",
    "-restart": "restart",
    "--restart": "restart",
    "-print": "print",
    "--print": "print",
    "-yes": "yes",
    "--yes": "yes",
    "-y": "yes",
    "-help": "help",
    "--help": "help",
    "-h": "help",
}


# Flags that take a value instead of being a boolean switch.
_VALUE_FLAGS = {"dir", "opencode"}


def _parse(argv: list) -> tuple[list, dict]:
    opts = {
        "dir": None,
        "opencode": None,
        "show_values": False,
        "background": False,
        "status": False,
        "restart": False,
        "print": False,
        "yes": False,
        "help": False,
    }
    positional: list = []
    index = 0
    while index < len(argv):
        token = argv[index]
        key = _FLAG_ALIASES.get(token.lower())
        if key is None:
            positional.append(token)
        elif key in _VALUE_FLAGS:
            index += 1
            if index >= len(argv):
                raise ConfigError(f"{token} requires a path argument")
            opts[key] = argv[index]
        else:
            opts[key] = True
        index += 1
    return positional, opts


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def confirm(question: str, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    try:
        answer = input(f"{question} [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def read_secret(prompt: str) -> str:
    """Read a secret without echoing it.

    Falls back to reading a line from stdin when there is no terminal, so
    the tool can be scripted (and tested) by piping input.
    """
    try:
        interactive = sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        interactive = False

    if not interactive:
        line = sys.stdin.readline() if sys.stdin is not None else ""
        if line == "":
            raise EOFError
        return line.rstrip("\r\n")

    return getpass.getpass(prompt)


def generate_password() -> str:
    return os.urandom(8).hex()


def _load_keys() -> Optional[dict]:
    """Prompt for the master password and return the decrypted key map."""
    if not paths.KEYS_PATH.exists():
        ui.error("No key store found. Run 'oc encrypt' first.")
        return None

    try:
        master = read_secret("Master password: ")
    except (EOFError, KeyboardInterrupt):
        ui.error("Aborted.")
        return None

    try:
        blob = paths.KEYS_PATH.read_bytes()
        plaintext = crypto.decrypt(blob, master.encode("utf-8"))
        return json.loads(plaintext.decode("utf-8"))
    except WrongPasswordError:
        ui.error("Wrong password or corrupted key store.")
        return None
    except CryptoError as exc:
        ui.error(str(exc))
        return None
    except Exception as exc:
        ui.error(f"Could not read the key store: {exc}")
        return None
    finally:
        del master


def _copy_to_clipboard(text: str) -> bool:
    candidates = []
    if os.name == "nt":
        candidates.append(["clip"])
    else:
        for tool, args in (
            ("pbcopy", []),
            ("wl-copy", []),
            ("xclip", ["-selection", "clipboard"]),
            ("xsel", ["-ib"]),
        ):
            if shutil.which(tool):
                candidates.append([tool, *args])

    for command in candidates:
        try:
            subprocess.run(command, input=text.encode("utf-8"), check=True, timeout=10)
            return True
        except Exception:
            continue
    return False


# --------------------------------------------------------------------------
# server helpers
# --------------------------------------------------------------------------


def is_server_running() -> bool:
    current = state.load()
    if current and current.pid > 0 and not server.pid_alive(current.pid):
        return False
    return server.port_is_listening(PORT)


def wait_ready(max_wait: float = 30.0) -> bool:
    sys.stdout.write("Waiting for server")
    sys.stdout.flush()
    waited = 0.0
    while waited < max_wait:
        if server.port_is_listening(PORT, timeout=1.0):
            ui.raw("")
            return True
        time.sleep(0.5)
        waited += 0.5
        sys.stdout.write(".")
        sys.stdout.flush()
    ui.raw("")
    return False


def sync_pid_from_port() -> None:
    real = server.listener_pid(PORT)
    current = state.load()
    if real and current and real != current.pid and current.password:
        state.save(current.mode, current.password, real, transition=current.transition)


def stop_and_cleanup() -> None:
    current = state.load()
    target = current.pid if current else None
    if target and server.pid_alive(target):
        server.stop(target)
    state.clear()


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_encrypt(opts: dict) -> int:
    try:
        master = read_secret("Set master password for the key store: ")
        confirmation = read_secret("Confirm master password: ")
    except (EOFError, KeyboardInterrupt):
        ui.error("Aborted.")
        return 1

    if master != confirmation:
        ui.error("Passwords do not match.")
        return 1
    if len(master) < 8:
        ui.warn("Warning: master password is shorter than 8 characters.")

    keys: dict = {}
    ui.info("")
    ui.dim("Enter key names and values. Values are hidden as you type.")
    while True:
        try:
            name = input("Key name (e.g. OPENROUTER_API_KEY) [empty to finish]: ").strip()
        except EOFError:
            break
        if not name:
            break
        try:
            value = read_secret(f"Value for [{name}] (hidden): ")
        except EOFError:
            break
        if value.strip():
            keys[name.upper()] = value.strip()

    if not keys:
        ui.warn("No keys provided. Canceled.")
        return 1

    try:
        plaintext = json.dumps(keys).encode("utf-8")
        blob = crypto.encrypt(plaintext, master.encode("utf-8"))
    except CryptoError as exc:
        ui.error(str(exc))
        return 1
    finally:
        del master, confirmation

    paths.ensure_state_dir()
    paths.write_private(paths.KEYS_PATH, blob)
    ui.ok(f"Done. {len(keys)} key(s) stored in {paths.KEYS_PATH}")
    ui.dim(f"Key derivation: {crypto.kdf_label(blob)}")
    return 0


def cmd_decrypt(opts: dict) -> int:
    keys = _load_keys()
    if keys is None:
        return 1
    ui.accent(f"Keys in store: {', '.join(keys)}")
    ui.dim("Use 'oc reveal' to copy the values to the clipboard.")
    return 0


def cmd_reveal(opts: dict) -> int:
    keys = _load_keys()
    if keys is None:
        return 1

    if opts["print"]:
        if not confirm(
            "Print secret values to the terminal? They may stay in scrollback and logs.",
            assume_yes=opts["yes"],
        ):
            ui.warn("Aborted.")
            return 1
        for name, value in keys.items():
            ui.raw(f"{name}={value}")
        return 0

    payload = "\n".join(f"{name}={value}" for name, value in keys.items())
    if _copy_to_clipboard(payload):
        ui.ok("Values copied to the clipboard.")
        ui.dim(f"Keys: {', '.join(keys)}")
        ui.dim("The clipboard is overwritten the next time you copy something.")
        return 0

    ui.error("No clipboard tool found. Use 'oc reveal --print' to display (not recommended).")
    return 1


def cmd_status() -> int:
    if not is_server_running():
        ui.error("Server: NOT RUNNING")
        return 1

    current = state.load()
    mode = current.mode if current else "unknown"
    attached = server.established_count(PORT)

    ui.ok("Server: RUNNING")
    ui.info(f"  URL:      {URL}")
    ui.info(f"  Mode:     {mode}")
    if attached < 0:
        ui.info("  Attached: unknown")
    else:
        suffix = "session" if attached == 1 else "sessions"
        ui.info(f"  Attached: {attached} {suffix}")
    ui.info("  Password: set (hidden)")

    if not current:
        return 0
    if not current.integrity_ok:
        ui.warn("  WARNING: state file failed its integrity check; run 'oc serve --restart'.")

    if current.mode == "background" and current.last_activity and attached == 0:
        idle = int(time.time()) - int(current.last_activity)
        remaining = max(0, IDLE_TIMEOUT_MIN * 60 - idle)
        ui.dim(f"  Idle:     {int(-(-remaining // 60))} min until auto-stop")
    elif current.mode == "background" and attached > 0:
        ui.dim("  Idle:     timer paused (sessions active)")
    return 0


def cmd_stop() -> int:
    if not is_server_running():
        ui.warn("Server is not running.")
        stop_and_cleanup()
        return 0

    current = state.load()
    target = current.pid if current else None
    if not target or not server.pid_alive(target):
        target = server.listener_pid(PORT)

    if target and server.stop(target):
        ui.ok("Server stopped.")
    else:
        ui.dim("No server process found.")
    state.clear()
    return 0


def _start_background(keys: dict, password: str, opencode: Optional[str]) -> bool:
    try:
        process = server.start(keys, password, PORT, background=True, opencode=opencode)
    except OSError as exc:
        ui.error(f"Failed to start server: {exc}")
        return False

    state.save("background", password, process.pid)
    if not wait_ready():
        ui.error("Server did not become ready in time.")
        stop_and_cleanup()
        return False
    sync_pid_from_port()
    if not server.spawn_watchdog(paths.STATE_PATH, PORT, IDLE_TIMEOUT_MIN * 60):
        ui.warn("Could not start the idle watchdog; use 'oc stop' manually.")
    ui.ok(f"Server running on {URL} (background)")
    ui.dim(f"Idle timeout: {IDLE_TIMEOUT_MIN} min without activity")
    return True


def _serve_foreground(keys: dict, password: str, opencode: Optional[str]) -> int:
    try:
        process = server.start(keys, password, PORT, background=False, opencode=opencode)
    except OSError as exc:
        ui.error(f"Failed to start server: {exc}")
        return 1

    time.sleep(0.5)
    state.save("foreground", password, process.pid)
    sync_pid_from_port()
    current = state.load()
    my_pid = current.pid if current else process.pid

    ui.accent(f"Server running on {URL} (foreground)")
    ui.warn("Press Ctrl+C to stop.")

    try:
        process.wait()
    except KeyboardInterrupt:
        server.stop(process.pid)

    current = state.load()
    if current and (current.transition or current.pid != my_pid):
        ui.dim("Server replaced by another mode.")
    else:
        state.clear()
        ui.ok("Server stopped.")
    return 0


def _restart_keeping_password(
    keys: dict, password: str, final_mode: str, opencode: Optional[str]
) -> int:
    current = state.load()
    previous_pid = current.pid if current else 0
    state.save("transition", password, previous_pid, transition=True)
    if previous_pid:
        server.stop(previous_pid)

    try:
        process = server.start(keys, password, PORT, background=True, opencode=opencode)
    except OSError as exc:
        ui.error(f"Failed to start server: {exc}")
        return 1

    state.save("background", password, process.pid)
    if not wait_ready():
        ui.error("Failed to restart the server.")
        stop_and_cleanup()
        return 1
    sync_pid_from_port()
    if final_mode == "background":
        server.spawn_watchdog(paths.STATE_PATH, PORT, IDLE_TIMEOUT_MIN * 60)
    ui.ok("Server running in background mode.")
    return 0


def _attach(
    password: Optional[str], workdir: str, extra: list, opencode: Optional[str]
) -> int:
    try:
        binary = server.find_opencode(opencode)
    except ConfigError as exc:
        ui.error(str(exc))
        return 1

    env = dict(os.environ)
    if password:
        env["OPENCODE_SERVER_PASSWORD"] = password

    # opencode >= 2 attaches with `--server <url>` and takes the working
    # directory as a positional argument. There is no `attach` subcommand
    # and no `--dir` flag.
    args = [binary, "--server", URL, workdir, *extra]
    try:
        return subprocess.call(args, env=env)
    except KeyboardInterrupt:
        return 130


def cmd_start(opts: dict, extra: list) -> int:
    try:
        server.find_opencode(opts["opencode"])
    except ConfigError as exc:
        ui.error(str(exc))
        return 1

    needs_restart = not is_server_running()
    password: Optional[str] = None

    if not needs_restart:
        current = state.load()
        if not current or current.transition or not current.password:
            ui.warn("Server running but state is invalid (no password).")
            if confirm("Restart it?", assume_yes=opts["yes"]):
                stop_and_cleanup()
                needs_restart = True
            else:
                ui.error("Cannot attach: server password unknown.")
                return 1
        else:
            password = current.password
            if not current.integrity_ok:
                ui.warn("WARNING: state file failed its integrity check.")
            ui.accent(f"Server already running on {URL}")

    if needs_restart:
        keys = _load_keys()
        if keys is None:
            return 1
        password = generate_password()
        ui.accent("Starting server...")
        try:
            process = server.start(
                keys, password, PORT, background=True, opencode=opts["opencode"]
            )
        except OSError as exc:
            ui.error(f"Failed to start server: {exc}")
            return 1
        del keys

        state.save("background", password, process.pid)
        if not wait_ready():
            ui.error("Server did not become ready in time.")
            stop_and_cleanup()
            return 1
        sync_pid_from_port()
        if not server.spawn_watchdog(paths.STATE_PATH, PORT, IDLE_TIMEOUT_MIN * 60):
            ui.warn("Could not start the idle watchdog; use 'oc stop' manually.")
        ui.ok(f"Server running on {URL}")

    current = state.load()
    if current and current.mode == "background":
        state.set_activity()

    workdir = os.path.abspath(opts["dir"]) if opts["dir"] else os.getcwd()
    return _attach(password, workdir, extra, opts["opencode"])


def cmd_serve(opts: dict) -> int:
    # `--status` only reads the state file and the port, so it must not
    # require opencode (or the key store) to be resolvable.
    if opts["status"]:
        return cmd_status()

    try:
        server.find_opencode(opts["opencode"])
    except ConfigError as exc:
        ui.error(str(exc))
        return 1

    if not paths.KEYS_PATH.exists():
        ui.error("No key store found. Run 'oc encrypt' first.")
        return 1

    if opts["restart"]:
        ui.warn("Restarting server...")
        previous_mode = None
        if is_server_running():
            current = state.load()
            previous_mode = current.mode if current else None
            stop_and_cleanup()
        keys = _load_keys()
        if keys is None:
            return 1
        new_password = generate_password()
        if previous_mode == "foreground":
            result = _serve_foreground(keys, new_password, opts["opencode"])
        else:
            result = 0 if _start_background(keys, new_password, opts["opencode"]) else 1
        del keys
        return result

    if opts["background"]:
        if not is_server_running():
            keys = _load_keys()
            if keys is None:
                return 1
            result = 0 if _start_background(keys, generate_password(), opts["opencode"]) else 1
            del keys
            return result

        current = state.load()
        if current and current.mode == "foreground":
            if not confirm("Foreground server detected. Restart in background?", assume_yes=opts["yes"]):
                ui.warn("Aborted.")
                return 1
            keys = _load_keys()
            if keys is None or not current.password:
                return 1
            result = _restart_keeping_password(
                keys, current.password, "background", opts["opencode"]
            )
            del keys
            return result
        if current and current.mode == "background":
            ui.warn("Server is already in background mode.")
            return 0
        # Unknown mode: adopt it as background.
        if current and current.password:
            state.save("background", current.password, current.pid)
            server.spawn_watchdog(paths.STATE_PATH, PORT, IDLE_TIMEOUT_MIN * 60)
            ui.ok("Server switched to background mode.")
            return 0
        ui.error("Server running with unknown state. Use 'oc serve --restart'.")
        return 1

    # Plain 'oc serve' -> foreground.
    if is_server_running():
        current = state.load()
        if current and current.mode == "foreground":
            ui.warn("Server is already running in foreground.")
            return 0
        if not confirm("Background server detected. Restart in foreground?", assume_yes=opts["yes"]):
            ui.warn("Aborted.")
            return 1
        keys = _load_keys()
        if keys is None or not current or not current.password:
            return 1
        server.stop(current.pid)
        result = _serve_foreground(keys, current.password, opts["opencode"])
        del keys
        return result

    keys = _load_keys()
    if keys is None:
        return 1
    result = _serve_foreground(keys, generate_password(), opts["opencode"])
    del keys
    return result


def _passthrough(opts: dict, extra: list, subcommand: str) -> int:
    try:
        binary = server.find_opencode(opts["opencode"])
    except ConfigError as exc:
        ui.error(str(exc))
        return 1
    args = [binary, subcommand, *extra]
    try:
        return subprocess.call(args)
    except KeyboardInterrupt:
        return 130


# --------------------------------------------------------------------------
# help
# --------------------------------------------------------------------------


def show_help() -> None:
    ui.accent("\noc - Secure opencode wrapper")
    ui.dim("Encrypted API-key manager with opencode server lifecycle.\n")
    ui.bold("USAGE")
    ui.raw(
        """  oc                          Start opencode (start server if needed, attach)
  oc serve                    Start a persistent server (foreground, shows logs)
  oc serve --background       Start a persistent server in background (daemon)
  oc serve --status           Show server status
  oc serve --restart          Restart the server (new password, clients disconnect)
  oc encrypt                  Encrypt and store API keys
  oc decrypt                  List stored API key names
  oc reveal                   Copy key values to the clipboard (never to stdout)
  oc reveal --print           Print values to the terminal (asks for confirmation)
  oc stop                     Stop the running server
  oc --dir <path>             Attach with a specific working directory
  oc --opencode <path>        Use a specific opencode binary (or set SECURE_OC_OPENCODE)
  oc --help                   Show this help
"""
    )
    ui.bold("WORKFLOW")
    ui.raw(
        """  First run:   oc            -> master password, starts the server, attaches
  Later runs:  oc            -> attaches directly (no master password)
  Background:  oc serve --background  -> daemon, auto-stops after 15 min idle
  Shutdown:    oc stop
"""
    )
    ui.bold("SECURITY")
    ui.raw(
        f"""  Key store:   {paths.KEYS_PATH} (Argon2id + AES-256-GCM)
  Secret store: {secrets_store.backend_name()}
  Server password is kept out of the state file and never passed on the command line.
  Values are hidden while typing and are never echoed unless you ask with --print.
  opencode is resolved from --opencode, then SECURE_OC_OPENCODE, then PATH.
"""
    )


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def main(argv: Optional[list] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "__watchdog":
        import argparse

        parser = argparse.ArgumentParser(prog="secure-oc __watchdog")
        parser.add_argument("--state", required=True)
        parser.add_argument("--port", type=int, required=True)
        parser.add_argument("--timeout", type=int, required=True)
        args = parser.parse_args(argv[1:])
        server.run_watchdog(args.state, args.port, args.timeout)
        return 0

    try:
        positional, opts = _parse(argv)
    except SecureOcError as exc:
        ui.error(str(exc))
        return 2

    if opts["help"]:
        show_help()
        return 0

    command = positional[0].lower() if positional else ""
    extra = positional[1:]

    try:
        if command == "encrypt":
            return cmd_encrypt(opts)
        if command == "decrypt":
            return cmd_decrypt(opts)
        if command == "reveal":
            return cmd_reveal(opts)
        if command == "serve":
            return cmd_serve(opts)
        if command == "stop":
            return cmd_stop()
        if command == "session":
            return _passthrough(opts, extra, "session")
        if command in ("model", "models"):
            return _passthrough(opts, extra, "models")
        if command in ("help",):
            show_help()
            return 0
        return cmd_start(opts, extra)
    except KeyboardInterrupt:
        ui.warn("\nInterrupted.")
        return 130
    except SecureOcError as exc:
        ui.error(str(exc))
        return 1
    except Exception as exc:  # pragma: no cover - defensive
        ui.error(f"Unexpected error: {exc}")
        return 1
