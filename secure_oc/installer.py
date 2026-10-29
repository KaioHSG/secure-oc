"""Install opencode on demand, bringing Bun along when it is missing.

Used when :func:`secure_oc.server.find_opencode` cannot resolve a binary and
the user accepts the prompt: Bun is installed with its official script and then
used to install opencode globally, so no Node toolchain is required.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from . import ui

PACKAGE = "@opencode/cli"
# `--trust` allows the package's install scripts, which the binary needs.
BUN_ARGS = ("install", "-g", "--trust", PACKAGE)
BUN_URL = "https://bun.sh/install"


def install_command() -> str:
    """The manual command shown when the automatic install is declined."""
    return "bun " + " ".join(BUN_ARGS)


def bun_bin_dir() -> Path:
    """Where Bun's installer drops the binary and its global shims."""
    return Path.home() / ".bun" / "bin"


def find_bun() -> str | None:
    """Locate Bun, falling back to its default install directory.

    The fallback matters on Windows: a binary launched from Explorer does not
    see the PATH entries Bun adds on install.
    """
    found = shutil.which("bun")
    if found:
        return found
    for name in ("bun.exe", "bun"):
        candidate = bun_bin_dir() / name
        if candidate.is_file():
            return str(candidate)
    return None


def install_bun() -> str | None:
    """Install Bun with its official script and return the binary path."""
    if sys.platform.startswith("win32"):
        command = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            f"irm {BUN_URL}.ps1 | iex",
        ]
    else:
        command = ["sh", "-c", f"curl -fsSL {BUN_URL} | bash"]

    ui.dim("Installing Bun...")
    try:
        subprocess.run(command, check=True, cwd=str(Path.home()))
    except (OSError, subprocess.CalledProcessError) as exc:
        ui.error(f"Could not install Bun: {exc}")
        ui.dim("Install it manually: https://bun.sh")
        return None
    return find_bun()


def install_opencode() -> bool:
    """Install Bun when needed, then opencode globally with it."""
    bun = find_bun()
    if bun is None:
        bun = install_bun()
        if bun is None:
            return False

    ui.dim(f"Installing {PACKAGE} with Bun...")
    try:
        subprocess.run([bun, *BUN_ARGS], check=True, cwd=str(Path.home()))
    except (OSError, subprocess.CalledProcessError) as exc:
        ui.error(f"Could not install opencode: {exc}")
        ui.dim(f"Install it manually: {install_command()}")
        return False
    return True
