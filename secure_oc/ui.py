"""Minimal coloured console output.

Colour is enabled only on a TTY and can be forced or disabled with
``FORCE_COLOR`` / ``NO_COLOR``.
"""

from __future__ import annotations

import os
import sys

_CODES = {
    "red": "31",
    "green": "32",
    "yellow": "33",
    "cyan": "36",
    "gray": "90",
    "bold": "1",
}


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


_ENABLED = _color_enabled()


def _paint(text: str, color: str) -> str:
    if not _ENABLED or color not in _CODES:
        return text
    return f"\033[{_CODES[color]}m{text}\033[0m"


def info(message: str = "") -> None:
    print(message)


def raw(message: str = "") -> None:
    print(message)


def ok(message: str) -> None:
    print(_paint(message, "green"))


def warn(message: str) -> None:
    print(_paint(message, "yellow"))


def error(message: str) -> None:
    print(_paint(message, "red"), file=sys.stderr)


def accent(message: str) -> None:
    print(_paint(message, "cyan"))


def dim(message: str) -> None:
    print(_paint(message, "gray"))


def bold(message: str) -> None:
    print(_paint(message, "bold"))
