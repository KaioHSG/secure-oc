#!/usr/bin/env python3
"""Build the standalone secure-oc binary for the current platform.

Wraps PyInstaller (``packaging/oc.spec``) and leaves the result in
``dist/``: ``oc.exe`` on Windows, ``oc`` elsewhere. Packaging and
distribution are the release workflow's job, not this script's.

PyInstaller cannot cross-compile, so run this once per platform:

    python -m pip install -r requirements-build.txt
    python build.py
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC = ROOT / "packaging" / "oc.spec"
DIST = ROOT / "dist"

BINARY_NAME = "oc.exe" if sys.platform.startswith("win32") else "oc"


def ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        raise SystemExit(
            "PyInstaller is not installed.\n"
            "Install the build dependencies first:\n"
            "    python -m pip install -r requirements-build.txt"
        ) from None


def clean_dist() -> None:
    if not DIST.exists():
        return
    try:
        shutil.rmtree(DIST)
    except PermissionError as exc:
        raise SystemExit(
            f"Could not clean {DIST.relative_to(ROOT)}: {exc}\n"
            "A secure-oc instance is probably still running from the binary.\n"
            "Stop it first and build again."
        ) from exc


def build() -> Path:
    if not SPEC.exists():
        raise SystemExit(f"Missing PyInstaller spec: {SPEC}")

    cmd = [sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", str(SPEC)]
    print("+ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)

    binary = DIST / BINARY_NAME
    if not binary.exists():
        raise SystemExit(f"Build finished but {binary} was not produced")
    return binary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the secure-oc binary for the current platform.",
    )
    parser.add_argument(
        "--keep-dist",
        action="store_true",
        help="keep previous dist/ contents instead of starting clean",
    )
    args = parser.parse_args()

    ensure_pyinstaller()
    if not args.keep_dist:
        clean_dist()

    binary = build()
    size_mib = binary.stat().st_size / (1024 * 1024)
    print(f"\nBinary: {binary.relative_to(ROOT)} ({size_mib:.1f} MiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
