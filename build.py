#!/usr/bin/env python3
"""Build the standalone secure-oc binary for the current platform.

Wraps PyInstaller (``packaging/oc.spec``), smoke-tests the result and
packages it into the release archive for the current OS:

    Windows   dist/secure-oc-Windows.zip    contains oc.exe
    Linux     dist/secure-oc-Linux.tar.gz   contains oc
    macOS     dist/secure-oc-macOS.tar.gz   contains oc

PyInstaller cannot cross-compile, so run this once per platform. From the
repository root:

    python -m pip install -r requirements-build.txt
    python build.py
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC = ROOT / "packaging" / "oc.spec"
DIST = ROOT / "dist"

# sys.platform prefix -> (archive platform name, binary name, archive kind)
TARGETS = {
    "win32": ("Windows", "oc.exe", "zip"),
    "linux": ("Linux", "oc", "tar.gz"),
    "darwin": ("macOS", "oc", "tar.gz"),
}


def target() -> tuple[str, str, str]:
    for prefix, value in TARGETS.items():
        if sys.platform.startswith(prefix):
            return value
    raise SystemExit(f"Unsupported platform: {sys.platform}")


def ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        raise SystemExit(
            "PyInstaller is not installed.\n"
            "Install the build dependencies first:\n"
            "    python -m pip install -r requirements-build.txt"
        )


def clean_dist() -> None:
    if not DIST.exists():
        return
    try:
        shutil.rmtree(DIST)
    except PermissionError as exc:
        raise SystemExit(
            f"Could not clean {DIST.relative_to(ROOT)}: {exc}\n"
            "A secure-oc instance is probably still running from the binary.\n"
            "Stop it first (for example: dist/oc.exe stop) and build again."
        )


def build_binary() -> None:
    if not SPEC.exists():
        raise SystemExit(f"Missing PyInstaller spec: {SPEC}")
    cmd = [sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", str(SPEC)]
    print("+ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)


def smoke_test(binary: Path) -> None:
    print(f"+ {binary.name} --help", flush=True)
    result = subprocess.run(
        [str(binary), "--help"], cwd=ROOT, capture_output=True, text=True
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(f"Smoke test failed (exit code {result.returncode})")
    print("  smoke test OK", flush=True)


def make_zip(binary: Path, archive: Path, arcname: str) -> None:
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(binary, arcname=arcname)


def make_targz(binary: Path, archive: Path, arcname: str) -> None:
    with tarfile.open(archive, "w:gz") as tf:
        info = tf.gettarinfo(str(binary), arcname=arcname)
        info.mode = 0o755  # keep the binary executable
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        with binary.open("rb") as handle:
            tf.addfile(info, handle)


def package(binary: Path, platform_name: str, arcname: str, kind: str) -> Path:
    if kind == "zip":
        archive = DIST / f"secure-oc-{platform_name}.zip"
        make_zip(binary, archive, arcname)
    else:
        archive = DIST / f"secure-oc-{platform_name}.tar.gz"
        make_targz(binary, archive, arcname)
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the secure-oc binary and release archive.",
    )
    parser.add_argument(
        "--skip-smoke",
        action="store_true",
        help="do not run the built binary before packaging",
    )
    parser.add_argument(
        "--keep-dist",
        action="store_true",
        help="keep previous dist/ contents instead of starting clean",
    )
    args = parser.parse_args()

    platform_name, binary_name, kind = target()
    ensure_pyinstaller()

    if not args.keep_dist:
        clean_dist()

    build_binary()

    binary = DIST / binary_name
    if not binary.exists():
        raise SystemExit(f"Build finished but {binary} was not produced")

    if not args.skip_smoke:
        smoke_test(binary)

    archive = package(binary, platform_name, binary_name, kind)
    size_mib = archive.stat().st_size / (1024 * 1024)
    print(f"\nBinary : {binary.relative_to(ROOT)}")
    print(f"Archive: {archive.relative_to(ROOT)} ({size_mib:.1f} MiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
