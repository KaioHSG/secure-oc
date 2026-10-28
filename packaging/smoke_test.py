#!/usr/bin/env python3
"""Smoke-test a frozen secure-oc binary.

Runs a real encrypt/decrypt round-trip against a throwaway state directory, so
a binary that cannot import ``cryptography`` (or otherwise fails at runtime) is
caught by CI. ``--help`` alone does not exercise the crypto path -- its text is
static -- which is how a release with a broken cryptography import once shipped.

    python packaging/smoke_test.py dist/oc.exe
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

PASSWORD = "smoke-password"
KEY_NAME = "SMOKE_KEY"
KEY_VALUE = "smoke-value"


def run(
    binary: str, args: list[str], stdin: str, env: dict[str, str]
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [binary, *args],
        input=stdin.encode("utf-8"),
        capture_output=True,
        env=env,
        check=False,
    )


def fail(stage: str, result: subprocess.CompletedProcess, extra: str = "") -> int:
    print(f"smoke test: {stage} failed (exit {result.returncode})", file=sys.stderr)
    if extra:
        print(f"  {extra}", file=sys.stderr)
    for name, data in (("stdout", result.stdout), ("stderr", result.stderr)):
        text = data.decode("utf-8", "replace").strip()
        if text:
            print(f"  {name}: {text}", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <binary>", file=sys.stderr)
        return 2

    binary = os.path.abspath(argv[1])
    if not os.path.isfile(binary):
        print(f"smoke test: binary not found: {binary}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="secure-oc-smoke-") as home:
        env = {**os.environ, "SECURE_OC_HOME": home}

        store_input = "\n".join([PASSWORD, PASSWORD, KEY_NAME, KEY_VALUE, ""]) + "\n"
        encrypted = run(binary, ["encrypt"], store_input, env)
        if encrypted.returncode != 0:
            return fail("encrypt", encrypted)

        decrypted = run(binary, ["decrypt"], PASSWORD + "\n", env)
        if decrypted.returncode != 0:
            return fail("decrypt", decrypted)
        if KEY_NAME not in decrypted.stdout.decode("utf-8", "replace"):
            return fail("decrypt", decrypted, f"expected {KEY_NAME!r} in the output")

    print("smoke test: encrypt/decrypt round-trip OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
