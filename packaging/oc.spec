# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: build a single-file ``oc`` binary for the current OS.

Cross-compilation is not supported by PyInstaller, so this spec is meant to
run once per platform (see .github/workflows/build.yaml).
"""

import os
import sys

from PyInstaller.utils.hooks import collect_submodules, copy_metadata

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

# keyring discovers its backends through importlib.metadata entry points, so
# both the backend modules and keyring's metadata must be bundled.
hiddenimports = collect_submodules("keyring.backends")
hiddenimports += ["keyring", "argon2", "psutil"]

datas = copy_metadata("keyring")
try:
    datas += copy_metadata("secretstorage")
except Exception:
    pass

# On Python 3.15 pip picks cryptography's `cp315-abi3.abi3t` wheel, whose
# `_rust` extension links against the free-threaded ABI3 shim `python3t.dll`.
# The interpreter ships that DLL in an `abi3t-compat/` directory beside itself
# (not on PATH) and adds it to its own DLL search path at startup, so plain
# `import cryptography` works. PyInstaller cannot resolve it, so a frozen
# binary fails to import `cryptography` unless we bundle it explicitly.
binaries = []
abi3t_compat = os.path.join(sys.base_prefix, "abi3t-compat")
if os.path.isdir(abi3t_compat):
    binaries += [
        (os.path.join(abi3t_compat, name), ".")
        for name in os.listdir(abi3t_compat)
        if name.lower().endswith(".dll")
    ]

a = Analysis(
    [os.path.join(SPECPATH, "entrypoint.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="oc",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
