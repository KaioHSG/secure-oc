# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: build a single-file "oc" binary for the current OS.

Cross-compilation is not supported by PyInstaller, so this spec is meant to
run once per platform (see .github/workflows/build.yaml).
"""

import os
import sys

from PyInstaller.utils.hooks import collect_submodules, copy_metadata

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

# The Windows executable embeds packaging/icon.png: a ready-made
# packaging/icon.ico wins, otherwise the PNG is converted (Pillow, a build
# dependency) into a multi-resolution .ico under build/icons/. Non-square
# artwork is padded with transparency instead of being stretched. Other
# platforms have nothing to embed: Linux ELF binaries carry no icon, and macOS
# only uses one for .app bundles, which this single-file CLI build does not
# produce.
icon = None
_png = os.path.join(SPECPATH, "icon.png")
if sys.platform.startswith("win32"):
    try:
        from PIL import Image
    except ImportError:
        raise SystemExit(
            f"Found {_png} but Pillow is not installed.\n"
            "Install the build dependencies first:\n"
            "    python -m pip install -r requirements-build.txt"
        ) from None
    _src = Image.open(_png).convert("RGBA")
    if _src.width != _src.height:
        _side = max(_src.size)
        _square = Image.new("RGBA", (_side, _side), (0, 0, 0, 0))
        _square.paste(_src, ((_side - _src.width) // 2, (_side - _src.height) // 2))
        _src = _square
    _out_dir = os.path.join(ROOT, "build", "icons")
    os.makedirs(_out_dir, exist_ok=True)
    icon = os.path.join(_out_dir, "icon.ico")
    _src.save(
        icon,
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )

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
    icon=icon,
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
