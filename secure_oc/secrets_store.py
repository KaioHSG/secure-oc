"""Protection of small secrets at rest (server password, HMAC key).

Three backends, tried in order of strength:

1. **OS keyring** — Windows Credential Manager, macOS Keychain or the
   freedesktop Secret Service. The secret never touches a file we manage.
2. **Windows DPAPI** — bound to the current user and machine.
3. **Local key file** — a random 32-byte key stored with ``0600`` perms
   next to the encrypted secret. This is the weakest option and only a
   fallback for headless POSIX systems without a keyring; it protects
   against casual file reads, not against an attacker who already runs as
   the current user.
"""

from __future__ import annotations

import base64
import ctypes
import os
import sys

from . import paths

SERVICE = "secure-oc"
_ENTROPY = b"secure-oc-secret"
_KEYFILE_NAME = ".key"

SCHEME_DPAPI = 0x01
SCHEME_KEYFILE = 0x02

_IS_WINDOWS = os.name == "nt"


def _debug(message: str) -> None:
    """Report a backend failure that was otherwise swallowed.

    Backends degrade silently by design, which can make a broken keyring
    look like a missing password. Set ``SECURE_OC_DEBUG`` to see why a
    backend was skipped or failed.
    """
    if os.environ.get("SECURE_OC_DEBUG"):
        print(f"[secure-oc] secret store: {message}", file=sys.stderr)


# --------------------------------------------------------------------------
# keyring backend
# --------------------------------------------------------------------------


def _keyring_module():
    try:
        import keyring  # type: ignore
    except Exception as exc:
        _debug(f"keyring is not installed ({exc})")
        return None
    try:
        backend = keyring.get_keyring()
    except Exception as exc:
        _debug(f"keyring backend lookup failed ({exc})")
        return None
    name = f"{type(backend).__module__}.{type(backend).__name__}".lower()
    if "fail" in name or "null" in name:
        _debug(f"keyring backend {name!r} is a null/fail backend")
        return None
    return keyring


def _kr_set(label: str, data: bytes) -> bool:
    kr = _keyring_module()
    if kr is None:
        return False
    try:
        kr.set_password(SERVICE, label, base64.b64encode(data).decode("ascii"))
        return True
    except Exception as exc:
        _debug(f"keyring set for {label!r} failed ({exc})")
        return False


def _kr_get(label: str):
    kr = _keyring_module()
    if kr is None:
        return None
    try:
        value = kr.get_password(SERVICE, label)
        return base64.b64decode(value) if value else None
    except Exception as exc:
        _debug(f"keyring get for {label!r} failed ({exc})")
        return None


def _kr_del(label: str) -> None:
    kr = _keyring_module()
    if kr is None:
        return
    try:
        kr.delete_password(SERVICE, label)
    except Exception as exc:
        _debug(f"keyring delete for {label!r} failed ({exc})")


# --------------------------------------------------------------------------
# Windows DPAPI backend
# --------------------------------------------------------------------------


def _dpapi(protect: bool, data: bytes, entropy: bytes = _ENTROPY) -> bytes:
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def to_blob(raw: bytes):
        buf = (ctypes.c_byte * len(raw)).from_buffer_copy(raw)
        blob = DATA_BLOB(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
        return blob, buf

    in_blob, _keep_in = to_blob(data)
    ent_blob, _keep_ent = to_blob(entropy)
    out_blob = DATA_BLOB()

    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(in_blob), None, ctypes.byref(ent_blob), None, None, 0,
            ctypes.byref(out_blob),
        )
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(in_blob), None, ctypes.byref(ent_blob), None, None, 0,
            ctypes.byref(out_blob),
        )
    if not ok:
        raise OSError(f"DPAPI call failed (error {ctypes.get_last_error()})")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_set(label: str, data: bytes) -> None:
    blob = bytes([SCHEME_DPAPI]) + _dpapi(True, data)
    paths.write_private(_secret_file(label), blob)


def _dpapi_get(label: str):
    path = _secret_file(label)
    if not path.exists():
        return None
    blob = path.read_bytes()
    if not blob or blob[0] != SCHEME_DPAPI:
        return None
    try:
        return _dpapi(False, blob[1:])
    except Exception as exc:
        _debug(f"DPAPI unprotect for {label!r} failed ({exc})")
        return None


# --------------------------------------------------------------------------
# local key-file backend
# --------------------------------------------------------------------------


def _load_keyfile() -> bytes:
    keyfile = paths.SECRETS_DIR / _KEYFILE_NAME
    if keyfile.exists():
        data = keyfile.read_bytes()
        if len(data) == 32:
            return data
    paths.ensure_state_dir()
    key = os.urandom(32)
    paths.write_private(keyfile, key)
    return key


def _keyfile_set(label: str, data: bytes) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _load_keyfile()
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, _ENTROPY)
    paths.write_private(_secret_file(label), bytes([SCHEME_KEYFILE]) + nonce + ciphertext)


def _keyfile_get(label: str):
    path = _secret_file(label)
    if not path.exists():
        return None
    blob = path.read_bytes()
    if not blob or blob[0] != SCHEME_KEYFILE:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(_load_keyfile()).decrypt(blob[1:13], blob[13:], _ENTROPY)
    except Exception as exc:
        _debug(f"key-file unprotect for {label!r} failed ({exc})")
        return None


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------


def _safe_label(label: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in label)


def _secret_file(label: str):
    return paths.SECRETS_DIR / f"{_safe_label(label)}.bin"


def protect(label: str, data: bytes) -> None:
    """Store *data* under *label*, using the strongest available backend."""
    paths.ensure_state_dir()
    if _kr_set(label, data):
        return
    if _IS_WINDOWS:
        try:
            _dpapi_set(label, data)
            return
        except Exception as exc:
            _debug(f"DPAPI protect for {label!r} failed, using key file ({exc})")
    _keyfile_set(label, data)


def unprotect(label: str):
    """Retrieve the secret stored under *label*, or ``None``."""
    value = _kr_get(label)
    if value is not None:
        return value
    if _IS_WINDOWS:
        value = _dpapi_get(label)
        if value is not None:
            return value
    return _keyfile_get(label)


def forget(label: str) -> None:
    """Remove a stored secret from every backend."""
    _kr_del(label)
    try:
        path = _secret_file(label)
        if path.exists():
            path.unlink()
    except Exception:
        pass


def backend_name() -> str:
    if _keyring_module() is not None:
        return "OS keyring"
    if _IS_WINDOWS:
        return "Windows DPAPI"
    return "local key file (0600, weak)"
