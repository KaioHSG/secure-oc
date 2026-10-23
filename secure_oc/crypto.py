"""Authenticated encryption for the secure-oc key store.

Container format (all integers big-endian)::

    magic        4 bytes   b"SOC2"
    header_len   4 bytes   uint32
    header       N bytes   UTF-8 JSON (KDF parameters)
    salt        16 bytes
    nonce       12 bytes
    ciphertext   ...       AES-256-GCM ciphertext || 16-byte tag

The header is authenticated as associated data, so downgrading the KDF or
tampering with its parameters makes decryption fail instead of silently
weakening the file.

Key derivation prefers Argon2id, falls back to scrypt, then PBKDF2-SHA256.
The algorithm actually used is recorded in the header, so files stay
readable regardless of which optional dependency is installed later.
"""

from __future__ import annotations

import json
import os
import struct

from .errors import CryptoError, WrongPasswordError

try:  # pragma: no cover - exercised via the import guard
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _HAVE_AESGCM = True
except Exception:  # pragma: no cover
    AESGCM = None  # type: ignore[assignment]
    _HAVE_AESGCM = False

try:
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_raw

    _HAVE_ARGON2 = True
except Exception:  # pragma: no cover
    _HAVE_ARGON2 = False

MAGIC = b"SOC2"
VERSION = 2

SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32

ARGON2_PARAMS = {"t": 3, "m": 65536, "p": 4}
SCRYPT_PARAMS = {"n": 65536, "r": 8, "p": 1}
PBKDF2_PARAMS = {"iters": 600_000}

_MIN_BLOB = 4 + 4 + SALT_LEN + NONCE_LEN + TAG_LEN


def require_aesgcm() -> None:
    if not _HAVE_AESGCM:
        raise CryptoError(
            "The 'cryptography' package is required for AES-256-GCM. "
            "Install it with: pip install cryptography"
        )


def default_kdf() -> tuple[str, dict]:
    """Return the strongest KDF available on this machine."""
    if _HAVE_ARGON2:
        return "argon2id", dict(ARGON2_PARAMS)
    return "scrypt", dict(SCRYPT_PARAMS)


def _derive_key(password: bytes, salt: bytes, kdf: str, params: dict) -> bytes:
    if kdf == "argon2id":
        if not _HAVE_ARGON2:
            raise CryptoError(
                "This key store was written with Argon2id but 'argon2-cffi' is not "
                "installed. Install it with: pip install argon2-cffi"
            )
        return _argon2_raw(
            secret=password,
            salt=salt,
            time_cost=int(params.get("t", ARGON2_PARAMS["t"])),
            memory_cost=int(params.get("m", ARGON2_PARAMS["m"])),
            parallelism=int(params.get("p", ARGON2_PARAMS["p"])),
            hash_len=KEY_LEN,
            type=_Argon2Type.ID,
        )

    if kdf == "scrypt":
        import hashlib

        n = int(params.get("n", SCRYPT_PARAMS["n"]))
        r = int(params.get("r", SCRYPT_PARAMS["r"]))
        p = int(params.get("p", SCRYPT_PARAMS["p"]))
        maxmem = 128 * n * r * 2 + (1 << 20)
        return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=KEY_LEN, maxmem=maxmem)

    if kdf == "pbkdf2":
        import hashlib

        iters = int(params.get("iters", PBKDF2_PARAMS["iters"]))
        return hashlib.pbkdf2_hmac("sha256", password, salt, iters, dklen=KEY_LEN)

    raise CryptoError(f"Unsupported key-derivation function: {kdf!r}")


def _header_bytes(kdf: str, params: dict) -> bytes:
    header = {
        "v": VERSION,
        "alg": "AES-256-GCM",
        "kdf": kdf,
        "salt_len": SALT_LEN,
        "nonce_len": NONCE_LEN,
        **params,
    }
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt(plaintext: bytes, password: bytes) -> bytes:
    """Encrypt *plaintext* and return the self-describing container blob."""
    require_aesgcm()

    kdf, params = default_kdf()
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = _header_bytes(kdf, params)
    aad = MAGIC + header

    key = _derive_key(password, salt, kdf, params)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

    return (
        MAGIC
        + struct.pack(">I", len(header))
        + header
        + salt
        + nonce
        + ciphertext
    )


def decrypt(blob: bytes, password: bytes) -> bytes:
    """Decrypt a container blob produced by :func:`encrypt`."""
    require_aesgcm()

    if len(blob) < _MIN_BLOB:
        raise CryptoError("Key store is truncated or not a secure-oc file.")
    if blob[:4] != MAGIC:
        raise CryptoError(
            "Unrecognised key-store format. This build only reads the 'SOC2' "
            "format; recreate it with 'oc encrypt'."
        )

    header_len = struct.unpack(">I", blob[4:8])[0]
    offset = 8
    header = blob[offset : offset + header_len]
    offset += header_len

    try:
        meta = json.loads(header)
    except Exception as exc:
        raise CryptoError("Key store header is corrupt.") from exc

    if int(meta.get("v", 0)) != VERSION:
        raise CryptoError(f"Unsupported key-store version: {meta.get('v')!r}")

    salt_len = int(meta.get("salt_len", SALT_LEN))
    nonce_len = int(meta.get("nonce_len", NONCE_LEN))
    salt = blob[offset : offset + salt_len]
    offset += salt_len
    nonce = blob[offset : offset + nonce_len]
    offset += nonce_len
    ciphertext = blob[offset:]

    if len(ciphertext) < TAG_LEN or len(salt) != salt_len or len(nonce) != nonce_len:
        raise CryptoError("Key store is truncated.")

    params = {k: v for k, v in meta.items() if k in ("t", "m", "p", "n", "r", "iters")}
    key = _derive_key(password, salt, str(meta.get("kdf")), params)
    aad = MAGIC + header

    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise WrongPasswordError(
            "Wrong password, corrupted file, or tampering detected."
        ) from exc


def kdf_label(blob: bytes) -> str:
    """Best-effort description of the KDF used by a container blob."""
    try:
        header_len = struct.unpack(">I", blob[4:8])[0]
        meta = json.loads(blob[8 : 8 + header_len])
    except Exception:
        return "unknown"
    kdf = str(meta.get("kdf", "unknown"))
    if kdf == "argon2id":
        return f"argon2id (t={meta.get('t')}, m={meta.get('m')} KiB, p={meta.get('p')})"
    if kdf == "scrypt":
        return f"scrypt (n={meta.get('n')}, r={meta.get('r')}, p={meta.get('p')})"
    if kdf == "pbkdf2":
        return f"pbkdf2-sha256 ({meta.get('iters')} iterations)"
    return kdf
