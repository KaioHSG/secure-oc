"""Key-store container: round-trip, authentication and error handling."""

from __future__ import annotations

import json
import struct

import pytest

from secure_oc import crypto
from secure_oc.errors import CryptoError, WrongPasswordError

PASSWORD = b"correct horse battery staple"


def test_round_trip():
    blob = crypto.encrypt(b'{"A":"1"}', PASSWORD)
    assert blob[:4] == crypto.MAGIC
    assert crypto.decrypt(blob, PASSWORD) == b'{"A":"1"}'


def test_wrong_password_is_reported():
    blob = crypto.encrypt(b"secret", PASSWORD)
    with pytest.raises(WrongPasswordError):
        crypto.decrypt(blob, b"not the password")


def test_bad_magic_is_rejected():
    blob = crypto.encrypt(b"secret", PASSWORD)
    with pytest.raises(CryptoError):
        crypto.decrypt(b"XXXX" + blob[4:], PASSWORD)


def test_truncated_blob_is_rejected():
    with pytest.raises(CryptoError):
        crypto.decrypt(b"SOC2\x00\x00", PASSWORD)


def test_encryption_is_randomised():
    assert crypto.encrypt(b"same", PASSWORD) != crypto.encrypt(b"same", PASSWORD)


def test_header_is_authenticated():
    """Bumping a KDF parameter must fail authentication, not weaken the file."""
    blob = crypto.encrypt(b"secret", PASSWORD)
    header_len = struct.unpack(">I", blob[4:8])[0]
    header = blob[8 : 8 + header_len]
    meta = json.loads(header)

    for key in ("m", "n", "iters", "t", "p", "r"):
        if isinstance(meta.get(key), int):
            meta[key] += 1  # same digit width, so the header length is stable
            break
    else:  # pragma: no cover - defensive
        pytest.skip("no integer KDF parameter to tamper with")

    new_header = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
    assert len(new_header) == header_len

    tampered = blob[:8] + new_header + blob[8 + header_len :]
    with pytest.raises(CryptoError):
        crypto.decrypt(tampered, PASSWORD)


def test_kdf_label_describes_algorithm():
    blob = crypto.encrypt(b"x", PASSWORD)
    label = crypto.kdf_label(blob)
    assert any(name in label for name in ("argon2id", "scrypt", "pbkdf2"))


def test_wrong_password_error_is_a_crypto_error():
    assert issubclass(WrongPasswordError, CryptoError)
