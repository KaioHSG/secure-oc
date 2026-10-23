"""Exception hierarchy for secure-oc."""

from __future__ import annotations


class SecureOcError(Exception):
    """Base class for every expected secure-oc failure."""


class CryptoError(SecureOcError):
    """The key store is malformed, truncated or uses an unsupported format."""


class WrongPasswordError(CryptoError):
    """Authentication failed: the master password is wrong or the file was tampered with."""


class ConfigError(SecureOcError):
    """The environment is not usable (missing opencode, bad arguments, ...)."""
