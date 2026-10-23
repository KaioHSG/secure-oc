"""Shared pytest fixtures.

Every test runs against a throwaway ``~/.oc`` and a deterministic
key-file secret backend, so nothing touches the developer's real state
and the results do not depend on whether a keyring is installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Allow running the tests straight from a checkout.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secure_oc import paths, secrets_store


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Redirect all state files into a per-test temporary directory."""
    state_dir = tmp_path / ".oc"
    secrets_dir = state_dir / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(paths, "STATE_DIR", state_dir)
    monkeypatch.setattr(paths, "KEYS_PATH", state_dir / "keys.dat")
    monkeypatch.setattr(paths, "STATE_PATH", state_dir / "server-state.json")
    monkeypatch.setattr(paths, "SECRETS_DIR", secrets_dir)
    # Avoid spawning icacls/chmod on every write during tests.
    monkeypatch.setattr(paths, "harden", lambda *args, **kwargs: None)
    return state_dir


@pytest.fixture(autouse=True)
def keyfile_backend(monkeypatch):
    """Force the local key-file backend for reproducible secrets handling."""
    monkeypatch.setattr(secrets_store, "_keyring_module", lambda: None)
    monkeypatch.setattr(secrets_store, "_IS_WINDOWS", False)
