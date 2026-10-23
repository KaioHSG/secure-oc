"""Server state file: persistence, HMAC integrity and password handling."""

from __future__ import annotations

import json

import pytest

from secure_oc import paths, secrets_store, state


def test_save_and_load_round_trip():
    state.save("background", "pw123", 4242)
    current = state.load()
    assert current is not None
    assert current.mode == "background"
    assert current.pid == 4242
    assert current.password == "pw123"
    assert current.integrity_ok is True


def test_password_is_not_written_to_the_state_file():
    state.save("background", "pw123", 4242)
    raw = paths.STATE_PATH.read_text(encoding="utf-8")
    assert "pw123" not in raw


def test_tampering_breaks_integrity():
    state.save("background", "pw123", 4242)
    raw = json.loads(paths.STATE_PATH.read_text(encoding="utf-8"))
    raw["pid"] = 9999
    paths.STATE_PATH.write_text(json.dumps(raw), encoding="utf-8")

    current = state.load()
    assert current.pid == 9999
    assert current.integrity_ok is False


def test_set_activity_refreshes_and_resigns():
    state.save("background", "pw123", 4242)
    before = json.loads(paths.STATE_PATH.read_text(encoding="utf-8"))["lastActivity"]

    state.set_activity()

    raw = json.loads(paths.STATE_PATH.read_text(encoding="utf-8"))
    assert raw["lastActivity"] >= before
    assert state.load().integrity_ok is True


def test_clear_removes_state_and_forgets_password():
    state.save("background", "pw123", 4242)
    state.clear()

    assert not paths.STATE_PATH.exists()
    assert state.load() is None
    assert secrets_store.unprotect("server-password") is None


def test_load_without_state_returns_none():
    assert state.load() is None


def test_invalid_mode_is_rejected():
    with pytest.raises(ValueError):
        state.save("bogus", "pw", 1)
