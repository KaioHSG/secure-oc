"""Secret-store backends (forced to the key-file backend by conftest)."""

from __future__ import annotations

from secure_oc import secrets_store


def test_keyfile_round_trip():
    secrets_store.protect("label", b"top-secret")
    assert secrets_store.unprotect("label") == b"top-secret"


def test_forget_removes_the_secret():
    secrets_store.protect("label", b"top-secret")
    secrets_store.forget("label")
    assert secrets_store.unprotect("label") is None


def test_unprotect_missing_label_returns_none():
    assert secrets_store.unprotect("never-stored") is None


def test_backend_name_reports_key_file():
    assert "key file" in secrets_store.backend_name()


def test_labels_are_sanitised_for_filenames():
    secrets_store.protect("weird/label:with*chars", b"data")
    assert secrets_store.unprotect("weird/label:with*chars") == b"data"
