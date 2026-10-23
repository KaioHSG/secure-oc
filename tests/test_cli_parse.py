"""Argument parsing and small CLI helpers."""

from __future__ import annotations

import pytest

from secure_oc import cli
from secure_oc.errors import ConfigError


def test_defaults_are_empty():
    positional, opts = cli._parse([])
    assert positional == []
    assert opts["dir"] is None
    assert opts["background"] is False


def test_value_flags_are_extracted():
    positional, opts = cli._parse(["--dir", "/tmp/work", "session", "list"])
    assert opts["dir"] == "/tmp/work"
    assert positional == ["session", "list"]


def test_boolean_flags_and_aliases():
    _, opts = cli._parse(["-Background", "--Status", "--restart"])
    assert opts["background"] is True
    assert opts["status"] is True
    assert opts["restart"] is True


def test_value_flag_without_argument_raises():
    with pytest.raises(ConfigError):
        cli._parse(["--dir"])


def test_version_flag():
    _, opts = cli._parse(["--version"])
    assert opts["version"] is True


def test_generate_password_has_128_bits():
    password = cli.generate_password()
    assert len(password) == 32
    int(password, 16)  # valid hex
    assert password != cli.generate_password()
