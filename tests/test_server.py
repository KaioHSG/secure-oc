"""opencode resolution, environment building and PID identity checks."""

from __future__ import annotations

import os

import pytest

from secure_oc import server
from secure_oc.errors import ConfigError


def test_explicit_path_must_exist(tmp_path):
    with pytest.raises(ConfigError):
        server.find_opencode(str(tmp_path / "missing"))


def test_env_variable_is_used(monkeypatch, tmp_path):
    fake = tmp_path / "opencode"
    fake.write_text("", encoding="utf-8")
    monkeypatch.setenv(server.ENV_OPENCODE, str(fake))
    assert server.find_opencode() == str(fake)


def test_explicit_path_beats_env(monkeypatch, tmp_path):
    env_binary = tmp_path / "env-opencode"
    env_binary.write_text("", encoding="utf-8")
    explicit = tmp_path / "explicit-opencode"
    explicit.write_text("", encoding="utf-8")
    monkeypatch.setenv(server.ENV_OPENCODE, str(env_binary))
    assert server.find_opencode(str(explicit)) == str(explicit)


def test_missing_everywhere_raises(monkeypatch):
    monkeypatch.delenv(server.ENV_OPENCODE, raising=False)
    monkeypatch.setattr(server.shutil, "which", lambda name: None)
    monkeypatch.setattr(server, "_search_extra_dirs", lambda: [])
    with pytest.raises(ConfigError):
        server.find_opencode()


def test_falls_back_to_known_install_dirs(monkeypatch, tmp_path):
    """A launcher without a shell PATH still finds an installed opencode."""
    monkeypatch.delenv(server.ENV_OPENCODE, raising=False)
    monkeypatch.setattr(server.shutil, "which", lambda name: None)
    fake = tmp_path / server._OPENCODE_NAMES[0]
    fake.write_text("", encoding="utf-8")
    monkeypatch.setattr(server, "_search_extra_dirs", lambda: [str(tmp_path)])
    assert server.find_opencode() == str(fake)


def test_extra_dirs_are_deduplicated(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_registry_path_dirs", lambda: [str(tmp_path)])
    monkeypatch.setattr(server, "_version_manager_dirs", lambda: [str(tmp_path)])
    monkeypatch.setattr(server, "_package_manager_dirs", lambda: [str(tmp_path)])
    assert server._search_extra_dirs() == [str(tmp_path)]


def test_version_managers_come_before_npm_prefix(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_registry_path_dirs", lambda: [])
    monkeypatch.setattr(server, "_version_manager_dirs", lambda: [str(tmp_path / "fnm")])
    monkeypatch.setattr(server, "_package_manager_dirs", lambda: [str(tmp_path / "npm")])
    assert server._search_extra_dirs() == [str(tmp_path / "fnm"), str(tmp_path / "npm")]


def test_ensure_on_path_prepends_binary_dir(tmp_path):
    other = tmp_path / "other"
    env = {"PATH": str(other)}
    server.ensure_on_path(env, str(tmp_path / "opencode"))
    assert env["PATH"].split(os.pathsep) == [str(tmp_path), str(other)]


def test_ensure_on_path_is_idempotent(tmp_path):
    other = tmp_path / "other"
    frozen = os.pathsep.join([str(tmp_path), str(other)])
    env = server.ensure_on_path({"PATH": frozen}, str(tmp_path / "opencode"))
    assert env["PATH"] == frozen


def test_ps1_is_swapped_for_cmd_sibling(tmp_path):
    ps1 = tmp_path / "opencode.ps1"
    ps1.write_text("", encoding="utf-8")
    cmd = tmp_path / "opencode.cmd"
    cmd.write_text("", encoding="utf-8")
    assert server._normalize_opencode(str(ps1)) == str(cmd)


def test_ps1_without_cmd_sibling_is_kept(tmp_path):
    ps1 = tmp_path / "opencode.ps1"
    ps1.write_text("", encoding="utf-8")
    assert server._normalize_opencode(str(ps1)) == str(ps1)


def test_build_env_injects_keys_without_mutating_parent(monkeypatch):
    monkeypatch.setenv("PATH", "unchanged")
    monkeypatch.delenv("SECURE_OC_TEST_API_KEY", raising=False)
    env = server.build_env({"secure_oc_test_api_key": "sk-1"}, "server-pw")
    assert env["SECURE_OC_TEST_API_KEY"] == "sk-1"
    assert env["OPENCODE_SERVER_PASSWORD"] == "server-pw"
    assert "SECURE_OC_TEST_API_KEY" not in os.environ


def test_build_env_without_password(monkeypatch):
    monkeypatch.delenv("OPENCODE_SERVER_PASSWORD", raising=False)
    env = server.build_env({}, None)
    assert "OPENCODE_SERVER_PASSWORD" not in env


def test_pid_identity_positive(monkeypatch):
    monkeypatch.setattr(
        server, "_process_description", lambda pid: "node /usr/bin/opencode serve --port 4096"
    )
    assert server.pid_looks_like_opencode(1234) is True


def test_pid_identity_negative(monkeypatch):
    monkeypatch.setattr(server, "_process_description", lambda pid: "python.exe -m pytest")
    assert server.pid_looks_like_opencode(1234) is False


def test_pid_identity_is_conservative_when_unknown(monkeypatch):
    monkeypatch.setattr(server, "_process_description", lambda pid: None)
    assert server.pid_looks_like_opencode(1234) is False


def test_pid_identity_rejects_non_positive():
    assert server.pid_looks_like_opencode(0) is False
    assert server.pid_looks_like_opencode(-5) is False
