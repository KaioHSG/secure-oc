"""End-to-end CLI flows driven through ``main`` with piped stdin."""

from __future__ import annotations

import io
import sys

from secure_oc import cli, paths


def test_encrypt_then_decrypt(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO("masterpass\nmasterpass\nOPENROUTER_API_KEY\nsk-123\n\n"),
    )
    assert cli.main(["encrypt"]) == 0
    assert paths.KEYS_PATH.exists()

    monkeypatch.setattr(sys, "stdin", io.StringIO("masterpass\n"))
    assert cli.main(["decrypt"]) == 0
    assert "OPENROUTER_API_KEY" in capsys.readouterr().out


def test_decrypt_with_wrong_password_fails(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("masterpass\nmasterpass\nK\nv\n\n"))
    assert cli.main(["encrypt"]) == 0

    monkeypatch.setattr(sys, "stdin", io.StringIO("wrong-password\n"))
    assert cli.main(["decrypt"]) == 1
    assert "Wrong password" in capsys.readouterr().err


def test_reveal_print_requires_confirmation(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("masterpass\nmasterpass\nK\nv\n\n"))
    assert cli.main(["encrypt"]) == 0

    # Answer "n" to the confirmation prompt.
    monkeypatch.setattr(sys, "stdin", io.StringIO("masterpass\nn\n"))
    assert cli.main(["reveal", "--print"]) == 1
    assert "K=v" not in capsys.readouterr().out


def test_reveal_print_with_confirmation(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("masterpass\nmasterpass\nK\nv\n\n"))
    assert cli.main(["encrypt"]) == 0

    monkeypatch.setattr(sys, "stdin", io.StringIO("masterpass\ny\n"))
    assert cli.main(["reveal", "--print"]) == 0
    assert "K=v" in capsys.readouterr().out


def test_decrypt_without_store_errors(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert cli.main(["decrypt"]) == 1
    assert "No key store" in capsys.readouterr().err


def test_version_flag_prints_version(capsys):
    assert cli.main(["--version"]) == 0
    assert "1.0.3" in capsys.readouterr().out


def test_load_keys_is_optional_without_store(capsys):
    """No key store is not an error when keys are optional."""
    assert cli._load_keys(optional=True) == {}
    assert "No key store" in capsys.readouterr().out


def test_missing_opencode_offers_install(monkeypatch):
    from secure_oc import installer, server
    from secure_oc.errors import ConfigError

    calls = []

    def fake_find(explicit=None):
        calls.append(explicit)
        if len(calls) == 1:
            raise ConfigError("'opencode' not found in PATH.")
        return "C:/fake/opencode.cmd"

    installed = []
    monkeypatch.setattr(server, "find_opencode", fake_find)
    monkeypatch.setattr(installer, "install_opencode", lambda: installed.append(True) or True)
    monkeypatch.setattr(cli, "confirm", lambda question, assume_yes=False: True)

    assert cli._resolve_opencode({"opencode": None}) == "C:/fake/opencode.cmd"
    assert installed == [True]
    assert calls == [None, None]


def test_missing_opencode_install_declined(monkeypatch, capsys):
    from secure_oc import installer, server
    from secure_oc.errors import ConfigError

    def fake_find(explicit=None):
        raise ConfigError("'opencode' not found in PATH.")

    installed = []
    monkeypatch.setattr(server, "find_opencode", fake_find)
    monkeypatch.setattr(installer, "install_opencode", lambda: installed.append(True) or True)
    monkeypatch.setattr(cli, "confirm", lambda question, assume_yes=False: False)

    assert cli._resolve_opencode({"opencode": None}) is None
    assert installed == []
    assert "bun install -g --trust @opencode/cli" in capsys.readouterr().out


def test_explicit_path_never_offers_install(monkeypatch, capsys):
    """A wrong --opencode is a misconfiguration, not a missing dependency."""
    from secure_oc import server
    from secure_oc.errors import ConfigError

    def fake_find(explicit=None):
        raise ConfigError(f"--opencode points to a file that does not exist: {explicit}")

    def fail(question, assume_yes=False):
        raise AssertionError("must not prompt to install")

    monkeypatch.setattr(server, "find_opencode", fake_find)
    monkeypatch.setattr(cli, "confirm", fail)

    assert cli._resolve_opencode({"opencode": "C:/nope/opencode"}) is None
    assert "does not exist" in capsys.readouterr().err


def test_env_override_never_offers_install(monkeypatch, capsys):
    from secure_oc import server
    from secure_oc.errors import ConfigError

    monkeypatch.setenv(server.ENV_OPENCODE, "C:/nope/opencode")
    monkeypatch.setattr(
        server, "find_opencode", lambda explicit=None: (_ for _ in ()).throw(ConfigError("nope"))
    )
    monkeypatch.setattr(cli, "confirm", lambda *args, **kwargs: False)

    assert cli._resolve_opencode({"opencode": None}) is None
