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
    assert "1.0.2" in capsys.readouterr().out
