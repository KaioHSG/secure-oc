"""Installing Bun and opencode on demand."""

from __future__ import annotations

import subprocess

from secure_oc import installer


def test_find_bun_prefers_path(monkeypatch):
    monkeypatch.setattr(installer.shutil, "which", lambda name: "/usr/local/bin/bun")
    assert installer.find_bun() == "/usr/local/bin/bun"


def test_find_bun_falls_back_to_install_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(installer.shutil, "which", lambda name: None)
    bun = tmp_path / ("bun.exe" if installer.sys.platform.startswith("win32") else "bun")
    bun.write_text("", encoding="utf-8")
    monkeypatch.setattr(installer, "bun_bin_dir", lambda: tmp_path)
    assert installer.find_bun() == str(bun)


def test_find_bun_returns_none_when_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(installer.shutil, "which", lambda name: None)
    monkeypatch.setattr(installer, "bun_bin_dir", lambda: tmp_path)
    assert installer.find_bun() is None


def test_install_opencode_uses_bun_install_global(monkeypatch):
    calls = []
    monkeypatch.setattr(installer, "find_bun", lambda: "C:/bun/bun.exe")
    monkeypatch.setattr(installer.subprocess, "run", lambda args, **kw: calls.append(args))
    assert installer.install_opencode() is True
    assert calls == [["C:/bun/bun.exe", *installer.BUN_ARGS]]
    assert calls[0][1:] == ["install", "-g", "--trust", "@opencode/cli"]


def test_install_opencode_installs_bun_first(monkeypatch):
    calls = []
    buns = iter([None, "C:/bun/bun.exe"])
    monkeypatch.setattr(installer, "find_bun", lambda: next(buns))
    monkeypatch.setattr(installer, "install_bun", lambda: "C:/bun/bun.exe")
    monkeypatch.setattr(installer.subprocess, "run", lambda args, **kw: calls.append(args))
    assert installer.install_opencode() is True
    assert calls == [["C:/bun/bun.exe", *installer.BUN_ARGS]]


def test_install_opencode_fails_when_bun_cannot_be_installed(monkeypatch):
    monkeypatch.setattr(installer, "find_bun", lambda: None)
    monkeypatch.setattr(installer, "install_bun", lambda: None)
    assert installer.install_opencode() is False


def test_install_opencode_reports_bun_failure(monkeypatch, capsys):
    def explode(args, **kwargs):
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(installer, "find_bun", lambda: "C:/bun/bun.exe")
    monkeypatch.setattr(installer.subprocess, "run", explode)
    assert installer.install_opencode() is False
    assert "Could not install opencode" in capsys.readouterr().err


def test_install_bun_reports_failure(monkeypatch, capsys):
    def explode(args, **kwargs):
        raise OSError("no powershell")

    monkeypatch.setattr(installer.subprocess, "run", explode)
    assert installer.install_bun() is None
    assert "Could not install Bun" in capsys.readouterr().err


def test_install_bun_uses_powershell_on_windows(monkeypatch):
    calls = []
    monkeypatch.setattr(installer.sys, "platform", "win32")
    monkeypatch.setattr(installer, "find_bun", lambda: None)
    monkeypatch.setattr(installer.subprocess, "run", lambda args, **kw: calls.append(args))
    installer.install_bun()
    assert calls[0][0] == "powershell"
    assert "bun.sh/install.ps1" in calls[0][-1]


def test_install_bun_uses_curl_on_posix(monkeypatch):
    calls = []
    monkeypatch.setattr(installer.sys, "platform", "linux")
    monkeypatch.setattr(installer, "find_bun", lambda: None)
    monkeypatch.setattr(installer.subprocess, "run", lambda args, **kw: calls.append(args))
    installer.install_bun()
    assert calls[0] == ["sh", "-c", "curl -fsSL https://bun.sh/install | bash"]


def test_install_command_is_platform_neutral():
    assert installer.install_command() == "bun install -g --trust @opencode/cli"
