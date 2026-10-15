# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_guest_shell.py — Keep Windows guest emulation on Git Bash."""

from pathlib import Path

import platform_support
import pytest


def test_windows_guest_shell_ignores_shadowing_wsl_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Select Git's paired tools even when bare Bash resolves to a WSL launcher."""
    binaries = tmp_path / "Git" / "usr" / "bin"
    binaries.mkdir(parents=True)
    for name in ("cygpath.exe", "bash.exe", "msys-2.0.dll"):
        (binaries / name).touch()
    wsl = tmp_path / "System32" / "bash.exe"
    wsl.parent.mkdir()
    wsl.touch()

    def which(name: str) -> str | None:
        if name == "cygpath":
            return str(binaries / "cygpath.exe")
        if name == "bash":
            return str(wsl)
        return None

    with monkeypatch.context() as patch:
        patch.setattr(platform_support.sys, "platform", "win32")
        patch.setattr(platform_support.shutil, "which", which)
        selected = platform_support.guest_bash()
    assert selected == str((binaries / "bash.exe").resolve())


def test_windows_guest_shell_requires_git_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail clearly instead of falling back to an unrelated Bash installation."""
    with monkeypatch.context() as patch:
        patch.setattr(platform_support.sys, "platform", "win32")
        patch.setattr(platform_support.shutil, "which", lambda _name: None)
        with pytest.raises(pytest.fail.Exception, match="Git for Windows usr/bin"):
            platform_support.guest_bash()
