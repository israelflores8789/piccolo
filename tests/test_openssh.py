# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_openssh.py — Provider-independent keys, client selection, and transfers."""

import hashlib
import os
import re
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from platform_support import assert_private

from piccolo.errors import PiccoloError
from piccolo.openssh import OpenSSH, SSHSession, write_host_keys
from piccolo.process import run_command
from piccolo.state.lock import file_lock
from piccolo.state.storage import private_directory


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> OpenSSH:
    """Use an offline runtime with private shared locks and no cloud identity."""
    monkeypatch.setattr(
        "piccolo.openssh.user_state_path",
        Mock(return_value=tmp_path / "shared-key-locks"),
    )
    return OpenSSH(lambda: os.environ.copy(), lambda: None)


@pytest.fixture
def session(tmp_path: Path) -> SSHSession:
    """Use a provider-neutral identity and paths with spaces and Unicode."""
    root = tmp_path / "profile with spaces \u00e9"
    return SSHSession(
        address="192.0.2.7",
        username="researcher",
        key_file=root / ".ssh" / "fixture_key",
        known_hosts=root / "trust",
        host_alias="fixture-host",
        empty_config=root / "empty",
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows OpenSSH")
def test_native_executables_ignore_git_bash_path(
    client: OpenSSH, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", "C:\\Program Files\\Git\\usr\\bin;" + os.environ["PATH"])
    executable = Path(client.executable("ssh"))
    assert executable.name == "ssh.exe"
    assert executable.parent == Path(os.environ["SYSTEMROOT"]) / "System32" / "OpenSSH"
    assert Path(client.executable("scp")).parent == executable.parent


def test_native_client_missing_has_no_path_fallback(
    client: OpenSSH,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client.windows = True
    monkeypatch.setenv("SYSTEMROOT", str(tmp_path / "missing-native-installation"))
    with pytest.raises(PiccoloError, match="optional feature"):
        client.executable("ssh")


def test_native_minimum_version_is_enforced(
    client: OpenSSH,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client.windows = True
    root = tmp_path / "windows"
    directory = root / "System32" / "OpenSSH"
    directory.mkdir(parents=True)
    for name in ("ssh", "scp", "ssh-keygen"):
        (directory / f"{name}.exe").write_bytes(b"offline placeholder")
    monkeypatch.setenv("SYSTEMROOT", str(root))
    monkeypatch.delenv("PROCESSOR_ARCHITEW6432", raising=False)
    monkeypatch.setattr(
        "piccolo.openssh.run_command",
        Mock(
            return_value=subprocess.CompletedProcess(
                [], 0, "", "OpenSSH_for_Windows_8.9p1"
            )
        ),
    )
    with pytest.raises(PiccoloError, match=r"9\.0"):
        client.executable("ssh")


def test_generate_reuse_and_recover_public_without_replacing_key(
    client: OpenSSH,
    session: SSHSession,
) -> None:
    public = client.prepare_key(
        session.key_file, session.username, session.require_passphrase
    )
    original = session.key_file.read_bytes()
    assert public.startswith("ssh-rsa ")
    assert_private(session.key_file)
    assert_private(session.key_file.with_name(session.key_file.name + ".pub"))
    assert (
        client.prepare_key(
            session.key_file, session.username, session.require_passphrase
        )
        == public
    )
    assert session.key_file.read_bytes() == original
    session.key_file.with_name(session.key_file.name + ".pub").unlink()
    assert (
        client.prepare_key(
            session.key_file, session.username, session.require_passphrase
        ).split()[:2]
        == public.split()[:2]
    )
    assert session.key_file.read_bytes() == original


def test_broken_or_mismatched_pair_is_never_overwritten(
    client: OpenSSH, session: SSHSession, tmp_path: Path
) -> None:
    client.prepare_key(session.key_file, session.username, session.require_passphrase)
    original = session.key_file.read_bytes()
    other = tmp_path / "other-key"
    generated = run_command(
        [
            client.executable("ssh-keygen"),
            "-t",
            "ed25519",
            "-f",
            str(other),
            "-N",
            "",
        ],
        os.environ.copy(),
    )
    assert generated.returncode == 0
    public = session.key_file.with_name(session.key_file.name + ".pub")
    public.write_bytes(other.with_suffix(".pub").read_bytes())
    unrelated = public.read_bytes()
    with pytest.raises(PiccoloError, match="do not match"):
        client.prepare_key(
            session.key_file, session.username, session.require_passphrase
        )
    assert session.key_file.read_bytes() == original
    assert public.read_bytes() == unrelated
    session.key_file.write_bytes(b"broken private key")
    with pytest.raises(PiccoloError, match="Invalid or unsupported"):
        client.prepare_key(
            session.key_file, session.username, session.require_passphrase
        )
    assert session.key_file.read_bytes() == b"broken private key"


def test_existing_encrypted_pair_can_use_agent_without_forcing_prompt(
    client: OpenSSH,
    session: SSHSession,
) -> None:
    private_directory(session.key_file.parent)
    generated = run_command(
        [
            client.executable("ssh-keygen"),
            "-t",
            "ed25519",
            "-f",
            str(session.key_file),
            "-N",
            "offline-fixture-passphrase",
        ],
        os.environ.copy(),
    )
    assert generated.returncode == 0
    original = session.key_file.read_bytes()
    assert client.prepare_key(
        session.key_file, session.username, session.require_passphrase
    ).startswith("ssh-ed25519 ")
    assert session.key_file.read_bytes() == original
    session = replace(session, require_passphrase=True)
    assert client.prepare_key(
        session.key_file, session.username, session.require_passphrase
    ).startswith("ssh-ed25519 ")
    assert_private(session.key_file)


def test_passphrase_requirement_rejects_unencrypted_pair(
    client: OpenSSH,
    session: SSHSession,
) -> None:
    client.prepare_key(session.key_file, session.username, session.require_passphrase)
    session = replace(session, require_passphrase=True)
    with pytest.raises(PiccoloError, match="requires an encrypted"):
        client.prepare_key(
            session.key_file, session.username, session.require_passphrase
        )


def test_native_scp_retries_only_pre_authentication_rejection(
    client: OpenSSH,
    session: SSHSession,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client, "executable", Mock(return_value="native-scp.exe"))
    monkeypatch.setattr("piccolo.openssh.time.sleep", Mock(return_value=None))
    launch = Mock(
        side_effect=[
            subprocess.CompletedProcess([], 255, "", "Permission denied (publickey)"),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
    )
    monkeypatch.setattr("piccolo.openssh.run_command", launch)
    client.transfer(session, tmp_path / "source with spaces", ".piccolo/setup.upload")
    assert launch.call_count == 2
    assert launch.call_args_list[0].args[0] == launch.call_args_list[1].args[0]
    launch.reset_mock(side_effect=True)
    launch.return_value = subprocess.CompletedProcess([], 255, "", "Connection reset")
    with pytest.raises(PiccoloError, match="Connection reset"):
        client.transfer(session, tmp_path / "source", ".piccolo/setup.upload")
    assert launch.call_count == 1


def test_key_preparation_uses_one_lock_across_state_overrides(
    client: OpenSSH,
    session: SSHSession,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = hashlib.sha256(
        str(session.key_file.absolute()).casefold().encode()
    ).hexdigest()
    lock = tmp_path / "shared-key-locks" / "ssh-locks" / f"{key}.lock"
    with file_lock(lock):
        monkeypatch.setenv("PICCOLO_STATE_DIR", str(tmp_path / "different-state-root"))
        with pytest.raises(PiccoloError, match="environment lock"):
            client.prepare_key(
                session.key_file, session.username, session.require_passphrase
            )
    assert client.prepare_key(
        session.key_file, session.username, session.require_passphrase
    ).startswith("ssh-rsa ")


@pytest.mark.parametrize("capture", [True, False])
def test_resolved_session_preserves_trust_proxy_terminal_and_output(
    client: OpenSSH,
    session: SSHSession,
    monkeypatch: pytest.MonkeyPatch,
    capture: bool,
) -> None:
    session = replace(session, proxy_command='"proxy with spaces" --binary')
    monkeypatch.setattr(client, "executable", Mock(return_value="fixture-ssh"))
    launch = Mock(return_value=subprocess.CompletedProcess([], 7, "result", "error"))
    monkeypatch.setattr("piccolo.openssh.run_command", launch)
    assert session.proxy_command is not None
    result = client.command(session, "printf result", timeout=None, capture=capture)
    assert result.returncode == 7
    assert result.stdout == "result"
    arguments, environment = launch.call_args.args
    assert arguments[:5] == [
        "fixture-ssh",
        "-F",
        str(session.empty_config),
        "-i",
        str(session.key_file),
    ]
    assert arguments[-3:] == [
        "-T" if capture else "-tt",
        "researcher@192.0.2.7",
        "printf result",
    ]
    assert f'UserKnownHostsFile="{session.known_hosts.as_posix()}"' in arguments
    assert f'GlobalKnownHostsFile="{session.empty_config.as_posix()}"' in arguments
    for option in (
        "HostKeyAlias=fixture-host",
        "StrictHostKeyChecking=yes",
        "KnownHostsCommand=none",
        "VerifyHostKeyDNS=no",
        "UpdateHostKeys=no",
        "CheckHostIP=no",
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "PreferredAuthentications=publickey",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "ProxyCommand=" + session.proxy_command,
    ):
        assert option in arguments
    assert environment.get("HOME") == os.environ.get("HOME")
    assert launch.call_args.kwargs == {
        "timeout": None,
        "capture": capture,
        "prompts": False,
    }


def test_prompt_capture_frames_only_remote_output(
    client: OpenSSH, session: SSHSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = replace(session, require_passphrase=True)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    monkeypatch.setattr(client, "executable", Mock(return_value="fixture-ssh"))

    def launch(
        arguments: list[str],
        _environment: dict[str, str],
        *,
        timeout: float | None,
        capture: bool,
        prompts: bool,
    ) -> subprocess.CompletedProcess[str]:
        assert timeout is not None and timeout <= 8
        assert capture and prompts
        assert "BatchMode=no" in arguments
        match = re.search(r"piccolo-output-[a-f0-9]+", arguments[-1])
        assert match is not None
        marker = match.group()
        return subprocess.CompletedProcess(
            arguments, 3, f"prompt\r\n{marker}\r\nremote\r\n{marker}\r\n", ""
        )

    monkeypatch.setattr("piccolo.openssh.run_command", launch)
    result = client.command(session, "exit 3", timeout=8, capture=True)
    assert result.stdout == "remote\n"
    assert result.returncode == 3


def test_expired_deadline_and_environment_rejection_prevent_launch(
    client: OpenSSH, session: SSHSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client, "executable", Mock(return_value="fixture-ssh"))
    launch = Mock()
    monkeypatch.setattr("piccolo.openssh.run_command", launch)
    client.deadline = lambda: time.monotonic() - 1
    with pytest.raises(PiccoloError, match="preparation timed out"):
        client.command(session, "true", timeout=8, capture=True)
    launch.assert_not_called()
    client.deadline = lambda: None

    def rejected() -> dict[str, str]:
        raise PiccoloError("runtime environment rejected")

    client.environment = rejected
    with pytest.raises(PiccoloError, match="environment rejected"):
        client.command(session, "true", timeout=8, capture=True)
    launch.assert_not_called()


@pytest.mark.parametrize(
    "destination", ["", "/absolute", "../escape", "a/../b", "a\nb", "a\rb", "a\0b"]
)
def test_transfer_refuses_unsafe_destination_before_launch(
    client: OpenSSH,
    session: SSHSession,
    monkeypatch: pytest.MonkeyPatch,
    destination: str,
) -> None:
    launch = Mock()
    monkeypatch.setattr("piccolo.openssh.run_command", launch)
    with pytest.raises(PiccoloError, match="safe home-relative"):
        client.transfer(session, Path("source"), destination)
    launch.assert_not_called()


def test_host_trust_append_preserves_entries_and_private_permissions(
    tmp_path: Path,
) -> None:
    path = tmp_path / "trust"
    write_host_keys(path, ["host-a ssh-ed25519 authenticated-a\n"])
    write_host_keys(path, ["host-b ssh-ed25519 authenticated-b\n"])
    assert path.read_bytes() == (
        b"host-a ssh-ed25519 authenticated-a\nhost-b ssh-ed25519 authenticated-b\n"
    )
    assert_private(path)
