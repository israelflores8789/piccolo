# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_native_ssh.py — Offline native client, keys, binary IAP, and foreground IO."""

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from platform_support import assert_private, redirect

from piccolo.config import Config
from piccolo.errors import PiccoloError
from piccolo.process import run_command
from piccolo.providers.gcp.connection import GCloudConnection
from piccolo.state.lock import file_lock
from piccolo.state.storage import private_directory


@pytest.fixture
def native(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> GCloudConnection:
    algorithm = b"ssh-ed25519"
    encoded = base64.b64encode(
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + (32).to_bytes(4, "big")
        + b"k" * 32
    ).decode()
    connection = GCloudConnection(
        replace(config.gcp, connection_account="connector@example.test"),
        lambda _zone: {
            "id": "123",
            "network_interfaces": [
                {
                    "network_i_p": "10.0.0.7",
                    "access_configs": [{"nat_i_p": "192.0.2.7"}],
                }
            ],
        },
        lambda _zone: {
            "query_value": {
                "items": [
                    {"namespace": "hostkeys", "key": "ssh-ed25519", "value": encoded}
                ]
            }
        },
    )
    connection.windows = True
    connection.user_home = tmp_path / "profile with spaces \u00e9"
    connection.key_file = connection.user_home / ".ssh" / "google_compute_engine"
    monkeypatch.setattr(
        connection,
        "environment",
        lambda: {**os.environ, "CLOUDSDK_CONFIG": str(connection.sdk_directory)},
    )
    monkeypatch.setattr(connection, "before_ssh", lambda _zone: None)
    monkeypatch.setattr(connection.ssh.authorization, "authorize", Mock())
    monkeypatch.setattr(
        "piccolo.providers.gcp.ssh.user_state_path",
        lambda *_args, **_kwargs: tmp_path / "shared-key-locks",
    )
    return connection


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows OpenSSH")
def test_native_executables_ignore_git_bash_path(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", "C:\\Program Files\\Git\\usr\\bin;" + os.environ["PATH"])
    executable = Path(native.ssh.executable("ssh"))
    assert executable.name == "ssh.exe"
    assert executable.parent == Path(os.environ["SYSTEMROOT"]) / "System32" / "OpenSSH"
    assert Path(native.ssh.executable("scp")).parent == executable.parent


def test_native_client_missing_has_no_path_fallback(
    native: GCloudConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYSTEMROOT", str(tmp_path / "missing-native-installation"))
    with pytest.raises(PiccoloError, match="optional feature"):
        native.ssh.executable("ssh")


def test_native_minimum_version_is_enforced(
    native: GCloudConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "windows"
    directory = root / "System32" / "OpenSSH"
    directory.mkdir(parents=True)
    for name in ("ssh", "scp", "ssh-keygen"):
        (directory / f"{name}.exe").write_bytes(b"offline placeholder")
    monkeypatch.setenv("SYSTEMROOT", str(root))
    monkeypatch.delenv("PROCESSOR_ARCHITEW6432", raising=False)
    monkeypatch.setattr(
        "piccolo.providers.gcp.ssh.run_command",
        Mock(
            return_value=subprocess.CompletedProcess(
                [], 0, "", "OpenSSH_for_Windows_8.9p1"
            )
        ),
    )
    with pytest.raises(PiccoloError, match=r"9\.0"):
        native.ssh.executable("ssh")


@pytest.mark.skipif(sys.platform != "win32", reason="Actual native key generation")
def test_generate_reuse_and_recover_public_without_replacing_key(
    native: GCloudConnection,
) -> None:
    public = native.ssh.prepare_key()
    original = native.key_file.read_bytes()
    assert public.startswith("ssh-rsa ")
    assert_private(native.key_file)
    assert_private(native.key_file.with_name(native.key_file.name + ".pub"))
    assert native.ssh.prepare_key() == public
    assert native.key_file.read_bytes() == original
    native.key_file.with_name(native.key_file.name + ".pub").unlink()
    assert native.ssh.prepare_key().split()[:2] == public.split()[:2]
    assert native.key_file.read_bytes() == original


@pytest.mark.skipif(sys.platform != "win32", reason="Actual native key validation")
def test_broken_or_mismatched_pair_is_never_overwritten(
    native: GCloudConnection, tmp_path: Path
) -> None:
    native.ssh.prepare_key()
    original = native.key_file.read_bytes()
    other = tmp_path / "other-key"
    generated = run_command(
        [
            native.ssh.executable("ssh-keygen"),
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
    public = native.key_file.with_name(native.key_file.name + ".pub")
    public.write_bytes(other.with_suffix(".pub").read_bytes())
    unrelated = public.read_bytes()
    with pytest.raises(PiccoloError, match="do not match"):
        native.ssh.prepare_key()
    assert native.key_file.read_bytes() == original
    assert public.read_bytes() == unrelated
    native.key_file.write_bytes(b"broken private key")
    with pytest.raises(PiccoloError, match="Invalid or unsupported"):
        native.ssh.prepare_key()
    assert native.key_file.read_bytes() == b"broken private key"


@pytest.mark.skipif(sys.platform != "win32", reason="Actual native encrypted key")
def test_existing_encrypted_pair_can_use_agent_without_forcing_prompt(
    native: GCloudConnection,
) -> None:
    private_directory(native.key_file.parent)
    generated = run_command(
        [
            native.ssh.executable("ssh-keygen"),
            "-t",
            "ed25519",
            "-f",
            str(native.key_file),
            "-N",
            "offline-fixture-passphrase",
        ],
        os.environ.copy(),
    )
    assert generated.returncode == 0
    original = native.key_file.read_bytes()
    assert native.ssh.prepare_key().startswith("ssh-ed25519 ")
    assert native.key_file.read_bytes() == original
    native.config = replace(native.config, require_passphrase=True)
    assert native.ssh.prepare_key().startswith("ssh-ed25519 ")
    assert_private(native.key_file)


@pytest.mark.skipif(sys.platform != "win32", reason="Actual native key enforcement")
def test_passphrase_requirement_rejects_unencrypted_pair(
    native: GCloudConnection,
) -> None:
    native.ssh.prepare_key()
    native.config = replace(native.config, require_passphrase=True)
    with pytest.raises(PiccoloError, match="requires an encrypted"):
        native.ssh.prepare_key()


@pytest.mark.parametrize("internal", [True, False])
def test_direct_address_selection_and_strict_isolation(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch, internal: bool
) -> None:
    native.config = replace(
        native.config, via_iap=False, internal_ip=internal, external_ip=not internal
    )
    monkeypatch.setattr(native.ssh, "prepare_key", lambda: "ssh-ed25519 offline-public")
    options, address = native.ssh.native_options("us-west1-a")
    assert address == ("10.0.0.7" if internal else "192.0.2.7")
    assert options[:2] == ["-F", str(native.empty_config)]
    assert "HostKeyAlias=compute.123" in options
    assert "StrictHostKeyChecking=yes" in options
    assert "BatchMode=yes" in options
    assert "IdentitiesOnly=yes" in options
    assert "PreferredAuthentications=publickey" in options
    assert "PasswordAuthentication=no" in options
    assert "KbdInteractiveAuthentication=no" in options
    assert "ProxyCommand=" not in " ".join(options)
    assert any("GlobalKnownHostsFile=" in item and "empty" in item for item in options)
    assert_private(native.known_hosts)


def test_native_shell_inherits_terminal_and_command_checks_user(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        native.ssh,
        "native_options",
        lambda _zone: (["-F", str(native.empty_config)], "192.0.2.7"),
    )
    monkeypatch.setattr(native.ssh, "executable", lambda _name: "native-ssh.exe")
    launch = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr("piccolo.providers.gcp.ssh.run_command", launch)
    native.shell("us-west1-a")
    assert launch.call_args.kwargs["capture"] is False
    assert launch.call_args.kwargs["timeout"] is None
    assert "-tt" in launch.call_args.args[0]
    assert '"$(id -un)" != researcher' in launch.call_args.args[0][-1]
    native.execute("us-west1-a", "printf result", timeout=8)
    assert "-T" in launch.call_args.args[0]
    assert launch.call_args.kwargs["timeout"] == pytest.approx(8, abs=0.2)
    assert launch.call_args.args[1].get("HOME") == os.environ.get("HOME")


def test_native_scp_retries_only_pre_authentication_rejection(
    native: GCloudConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(native.ssh, "native_options", lambda _zone: ([], "192.0.2.7"))
    monkeypatch.setattr(native.ssh, "executable", lambda _name: "native-scp.exe")
    monkeypatch.setattr("piccolo.providers.gcp.ssh.time.sleep", lambda _delay: None)
    launch = Mock(
        side_effect=[
            subprocess.CompletedProcess([], 255, "", "Permission denied (publickey)"),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
    )
    monkeypatch.setattr("piccolo.providers.gcp.ssh.run_command", launch)
    native.copy("us-west1-a", tmp_path / "source with spaces", ".piccolo/setup.upload")
    assert launch.call_count == 2
    assert launch.call_args_list[0].args[0] == launch.call_args_list[1].args[0]
    launch.reset_mock(side_effect=True)
    launch.return_value = subprocess.CompletedProcess([], 255, "", "Connection reset")
    with pytest.raises(PiccoloError, match="Connection reset"):
        native.copy("us-west1-a", tmp_path / "source", ".piccolo/setup.upload")
    assert launch.call_count == 1


def test_iap_proxy_encodes_sdk_argv_and_explicit_identity(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    native.config = replace(
        native.config, connection_impersonate="connector-sa@example.test"
    )
    monkeypatch.setattr(native.ssh, "prepare_key", lambda: "ssh-ed25519 offline-public")
    launcher = ["C:/Python with spaces/python.exe", "C:/SDK \u00e9/gcloud.py"]
    monkeypatch.setattr(native, "launcher", lambda: launcher)
    options, _address = native.ssh.native_options("us-west1-a")
    proxy = next(item for item in options if item.startswith("ProxyCommand="))
    encoded = proxy.split()[-1]
    arguments = json.loads(base64.urlsafe_b64decode(encoded))
    assert arguments[:2] == launcher
    assert "--listen-on-stdin" in arguments
    assert "--zone=us-west1-a" in arguments
    assert "--project=test-project" in arguments
    assert "--account=connector@example.test" in arguments
    assert "--impersonate-service-account=connector-sa@example.test" in arguments


@pytest.mark.parametrize("success", [True, False])
def test_native_readiness_bounds_new_key_propagation(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch, success: bool
) -> None:
    monkeypatch.setattr(native, "check_identity", lambda: None)
    monkeypatch.setattr("piccolo.providers.gcp.ssh.time.sleep", lambda _delay: None)
    denied = subprocess.CompletedProcess([], 255, "", "Permission denied (publickey)")
    results = (
        [denied, subprocess.CompletedProcess([], 0, "", "")]
        if success
        else [denied] * 4
    )
    probe = Mock(side_effect=results)
    monkeypatch.setattr(native.ssh, "native_result", probe)
    if success:
        native.ready("us-west1-a")
        assert probe.call_count == 2
    else:
        with pytest.raises(PiccoloError, match="permission failure"):
            native.ready("us-west1-a")
        assert probe.call_count == 4


def test_preparation_deadline_prevents_launch_and_restores_outer_state(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    def expired_options(_zone: str) -> tuple[list[str], str]:
        native.deadline = time.monotonic() - 1
        return [], "192.0.2.7"

    monkeypatch.setattr(native.ssh, "native_options", expired_options)
    monkeypatch.setattr(native.ssh, "executable", lambda _name: "native-ssh.exe")
    launch = Mock()
    monkeypatch.setattr("piccolo.providers.gcp.ssh.run_command", launch)
    with pytest.raises(PiccoloError, match="preparation timed out"):
        native.execute("us-west1-a", "true", timeout=2)
    assert native.deadline is None
    launch.assert_not_called()


@pytest.mark.skipif(sys.platform != "win32", reason="Native shared-key preparation")
def test_key_preparation_uses_one_lock_across_state_overrides(
    native: GCloudConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = hashlib.sha256(
        str(native.key_file.absolute()).casefold().encode()
    ).hexdigest()
    lock = tmp_path / "shared-key-locks" / "ssh-locks" / f"{key}.lock"
    with file_lock(lock):
        monkeypatch.setenv("PICCOLO_STATE_DIR", str(tmp_path / "different-state-root"))
        with pytest.raises(PiccoloError, match="environment lock"):
            native.ssh.prepare_key()
    assert native.ssh.prepare_key().startswith("ssh-rsa ")


@pytest.mark.skipif(
    sys.platform != "win32", reason="Actual native ProxyCommand parsing"
)
def test_native_iap_proxy_boundary_preserves_spaces_unicode_and_binary_stream(
    native: GCloudConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "fake SDK \u00e9.py"
    marker = tmp_path / "proxy arguments.json"
    fake.write_text(
        "# Copyright 2026 Israel Flores-Arbolay\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        "import json,os,sys\nfrom pathlib import Path\n"
        "Path(os.environ['PICCOLO_PROXY_TEST_MARKER']).write_text(json.dumps(sys.argv[1:]))\n"
        "sys.stdout.buffer.write(b'SSH-2.0-offline-proxy\\r\\n')\n"
        "sys.stdout.buffer.flush()\n",
        encoding="utf-8",
        newline="\n",
    )
    monkeypatch.setenv("PICCOLO_PROXY_TEST_MARKER", str(marker))
    alias = tmp_path / "proxy Python %literal & \u00e9"
    redirect(alias, Path(sys.prefix), directory=True)
    monkeypatch.setattr(sys, "executable", str(alias / "Scripts" / "python.exe"))
    monkeypatch.setattr(native.ssh, "prepare_key", lambda: "ssh-ed25519 offline-public")
    monkeypatch.setattr(native, "launcher", lambda: [sys.executable, str(fake)])
    options, address = native.ssh.native_options("us-west1-a")
    result = run_command(
        [native.ssh.executable("ssh"), *options, f"researcher@{address}", "true"],
        native.environment(),
        timeout=5,
    )
    assert result.returncode != 0
    assert marker.exists(), result.stderr
    arguments = json.loads(marker.read_text())
    assert arguments[:3] == ["compute", "start-iap-tunnel", "test-vm"]
    assert "--account=connector@example.test" in arguments
    assert "--listen-on-stdin" in arguments
