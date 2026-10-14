# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_native_ssh.py — GCP native-session policy and offline IAP integration."""

import base64
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
from piccolo.openssh import SSHSession
from piccolo.process import run_command
from piccolo.providers.gcp.connection import GCloudConnection
from piccolo.state.journal import Journal


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
        Mock(
            return_value={
                "id": "123",
                "network_interfaces": [
                    {
                        "network_i_p": "10.0.0.7",
                        "access_configs": [{"nat_i_p": "192.0.2.7"}],
                    }
                ],
            }
        ),
        Mock(
            return_value={
                "query_value": {
                    "items": [
                        {
                            "namespace": "hostkeys",
                            "key": "ssh-ed25519",
                            "value": encoded,
                        }
                    ]
                }
            }
        ),
    )
    connection.windows = True
    connection.user_home = tmp_path / "profile with spaces \u00e9"
    connection.key_file = connection.user_home / ".ssh" / "google_compute_engine"
    monkeypatch.setattr(
        connection,
        "environment",
        lambda: {**os.environ, "CLOUDSDK_CONFIG": str(connection.sdk_directory)},
    )
    monkeypatch.setattr(connection, "before_ssh", Mock(return_value=None))
    monkeypatch.setattr(connection.ssh.authorization, "authorize", Mock())
    monkeypatch.setattr(
        "piccolo.openssh.user_state_path",
        Mock(return_value=tmp_path / "shared-key-locks"),
    )
    return connection


@pytest.mark.parametrize("internal", [True, False])
def test_direct_address_selection_and_strict_isolation(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch, internal: bool
) -> None:
    native.config = replace(
        native.config, via_iap=False, internal_ip=internal, external_ip=not internal
    )
    monkeypatch.setattr(
        native.ssh.client,
        "prepare_key",
        Mock(return_value="ssh-ed25519 offline-public"),
    )
    session = native.ssh.native_session("us-west1-a")
    options, address = native.ssh.client.options(session), session.address
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


def test_session_authorizes_selected_identity_and_resolved_key_policy(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepare = Mock(return_value="ssh-ed25519 offline-public")
    authorize = Mock()
    monkeypatch.setattr(native.ssh.client, "prepare_key", prepare)
    monkeypatch.setattr(native.ssh.authorization, "authorize", authorize)
    monkeypatch.setattr(native, "launcher", lambda: ["offline-gcloud"])
    session = native.ssh.native_session("us-west1-a")
    prepare.assert_called_once_with(native.key_file, "researcher", False)
    authorize.assert_called_once_with("us-west1-a", "123", "ssh-ed25519 offline-public")
    assert session.host_alias == "compute.123"
    assert session.known_hosts == native.known_hosts
    assert session.proxy_command is not None


def test_rejected_connection_policy_prevents_key_preparation(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    def rejected() -> dict[str, str]:
        raise PiccoloError("connection identity rejected")

    prepare = Mock()
    monkeypatch.setattr(native, "environment", rejected)
    monkeypatch.setattr(native.ssh.client, "prepare_key", prepare)
    with pytest.raises(PiccoloError, match="identity rejected"):
        native.ssh.native_session("us-west1-a")
    prepare.assert_not_called()


def test_native_transfer_rejects_path_before_authorization(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepare = Mock()
    monkeypatch.setattr(native.ssh, "native_session", prepare)
    with pytest.raises(PiccoloError, match="safe home-relative"):
        native.copy("us-west1-a", Path("source"), "../escape")
    prepare.assert_not_called()
    assert native.deadline is None


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows artifact ACLs")
def test_native_session_artifacts_remain_private_after_authorization_failure(
    native: GCloudConnection,
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(native, "launcher", Mock(return_value=["offline-gcloud"]))
    journal = Journal(config)
    journal.begin({"kind": "init", "id": "fixture-operation"})
    try:
        native.ssh.native_session("us-west1-a")
        original_key = native.key_file.read_bytes()
        original_trust = native.known_hosts.read_bytes()
        artifacts = [
            native.key_file,
            native.key_file.with_name(native.key_file.name + ".pub"),
            native.known_hosts,
            native.empty_config,
            journal.path,
        ]
        for path in artifacts:
            assert_private(path)
        assert_private(native.known_hosts.parent, directory=True)
        assert_private(Path(native.host_directory.name), directory=True)
        monkeypatch.setattr(
            native.ssh.authorization,
            "authorize",
            Mock(side_effect=PiccoloError("fixture authorization rejected")),
        )
        launch = Mock()
        monkeypatch.setattr(native.ssh.client, "command", launch)
        with pytest.raises(PiccoloError, match="authorization rejected"):
            native.execute("us-west1-a", "true")
        launch.assert_not_called()
        assert native.deadline is None
        assert native.key_file.read_bytes() == original_key
        assert native.known_hosts.read_bytes() == original_trust
        journal.update({"kind": "init", "id": "fixture-after-failure"})
        assert Journal(config).operation["id"] == "fixture-after-failure"
        for path in artifacts:
            assert_private(path)
    finally:
        native.host_directory.cleanup()
    assert not native.known_hosts.parent.exists()


def test_native_shell_inherits_terminal_and_command_checks_user(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        native.ssh,
        "native_session",
        Mock(
            return_value=SSHSession(
                "192.0.2.7",
                "researcher",
                native.key_file,
                native.known_hosts,
                "compute.123",
                native.empty_config,
            )
        ),
    )
    monkeypatch.setattr(
        native.ssh.client, "executable", Mock(return_value="native-ssh.exe")
    )
    launch = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr("piccolo.openssh.run_command", launch)
    native.shell("us-west1-a")
    assert launch.call_args.kwargs["capture"] is False
    assert launch.call_args.kwargs["timeout"] is None
    assert "-tt" in launch.call_args.args[0]
    assert '"$(id -un)" != researcher' in launch.call_args.args[0][-1]
    native.execute("us-west1-a", "printf result", timeout=8)
    assert "-T" in launch.call_args.args[0]
    assert launch.call_args.kwargs["timeout"] == pytest.approx(8, abs=0.2)
    assert launch.call_args.args[1].get("HOME") == os.environ.get("HOME")


def test_iap_proxy_encodes_sdk_argv_and_explicit_identity(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    native.config = replace(
        native.config, connection_impersonate="connector-sa@example.test"
    )
    monkeypatch.setattr(
        native.ssh.client,
        "prepare_key",
        Mock(return_value="ssh-ed25519 offline-public"),
    )
    launcher = ["C:/Python with spaces/python.exe", "C:/SDK \u00e9/gcloud.py"]
    monkeypatch.setattr(native, "launcher", lambda: launcher)
    session = native.ssh.native_session("us-west1-a")
    options = native.ssh.client.options(session)
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
    monkeypatch.setattr("piccolo.providers.gcp.ssh.time.sleep", Mock(return_value=None))
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
    def expired_options(_zone: str) -> SSHSession:
        native.deadline = time.monotonic() - 1
        return SSHSession(
            "192.0.2.7",
            "researcher",
            native.key_file,
            native.known_hosts,
            "compute.123",
            native.empty_config,
        )

    monkeypatch.setattr(native.ssh, "native_session", expired_options)
    monkeypatch.setattr(
        native.ssh.client, "executable", Mock(return_value="native-ssh.exe")
    )
    launch = Mock()
    monkeypatch.setattr("piccolo.openssh.run_command", launch)
    with pytest.raises(PiccoloError, match="preparation timed out"):
        native.execute("us-west1-a", "true", timeout=2)
    assert native.deadline is None
    launch.assert_not_called()


def test_native_readiness_allows_preparation_within_configured_deadline(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep helper preparation from exhausting a short network-probe allowance."""
    monkeypatch.setattr(native, "check_identity", Mock())
    probe = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(native.ssh, "native_result", probe)
    native.ready("us-west1-a")
    assert 40 < probe.call_args.kwargs["timeout"] <= native.config.readiness_timeout


@pytest.mark.parametrize("status", [0, 130, 42, 255])
def test_interactive_shell_accepts_ctrl_c_but_retains_session_errors(
    native: GCloudConnection, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    """Treat an interrupted final guest command as a normal interactive exit."""
    result = subprocess.CompletedProcess([], status, "", "")
    monkeypatch.setattr(native.ssh, "native_result", Mock(return_value=result))
    if status in {0, 130}:
        native.shell("us-west1-a")
    else:
        with pytest.raises(PiccoloError, match="SSH session exited"):
            native.shell("us-west1-a")


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
    monkeypatch.setattr(
        native.ssh.client,
        "prepare_key",
        Mock(return_value="ssh-ed25519 offline-public"),
    )
    monkeypatch.setattr(native, "launcher", lambda: [sys.executable, str(fake)])
    session = native.ssh.native_session("us-west1-a")
    options, address = native.ssh.client.options(session), session.address
    result = run_command(
        [
            native.ssh.client.executable("ssh"),
            *options,
            f"researcher@{address}",
            "true",
        ],
        native.environment(),
        timeout=5,
    )
    assert result.returncode != 0
    assert marker.exists(), result.stderr
    arguments = json.loads(marker.read_text())
    assert arguments[:3] == ["compute", "start-iap-tunnel", "test-vm"]
    assert "--account=connector@example.test" in arguments
    assert "--listen-on-stdin" in arguments
