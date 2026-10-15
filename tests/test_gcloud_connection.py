# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcloud_connection.py — Host trust, transfers, and prompt forwarding."""

import base64
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from google.api_core import exceptions
from google.auth.credentials import AnonymousCredentials
from google.cloud import compute_v1
from platform_support import guest_bash

from piccolo.config import Config
from piccolo.data import Document, document, objects
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.connection import GCloudConnection
from piccolo.providers.gcp.resources import SDKCloud


def test_host_enrollment_uses_authenticated_instance_keys(
    config: Config,
) -> None:
    algorithm = b"ssh-ed25519"
    encoded = base64.b64encode(
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + (32).to_bytes(4, "big")
        + b"k" * 32
    ).decode()
    calls: list[str] = []

    def response(zone: str) -> Document:
        calls.append(zone)
        return {
            "query_value": {
                "items": [
                    {"namespace": "hostkeys", "key": "ssh-ed25519", "value": encoded}
                ]
            }
        }

    connection = GCloudConnection(config.gcp, lambda _zone: {"id": "123"}, response)
    options = connection.host_options("us-west1-a", "scp-flag")
    assert "--strict-host-key-checking=yes" in options
    assert "--ssh-key-expire-after=24h" in options
    assert "--scp-flag=-oHostKeyAlias=compute.123" in options
    assert calls == ["us-west1-a"]
    path = connection.host_files["us-west1-a"][1]
    assert encoded in path.read_text()
    from platform_support import assert_private

    assert_private(path)


@pytest.mark.parametrize("changed", [False, True])
def test_host_enrollment_refuses_unknown_or_replaced_vm(
    config: Config, monkeypatch: pytest.MonkeyPatch, changed: bool
) -> None:
    identity = Mock(side_effect=[{"id": "123"}, {"id": "456"}])
    connection = GCloudConnection(config.gcp, identity)
    algorithm = b"ssh-ed25519"
    key = base64.b64encode(
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + (32).to_bytes(4, "big")
        + b"k" * 32
    ).decode()
    entries = (
        [{"namespace": "hostkeys", "key": "ssh-ed25519", "value": key}]
        if changed
        else []
    )
    monkeypatch.setattr(
        connection, "host_keys", lambda _zone: {"query_value": {"items": entries}}
    )
    with pytest.raises(
        PiccoloError, match=r"Instance changed|No trusted GCP host keys"
    ):
        connection.host_options("us-west1-a", "ssh-flag")


def test_passphrase_mode_forwards_prompts_and_preserves_output(
    config: Config, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    connection = GCloudConnection(replace(config.gcp, require_passphrase=True))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    monkeypatch.setattr(connection, "launcher", lambda: ["ignored"])
    shell = guest_bash()
    real_popen = subprocess.Popen

    def local_process(args: list[str], **kwargs: object) -> subprocess.Popen[str]:
        command = next(
            argument.removeprefix("--command=")
            for argument in args
            if argument.startswith("--command=")
        )
        assert "--quiet" not in args
        assert "stdin" not in kwargs and kwargs.get("stderr") is None
        return real_popen(
            [shell, "-x", "-c", "printf 'gcloud prompt\\n'; " + command], **kwargs
        )

    monkeypatch.setattr(subprocess, "Popen", local_process)
    result = connection.interactive_invoke(
        ["compute", "ssh", "test-vm", "--command=printf 123"],
        dict(os.environ),
        timeout=10,
    )
    captured = capfd.readouterr()
    assert result.returncode == 0 and result.stdout == "123", (
        f"{result!r}\nShell: {shell}\nForwarded stdout:\n{captured.out}\n"
        f"Child stderr (Bash trace):\n{captured.err}"
    )
    assert "gcloud prompt" in captured.out


def test_scp_uses_isolated_host_trust_and_normal_gcloud_key_path(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    algorithm = b"ssh-ed25519"
    value = base64.b64encode(
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + (32).to_bytes(4, "big")
        + b"k" * 32
    ).decode()
    connection = GCloudConnection(
        config.gcp,
        lambda _zone: {"id": "123"},
        lambda _zone: {
            "query_value": {
                "items": [
                    {"namespace": "hostkeys", "key": "ssh-ed25519", "value": value}
                ]
            }
        },
    )
    monkeypatch.setattr(
        connection,
        "environment",
        lambda: {"HOME": "/original", "CLOUDSDK_CONFIG": "/original/gcloud"},
    )
    monkeypatch.setattr(connection, "launcher", lambda: ["gcloud"])
    connection.identity_checked = True
    invoke = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(subprocess, "run", invoke)
    source = tmp_path / "script"
    source.write_text("exit 0")
    connection.copy("us-west1-a", source, ".piccolo/setup.upload")
    args = invoke.call_args.args[0]
    assert "--strict-host-key-checking=yes" in args
    assert "--ssh-key-expire-after=24h" in args
    assert (
        f"--ssh-key-file={connection.user_home / '.ssh' / 'google_compute_engine'}"
        in args
    )
    assert "--scp-flag=-oBatchMode=yes" in args
    assert "--scp-flag=-Fnone" in args
    environment = invoke.call_args.kwargs["env"]
    assert environment["HOME"] == connection.host_directory.name
    assert environment["CLOUDSDK_CONFIG"] == str(connection.sdk_directory)
    assert (
        connection.known_hosts
        == Path(environment["HOME"]) / ".ssh" / "google_compute_known_hosts"
    )


def test_host_publication_is_polled_without_accepting_unknown_keys(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    algorithm = b"ssh-ed25519"
    key = base64.b64encode(
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + (32).to_bytes(4, "big")
        + b"k" * 32
    ).decode()
    host_keys = Mock(
        side_effect=[
            {},
            {
                "query_value": {
                    "items": [
                        {"namespace": "hostkeys", "key": "ssh-ed25519", "value": key}
                    ]
                }
            },
        ]
    )
    connection = GCloudConnection(config.gcp, lambda _zone: {"id": "123"}, host_keys)
    monkeypatch.setattr(connection, "check_identity", lambda: None)
    run = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(connection, "run", run)
    monkeypatch.setattr("piccolo.providers.gcp.ssh.time.sleep", lambda _seconds: None)
    connection.ready("us-west1-a")
    assert host_keys.call_count == 2
    run.assert_called_once()
    assert "--strict-host-key-checking=yes" in run.call_args.args[0]


def test_compute_host_key_read_uses_api_and_distinguishes_permission_denial(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients = Clients(AnonymousCredentials())
    attributes = compute_v1.GuestAttributes(
        query_value=compute_v1.GuestAttributesValue(
            items=[
                compute_v1.GuestAttributesEntry(
                    namespace="hostkeys", key="ssh-ed25519", value="opaque"
                )
            ]
        )
    )
    read = Mock(return_value=attributes)
    monkeypatch.setattr(clients.instances, "get_guest_attributes", read)
    cloud = SDKCloud(config, clients)
    assert (
        objects(document(cloud.host_keys("us-west1-a")["query_value"]), "items")[0][
            "value"
        ]
        == "opaque"
    )
    assert read.call_args.kwargs["request"].query_path == "hostkeys/"
    read.side_effect = exceptions.NotFound("not published")
    assert cloud.host_keys("us-west1-a") == {}
    read.side_effect = exceptions.Forbidden("denied")
    with pytest.raises(PiccoloError, match=r"GCP:roles/compute\.viewer"):
        cloud.host_keys("us-west1-a")


def test_ssh_user_mismatch_stops_readiness_immediately(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = GCloudConnection(config.gcp)
    monkeypatch.setattr(connection, "check_identity", lambda: None)
    monkeypatch.setattr(
        connection,
        "host_options",
        lambda _zone, _flag: ["--strict-host-key-checking=yes"],
    )
    run = Mock(
        return_value=subprocess.CompletedProcess(
            [], 65, "", "Piccolo SSH user mismatch"
        )
    )
    monkeypatch.setattr(connection, "run", run)
    with pytest.raises(PiccoloError, match="SSH user mismatch"):
        connection.ready("us-west1-a")
    run.assert_called_once()
    remote = next(
        item for item in run.call_args.args[0] if item.startswith("--command=")
    )
    assert '"$(id -un)" != researcher' in remote


def test_interactive_timeout_returns_with_descendant_stdout_open(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = GCloudConnection(replace(config.gcp, require_passphrase=True))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    monkeypatch.setattr(connection, "launcher", lambda: ["ignored"])
    real_popen = subprocess.Popen

    def local_process(_args: list[str], **kwargs: object) -> subprocess.Popen[str]:
        code = (
            "import subprocess,sys,time; subprocess.Popen([sys.executable, "
            "'-c', 'import time; time.sleep(0.5)']); time.sleep(10)"
        )
        return real_popen([sys.executable, "-c", code], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", local_process)
    before = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        connection.interactive_invoke(
            ["compute", "ssh", "--command=true"], dict(os.environ), timeout=0.1
        )
    assert time.monotonic() - before < 0.4
