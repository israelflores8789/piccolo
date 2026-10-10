# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_connection.py — Transport identity, retries, and subprocess construction."""

import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from piccolo.config import Config
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.connection import GCloudConnection


def test_connection_uses_configured_user_project_and_iap(config: Config) -> None:
    connection = GCloudConnection(config.gcp)
    args = connection.ssh_arguments("us-west1-a", "true")
    assert "researcher@test-vm" in args
    assert "--tunnel-through-iap" in args
    assert "--ssh-flag=-oBatchMode=yes" in args
    assert "--project=test-project" in connection.flags()


def test_shell_is_foreground_and_no_local_shell_interpolation(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = GCloudConnection(config.gcp)
    monkeypatch.setattr(connection, "executable", lambda: "/sdk with spaces/gcloud")
    mocked = Mock(return_value=subprocess.CompletedProcess(["gcloud"], 0, "", ""))
    monkeypatch.setattr(subprocess, "run", mocked)
    monkeypatch.setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "unrelated-key.json")
    connection.shell("us-west1-a")
    arguments = mocked.call_args
    assert arguments.args[0][0] == "/sdk with spaces/gcloud"
    assert arguments.kwargs["shell"] is False
    assert arguments.kwargs["capture_output"] is False
    assert arguments.kwargs["timeout"] is None
    assert "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE" not in arguments.kwargs["env"]


def test_readiness_retries_then_succeeds(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = GCloudConnection(config.gcp)
    monkeypatch.setattr(connection, "check_identity", lambda: None)
    monkeypatch.setattr(
        "piccolo.providers.gcp.connection.time.sleep", lambda _delay: None
    )
    mocked = Mock(
        side_effect=[
            subprocess.CompletedProcess([], 255, "", "Connection refused"),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
    )
    monkeypatch.setattr(connection, "run", mocked)
    connection.ready("us-west1-a")
    assert mocked.call_count == 2


def test_permission_failure_is_not_retried(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = GCloudConnection(config.gcp)
    monkeypatch.setattr(connection, "check_identity", lambda: None)
    mocked = Mock(
        return_value=subprocess.CompletedProcess([], 255, "", "Permission denied")
    )
    monkeypatch.setattr(connection, "run", mocked)
    with pytest.raises(PiccoloError, match="permission"):
        connection.ready("us-west1-a")
    assert mocked.call_count == 1


def test_sdk_impersonation_requires_explicit_connection_identity(
    config: Config,
) -> None:
    gcp = replace(
        config.gcp,
        auth=replace(
            config.gcp.auth,
            impersonate_service_account="provisioner@test-project.iam.gserviceaccount.com",
        ),
    )
    with pytest.raises(PiccoloError, match="explicitly"):
        GCloudConnection(gcp).check_identity()


def test_windows_launcher_avoids_command_shim_interpolation(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdk = tmp_path / "sdk with spaces"
    (sdk / "bin").mkdir(parents=True)
    (sdk / "lib").mkdir()
    script = sdk / "lib" / "gcloud.py"
    script.write_text("pass\n")
    connection = GCloudConnection(config.gcp)
    connection.windows = True
    monkeypatch.delenv("CLOUDSDK_PYTHON", raising=False)
    monkeypatch.setattr(
        connection, "executable", lambda: str(sdk / "bin" / "gcloud.cmd")
    )
    assert connection.launcher() == [sys.executable, str(script)]
