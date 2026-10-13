# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_paths.py — Platform paths and SDK isolation."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from platformdirs import user_state_path

from piccolo.config import Config
from piccolo.errors import PiccoloError
from piccolo.paths import cloud_sdk_directory, state_root
from piccolo.providers.gcp.auth import adc_path
from piccolo.providers.gcp.connection import GCloudConnection


def test_platform_state_default_does_not_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PICCOLO_STATE_DIR")
    assert state_root() == user_state_path(
        "piccolo", appauthor=False, ensure_exists=False
    )


def test_override_and_empty_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PICCOLO_STATE_DIR", str(tmp_path / "explicit"))
    assert state_root() == tmp_path / "explicit"
    assert not state_root().exists()
    monkeypatch.setenv("PICCOLO_STATE_DIR", "")
    with pytest.raises(PiccoloError, match="must not be empty"):
        state_root()


@pytest.mark.parametrize("override", [None, "", "explicit SDK with spaces"])
def test_adc_and_launch_share_sdk_location(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: str | None,
) -> None:
    if override is None:
        monkeypatch.delenv("CLOUDSDK_CONFIG", raising=False)
    else:
        monkeypatch.setenv(
            "CLOUDSDK_CONFIG", "" if not override else str(tmp_path / override)
        )
    connection = GCloudConnection(config.gcp)
    expected = cloud_sdk_directory()
    assert adc_path() == expected / "application_default_credentials.json"
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(tmp_path / "changed-after-resolution"))
    invoke = Mock(return_value=subprocess.CompletedProcess([], 0, "{}", ""))
    monkeypatch.setattr(connection, "invoke", invoke)
    assert connection.environment()["CLOUDSDK_CONFIG"] == str(expected)
    assert invoke.call_args.args[1]["CLOUDSDK_CONFIG"] == str(expected)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows SDK default")
def test_missing_appdata_does_not_choose_drive_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CLOUDSDK_CONFIG", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    with pytest.raises(PiccoloError, match="APPDATA"):
        cloud_sdk_directory()
