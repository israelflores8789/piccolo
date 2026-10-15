# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_windows_connection.py — Offline native gcloud helper containment and IO."""

import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from piccolo.config import Config
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.connection import AUTH_OVERRIDES, GCloudConnection

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Native Windows jobs")


def assert_stopped(pid: int) -> None:
    """Check a fixture process has exited, cleaning it even on a failed assertion."""
    import pywintypes
    import win32api
    import win32con
    import win32event

    try:
        handle = win32api.OpenProcess(
            win32con.SYNCHRONIZE | win32con.PROCESS_TERMINATE, False, pid
        )
    except pywintypes.error as exc:
        assert exc.winerror == 87
        return
    try:
        stopped = (
            win32event.WaitForSingleObject(handle, 2000) == win32event.WAIT_OBJECT_0
        )
        if not stopped:
            win32api.TerminateProcess(handle, 1)
            win32event.WaitForSingleObject(handle, 2000)
        assert stopped, "Fixture descendant survived its connection helper"
    finally:
        win32api.CloseHandle(handle)


def sleeper_launcher(pid_path: Path) -> list[str]:
    """Start a short-lived descendant that inherits both captured output handles."""
    code = (
        "import subprocess,sys,time; from pathlib import Path; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(5)']); "
        "marker=Path(sys.argv[1]); "
        "marker.with_suffix('.tmp').write_text(str(child.pid)); "
        "marker.with_suffix('.tmp').replace(marker); time.sleep(10)"
    )
    return [sys.executable, "-c", code, str(pid_path)]


@pytest.mark.parametrize(
    "arguments,use_flags",
    [
        (["config", "list", "--format=json"], False),
        (["auth", "list"], True),
        (["auth", "print-access-token"], True),
        (["compute", "os-login", "describe-profile"], True),
        (["compute", "os-login", "ssh-keys", "add"], True),
    ],
)
@pytest.mark.parametrize("capture", [True, False])
def test_helper_timeout_terminates_descendant(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    use_flags: bool,
    capture: bool,
) -> None:
    connection = GCloudConnection(config.gcp)
    pid_path = tmp_path / "descendant.pid"
    monkeypatch.setattr(
        connection, "launcher", Mock(return_value=sleeper_launcher(pid_path))
    )
    started = time.monotonic()
    with pytest.raises(PiccoloError, match="timed out"):
        connection.invoke(
            arguments,
            os.environ.copy(),
            timeout=1,
            capture=capture,
            use_flags=use_flags,
        )
    elapsed = time.monotonic() - started
    assert pid_path.exists()
    assert_stopped(int(pid_path.read_text()))
    assert elapsed < 4


@pytest.mark.parametrize("capture", [True, False])
def test_helper_cancellation_terminates_descendant(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capture: bool,
) -> None:
    connection = GCloudConnection(config.gcp)
    pid_path = tmp_path / "cancelled-descendant.pid"
    monkeypatch.setattr(
        connection, "launcher", Mock(return_value=sleeper_launcher(pid_path))
    )

    def interrupted(
        _process: subprocess.Popen[bytes], *_args: object, **_kwargs: object
    ) -> tuple[bytes, bytes]:
        deadline = time.monotonic() + 4
        while not pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pid_path.exists()
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess.Popen, "communicate", interrupted)
    with pytest.raises(KeyboardInterrupt):
        connection.invoke(
            ["auth", "print-access-token"], os.environ.copy(), capture=capture
        )
    assert_stopped(int(pid_path.read_text()))


@pytest.mark.parametrize("use_flags", [True, False])
def test_helper_preserves_identity_environment_output_and_remaining_deadline(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
    use_flags: bool,
) -> None:
    connection = GCloudConnection(
        replace(
            config.gcp,
            connection_account="connector@example.test",
            connection_impersonate="connector-sa@example.test",
        )
    )
    code = (
        "import json,os,sys; "
        "print(json.dumps({'arguments':sys.argv[1:],"
        "'marker':os.environ['PICCOLO_TEST_MARKER']})); "
        "print('fixture error',file=sys.stderr); raise SystemExit(7)"
    )
    monkeypatch.setattr(
        connection, "launcher", Mock(return_value=[sys.executable, "-c", code])
    )
    environment = {**os.environ, "PICCOLO_TEST_MARKER": "two words \u00e9 % &"}
    arguments = ["auth", "list", "--fixture=two words \u00e9 % &"]
    result = connection.invoke(arguments, environment, timeout=5, use_flags=use_flags)
    output = json.loads(result.stdout)
    assert output["arguments"] == [
        *arguments,
        *(connection.flags() if use_flags else []),
    ]
    assert output["marker"] == environment["PICCOLO_TEST_MARKER"]
    assert result.returncode == 7
    assert result.stderr.strip() == "fixture error"

    def delayed_launcher() -> list[str]:
        time.sleep(0.1)
        return [sys.executable, "-c", "import time; time.sleep(10)"]

    monkeypatch.setattr(connection, "launcher", delayed_launcher)
    connection.deadline = time.monotonic() + 0.3
    started = time.monotonic()
    with pytest.raises(PiccoloError, match="timed out"):
        connection.invoke(["auth", "list"], environment, timeout=None)
    assert time.monotonic() - started < 2


def test_foreground_helper_preserves_exit_without_capture(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = GCloudConnection(config.gcp)
    monkeypatch.setattr(
        connection,
        "launcher",
        Mock(
            return_value=[
                sys.executable,
                "-c",
                "raise SystemExit(7)",
            ]
        ),
    )
    result = connection.invoke(["auth", "list"], os.environ.copy(), capture=False)
    assert result.returncode == 7
    assert result.stdout == result.stderr == ""


@pytest.mark.parametrize("variable", AUTH_OVERRIDES)
def test_native_helper_rejects_inherited_credentials_before_launch(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
) -> None:
    connection = GCloudConnection(config.gcp)
    launch = Mock()
    monkeypatch.setattr(connection, "invoke", launch)
    monkeypatch.setenv(variable, "fixture-credential-value")
    with pytest.raises(PiccoloError, match=variable) as caught:
        connection.run(["auth", "print-access-token"])
    assert "fixture-credential-value" not in str(caught.value)
    launch.assert_not_called()


@pytest.mark.parametrize(
    "property_name",
    ["access_token_file", "credential_file_override", "impersonate_service_account"],
)
def test_native_helper_rejects_persisted_credentials_before_token_acquisition(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
    property_name: str,
) -> None:
    connection = GCloudConnection(config.gcp)
    for variable in AUTH_OVERRIDES:
        monkeypatch.delenv(variable, raising=False)
    response = json.dumps({"auth": {property_name: "fixture-credential-value"}})
    monkeypatch.setattr(
        connection,
        "launcher",
        Mock(
            return_value=[
                sys.executable,
                "-c",
                f"print({response!r})",
            ]
        ),
    )
    invoke = Mock(wraps=connection.invoke)
    monkeypatch.setattr(connection, "invoke", invoke)
    with pytest.raises(PiccoloError, match=property_name) as caught:
        connection.run(["auth", "print-access-token"])
    assert "fixture-credential-value" not in str(caught.value)
    invoke.assert_called_once()
    assert invoke.call_args.args[0] == ["config", "list", "--format=json"]
