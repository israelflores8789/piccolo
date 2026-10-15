# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_bootstrap_artifacts.py — Private staging and artifact validation."""

import sys
from pathlib import Path

import pytest
from conftest import FakeCloud, GuestConnection

from piccolo.config import Config, load
from piccolo.data import document, text
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.provider import GCPProvider


@pytest.fixture
def bootstrap_config(config_path: Path) -> Config:
    (config_path.parent / "setup.sh").write_text("#!/bin/bash\nexit 0\n")
    config_path.write_text(
        config_path.read_text()
        + '[bootstrap]\nscript="setup.sh"\nexecution_user="researcher"\ntimeout=5\n'
    )
    return load(config_path)


def test_failed_guest_command_reports_expanded_guard(
    connection: GuestConnection,
) -> None:
    """Expose silent shell checks with their expanded operands and exit status."""
    with pytest.raises(PiccoloError) as failure:
        connection.execute(
            "us-west1-a", 'set -eu; expected=piccolo; test "$expected" = other'
        )
    detail = str(failure.value)
    assert "exit 1" in detail
    assert "test piccolo = other" in detail


@pytest.mark.parametrize(
    "component", [".piccolo", ".piccolo/bootstrap", ".piccolo/bootstrap/setup.sh"]
)
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Linux guest symlink semantics require a POSIX test filesystem",
)
def test_staging_rejects_guest_symlinks(
    bootstrap_config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    tmp_path: Path,
    component: str,
) -> None:
    external = tmp_path / "outside"
    external.mkdir()
    target = connection.directory / component
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(external, target_is_directory=True)
    with pytest.raises(PiccoloError):
        GCPProvider(bootstrap_config, cloud, connection).init()
    assert connection.copies == 0
    assert not list(external.iterdir())


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Linux guest modes require POSIX; native upload ACLs have separate coverage",
)
def test_script_and_runner_are_private_before_copy(
    bootstrap_config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copy = connection.copy
    modes: list[int] = []

    def private_copy(zone: str, source: Path, destination: str) -> None:
        target = connection.directory / destination
        modes.append(target.stat().st_mode & 0o777)
        assert target.parent.stat().st_mode & 0o777 == 0o700
        assert source.stat().st_mode & 0o777 == 0o600
        copy(zone, source, destination)

    monkeypatch.setattr(connection, "copy", private_copy)
    provider = GCPProvider(bootstrap_config, cloud, connection)
    provider.init()
    assert provider.bootstrap(False, False)["status"] == "completed"
    assert modes == [0o600, 0o600]


def test_runner_digest_tampering_blocks_launch(
    bootstrap_config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = GCPProvider(bootstrap_config, cloud, connection)
    provider.init()
    copy = connection.copy

    def tamper(zone: str, source: Path, destination: str) -> None:
        copy(zone, source, destination)
        if destination.endswith(".runner.sh"):
            (connection.directory / destination).write_text("exit 0\n")

    monkeypatch.setattr(connection, "copy", tamper)
    with pytest.raises(PiccoloError, match="digest mismatch"):
        provider.bootstrap(False, False)
    assert text(document(provider.journal.data["bootstrap"]), "status") == "staged"


def test_staging_refuses_disk_replacement_during_readiness(
    bootstrap_config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def replace_disk(_zone: str) -> None:
        for (kind, _, _), resource in cloud.resources.items():
            if kind == "disk":
                resource["id"] = "replaced"

    monkeypatch.setattr(connection, "ready", replace_disk)
    provider = GCPProvider(bootstrap_config, cloud, connection)
    with pytest.raises(PiccoloError, match="boot disk differs"):
        provider.init()
    assert connection.copies == 0
    assert text(document(provider.journal.data["bootstrap"]), "status") == "staging"


@pytest.mark.parametrize(
    "path",
    [
        ".piccolo/bootstrap/attempt-123",
        ".piccolo/bootstrap/attempt-123/script",
        ".piccolo/bootstrap/file.runner.sh",
        ".piccolo/bootstrap/file.upload-test",
        "directory/../script",
        "directory//script",
        "directory/./script",
    ],
)
def test_reserved_remote_paths_are_rejected(config_path: Path, path: str) -> None:
    (config_path.parent / "script.sh").write_text("exit 0")
    config_path.write_text(
        config_path.read_text()
        + f'[bootstrap]\nscript="script.sh"\nremote_path="{path}"\n'
        'execution_user="researcher"\n'
    )
    with pytest.raises(PiccoloError, match=r"bootstrap\.remote_path"):
        load(config_path)
