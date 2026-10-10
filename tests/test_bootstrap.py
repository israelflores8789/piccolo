# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_bootstrap.py — Harmless local guest tests for one-attempt bootstrap policy."""

from pathlib import Path

import pytest
from conftest import FakeCloud, GuestConnection

from piccolo.config import Config, load
from piccolo.data import text
from piccolo.errors import PiccoloError, UncertainError
from piccolo.providers.gcp.provider import GCPProvider


@pytest.fixture
def setup_config(config_path: Path) -> Config:
    output = config_path.parent / "executions"
    (config_path.parent / "setup.sh").write_text(
        f"#!/bin/bash\nprintf executed >> '{output}'\n"
    )
    config_path.write_text(
        config_path.read_text()
        + '[bootstrap]\nscript="setup.sh"\nexecution_user="researcher"\ntimeout=10\n'
    )
    return load(config_path)


def test_stage_only_then_explicit_execution_and_never_repeat(
    setup_config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = GCPProvider(setup_config, cloud, connection)
    provider.init()
    output = setup_config.path.parent / "executions"
    assert not output.exists()
    assert provider.bootstrap(True, False)["eligible"] is True
    assert provider.bootstrap(False, False)["status"] == "completed"
    assert output.read_text() == "executed"
    with pytest.raises(PiccoloError, match="blocked"):
        provider.bootstrap(False, False)
    provider.init()
    provider.stop()
    provider.start()
    provider.move("us-east1-b")
    assert output.read_text() == "executed"
    assert provider.bootstrap(False, True)["status"] == "completed"
    with pytest.raises(PiccoloError, match="blocked"):
        provider.bootstrap(False, False)


def test_failed_script_is_not_eligible_for_retry(
    setup_config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    setup_config.bootstrap.script.write_text("#!/bin/bash\nexit 17\n")
    provider = GCPProvider(setup_config, cloud, connection)
    provider.init()
    with pytest.raises(PiccoloError, match="exit code 17"):
        provider.bootstrap(False, False)
    assert provider.bootstrap(False, True)["status"] == "failed"
    with pytest.raises(PiccoloError, match="blocked"):
        provider.bootstrap(False, False)


def test_disconnect_does_not_authorize_second_attempt(
    setup_config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = GCPProvider(setup_config, cloud, connection)
    provider.init()
    connection.launch_failure = True
    with pytest.raises(UncertainError):
        provider.bootstrap(False, False)
    assert provider.bootstrap(False, True)["status"] == "uncertain"
    connection.launch_failure = False
    with pytest.raises(PiccoloError, match="blocked"):
        GCPProvider(setup_config, cloud, connection).bootstrap(False, False)


def test_running_receipt_survives_local_disconnect(
    setup_config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = GCPProvider(setup_config, cloud, connection)
    provider.init()
    record = provider.journal.data["bootstrap"]
    record["status"] = "started"
    provider.journal.save()
    receipt_path = connection.directory / text(record, "receipt")
    receipt_path.mkdir()
    assert provider.bootstrap(False, True)["status"] == "started"
    (receipt_path / "exit-code").write_text("0\n")
    assert (
        GCPProvider(setup_config, cloud, connection).bootstrap(False, True)["status"]
        == "completed"
    )
    with pytest.raises(PiccoloError):
        provider.bootstrap(False, False)


def test_changed_script_never_executes_automatically(
    setup_config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = GCPProvider(setup_config, cloud, connection)
    provider.init()
    setup_config.bootstrap.script.write_text("echo changed\n")
    provider.init()
    with pytest.raises(PiccoloError, match="changed"):
        provider.bootstrap(False, False)
    assert not (setup_config.path.parent / "executions").exists()


def test_missing_local_history_on_existing_disk_blocks_execution(
    setup_config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = GCPProvider(setup_config, cloud, connection)
    provider.init()
    provider.journal.path.unlink()
    unknown = GCPProvider(setup_config, cloud, connection)
    unknown.init()
    assert unknown.bootstrap(True, False)["eligible"] is False
    with pytest.raises(PiccoloError, match="blocked"):
        unknown.bootstrap(False, False)


def test_staging_failure_resumes_only_copy(
    setup_config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    connection.readiness_failure = True
    provider = GCPProvider(setup_config, cloud, connection)
    with pytest.raises(PiccoloError):
        provider.init()
    assert provider.journal.operation
    connection.readiness_failure = False
    provider.resume()
    assert provider.bootstrap(True, False)["eligible"] is True
    assert not (setup_config.path.parent / "executions").exists()
