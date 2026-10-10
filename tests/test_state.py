# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_state.py — Atomic state and independent-process lock behavior."""

import os
import subprocess
import sys

import pytest

from piccolo.config import Config
from piccolo.errors import PiccoloError
from piccolo.state.journal import Journal
from piccolo.state.lock import environment_lock


def test_state_round_trip_and_history(config: Config) -> None:
    journal = Journal(config)
    journal.begin({"kind": "move", "id": "test-operation"})
    assert Journal(config).operation["id"] == "test-operation"
    with pytest.raises(PiccoloError, match="unresolved"):
        journal.begin({"kind": "init"})
    journal.finish()
    restored = Journal(config)
    assert not restored.operation
    assert restored.data["history"][0]["id"] == "test-operation"


def test_lock_blocks_other_process_and_releases(config: Config) -> None:
    command = [
        sys.executable,
        "-c",
        "from pathlib import Path\n"
        "from piccolo.config import load\n"
        "from piccolo.state.lock import environment_lock\n"
        "import sys\n"
        "with environment_lock(load(Path(sys.argv[1]))):\n"
        " print('locked')",
        str(config.path),
    ]
    with environment_lock(config):
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, env=os.environ.copy()
        )
        assert result.returncode != 0
        assert "environment lock" in result.stderr
    result = subprocess.run(
        command, capture_output=True, text=True, check=False, env=os.environ.copy()
    )
    assert result.returncode == 0
