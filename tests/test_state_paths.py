# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_state_paths.py — Piccolo state-root policy."""

from pathlib import Path

import pytest
from platformdirs import user_state_path

from piccolo.errors import PiccoloError
from piccolo.state.paths import state_root


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
