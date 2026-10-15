# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_spinner.py — Spinner lifecycle and terminal handoff integration."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner
from yaspin.constants import SPINNER_ATTRS
from yaspin.spinners import Spinners

from piccolo.cli import app
from piccolo.config import load, spinner
from piccolo.data import Document
from piccolo.errors import PiccoloError


@pytest.mark.parametrize("command", ["connect", "tunnel", "start", "status", "plan"])
@pytest.mark.parametrize("fail", [False, True])
def test_command_spinner_lifetime(
    config_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, fail: bool
) -> None:
    """Stop progress before foreground IO and also after preparation failures."""
    config_path.write_text('spinner = "clock"\n' + config_path.read_text())
    events: list[str] = []
    stream = MagicMock()
    stream.isatty.return_value = True
    monkeypatch.setattr(spinner, "sys", SimpleNamespace(stderr=stream))
    renderer = MagicMock()
    renderer.__enter__.side_effect = lambda: events.append("enter")
    renderer.__exit__.side_effect = lambda *_: events.append("exit")
    factory = MagicMock(return_value=renderer)
    monkeypatch.setattr(spinner, "yaspin", factory)
    provider = MagicMock()
    monkeypatch.setattr("piccolo.cli.create", lambda _: provider)

    def prepare() -> str | Document:
        assert events == ["enter"]
        if fail:
            raise PiccoloError("Preparation failed")
        if command == "tunnel":
            return {"zone": "projects/test-project/zones/us-west1-a"}
        if command in {"status", "plan"}:
            return {"state": "ready"}
        return "us-west1-a"

    def ready(zone: str) -> None:
        assert zone == "us-west1-a"
        assert events == ["enter"]

    def foreground(zone: str) -> None:
        assert zone == "us-west1-a"
        assert events == ["enter", "exit"]

    method = {
        "connect": "start",
        "tunnel": "active",
        "start": "start",
        "status": "inspect",
        "plan": "plan",
    }[command]
    provider.capabilities = {"start"}
    getattr(provider, method).side_effect = prepare
    provider.connection.ready.side_effect = ready
    provider.connection.shell.side_effect = foreground
    provider.connection.tunnel.side_effect = foreground

    result = CliRunner().invoke(app, [command, "-c", str(config_path)])
    assert result.exit_code == (1 if fail else 0), result.output
    assert events == ["enter", "exit"]
    factory.assert_called_once_with(
        Spinners.clock, text=f"Piccolo {command}", stream=stream
    )
    if not fail and command == "connect":
        provider.connection.ready.assert_called_once_with("us-west1-a")
        provider.connection.shell.assert_called_once_with("us-west1-a")
    elif not fail and command == "tunnel":
        provider.connection.tunnel.assert_called_once_with("us-west1-a")
    else:
        provider.connection.shell.assert_not_called()
        provider.connection.tunnel.assert_not_called()


def test_redirected_output_does_not_create_spinner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Avoid spinner animation when stderr is redirected."""
    stream = MagicMock()
    stream.isatty.return_value = False
    monkeypatch.setattr(spinner, "sys", SimpleNamespace(stderr=stream))
    factory = MagicMock()
    monkeypatch.setattr(spinner, "yaspin", factory)
    with spinner.loading_spinner("clock", "connect") as progress:
        assert progress is None
    factory.assert_not_called()


def test_spinner_config_and_schema_choices(config_path: Path) -> None:
    """Keep editor choices aligned with the installed spinner catalog."""
    assert load(config_path).spinner == "dots"
    original = config_path.read_text()
    config_path.write_text('spinner = "dots8Bit"\n' + original)
    assert load(config_path).spinner == "dots8Bit"
    config_path.write_text('spinner = "not-a-spinner"\n' + original)
    with pytest.raises(PiccoloError, match="spinner: unsupported"):
        load(config_path)
    schema_path = Path(__file__).resolve().parents[1] / "config.schema.json"
    schema = json.loads(schema_path.read_text())
    assert set(schema["properties"]["spinner"]["enum"]) == set(SPINNER_ATTRS)
