# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_config.py — Strict schema, discovery, and CLI option contracts."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from piccolo.cli import app
from piccolo.config import load
from piccolo.errors import PiccoloError


def test_current_directory_only(
    config_path: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(config_path.parent)
    assert load().path == config_path
    child = tmp_path / "child"
    child.mkdir()
    monkeypatch.chdir(child)
    with pytest.raises(PiccoloError, match="Configuration not found"):
        load()


def test_explicit_missing_never_falls_back(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(config_path.parent)
    with pytest.raises(PiccoloError):
        load(Path("missing.toml"))


@pytest.mark.parametrize(
    "snippet,field",
    [
        ("[gcp.extra]\nfoo = 1\n", "gcp.extra"),
        ("[gcp.iap]\nports = [true]\n", "gcp.iap.ports"),
        ('[gcp.auth]\nmode = "file"\n', "gcp.auth"),
        ('[gcp.iap]\nsource_ranges = ["invalid"]\n', "gcp.iap.source_ranges"),
        (
            '[bootstrap]\nscript = "missing.sh"\nexecution_user="researcher"\n',
            "bootstrap.script",
        ),
    ],
)
def test_invalid_fields(config_path: Path, snippet: str, field: str) -> None:
    config_path.write_text(config_path.read_text() + snippet)
    with pytest.raises(PiccoloError, match=field):
        load(config_path)


def test_relative_files_and_identity(config_path: Path) -> None:
    script = config_path.parent / "setup.sh"
    script.write_text("echo harmless\n")
    config_path.write_text(
        config_path.read_text()
        + '[bootstrap]\nscript="setup.sh"\nexecution_user="researcher"\n'
    )
    config = load(config_path)
    assert config.bootstrap is not None
    assert config.bootstrap.script == script
    config_path.write_text(
        config_path.read_text().replace(
            'execution_user="researcher"', 'execution_user="root"'
        )
    )
    with pytest.raises(PiccoloError, match="execution_user"):
        load(config_path)


@pytest.mark.parametrize("global_option", [True, False])
def test_config_option_both_positions(config_path: Path, global_option: bool) -> None:
    arguments = (
        ["-c", str(config_path), "validate"]
        if global_option
        else ["validate", "-c", str(config_path)]
    )
    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == 0, result.output
    assert "Configuration valid" in result.output


def test_conflicting_options(config_path: Path) -> None:
    result = CliRunner().invoke(
        app, ["-c", str(config_path), "validate", "-c", "other.toml"]
    )
    assert result.exit_code == 1
    assert "Conflicting" in result.output
