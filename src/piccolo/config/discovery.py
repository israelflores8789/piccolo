# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""discovery.py — Predictable configuration selection without parent searches."""

from pathlib import Path

from piccolo.errors import PiccoloError


def discover(path: Path | None = None) -> Path:
    """Resolve an explicit path or piccolo.toml in the current directory."""
    selected = (path if path is not None else Path.cwd() / "piccolo.toml").resolve()
    if not selected.is_file():
        raise PiccoloError(f"Configuration not found: {selected}; use --config PATH")
    return selected
