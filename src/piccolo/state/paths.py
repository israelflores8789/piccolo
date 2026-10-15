# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""paths.py — Resolve Piccolo state paths without creating them."""

import os
from pathlib import Path

from platformdirs import user_state_path

from piccolo.errors import PiccoloError


def state_root() -> Path:
    """Resolve the explicit state override or the platform's state directory."""
    override = os.environ.get("PICCOLO_STATE_DIR")
    if override is not None:
        if not override:
            raise PiccoloError("PICCOLO_STATE_DIR must not be empty")
        return Path(override)
    return user_state_path("piccolo", appauthor=False, ensure_exists=False)
