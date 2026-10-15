# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""spinner.py — Spinner validation and operation loading messages."""

from __future__ import annotations

import sys
from contextlib import AbstractContextManager, nullcontext
from typing import cast

from yaspin import Spinner, yaspin
from yaspin.constants import SPINNER_ATTRS
from yaspin.core import Yaspin
from yaspin.spinners import Spinners

from piccolo.errors import PiccoloError

DEFAULT_SPINNER = "dots"


def validate_spinner(name: str) -> str:
    """Validate a configured built-in yaspin spinner name."""
    if name not in SPINNER_ATTRS:
        raise PiccoloError(f"spinner: unsupported yaspin spinner {name!r}")
    return name


def loading_spinner(name: str, action: str) -> AbstractContextManager[Yaspin | None]:
    """Create operation progress, disabled when stderr is redirected.

    Args:
        name: Built-in yaspin spinner name.
        action: Piccolo operation being performed.
    """
    if not sys.stderr.isatty():
        return nullcontext()
    selected = cast(Spinner, getattr(Spinners, validate_spinner(name)))
    return yaspin(selected, text=f"Piccolo {action}", stream=sys.stderr)
