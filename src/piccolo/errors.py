# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""errors.py — User-facing failures with conservative mutation semantics."""

from piccolo.privacy import sanitize_text


class PiccoloError(Exception):
    """Report a configuration, infrastructure, or safety failure."""

    def __init__(self, message: str) -> None:
        """Sanitize failures before consoles, journals, or tracebacks render them."""
        super().__init__(sanitize_text(message))


class CapacityError(PiccoloError):
    """Report confirmed, terminal Compute zone capacity exhaustion."""


class UncertainError(PiccoloError):
    """Block further mutations until a submitted operation is reconciled."""
