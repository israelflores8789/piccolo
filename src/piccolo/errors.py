# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""errors.py — User-facing failures with conservative mutation semantics."""


class PiccoloError(Exception):
    """Report a configuration, infrastructure, or safety failure."""


class CapacityError(PiccoloError):
    """Report confirmed, terminal Compute zone capacity exhaustion."""


class UncertainError(PiccoloError):
    """Block further mutations until a submitted operation is reconciled."""
