# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""permissions.py — Action-specific IAM guidance for the acting identity."""

from piccolo.errors import PiccoloError


def permission_error(principal: str, role: str, resource: str) -> PiccoloError:
    """Describe the required provider role and binding scope without granting it."""
    identity = (
        f"Piccolo's service account `{principal}`"
        if principal.endswith(".gserviceaccount.com")
        else f"Piccolo's SDK identity `{principal}`"
    )
    return PiccoloError(
        f"[Piccolo] Permission denied. Please bind the required IAM permission "
        f"`GCP:{role}` to {identity} on `{resource}`. "
        "A custom role with the action's required permissions is also supported."
    )
