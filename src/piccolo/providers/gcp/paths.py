# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""paths.py — Resolve Cloud SDK paths without creating them."""

import os
from pathlib import Path

from piccolo.errors import PiccoloError


def cloud_sdk_directory() -> Path:
    """Use Cloud SDK conventions consistently for ADC and transport launches."""
    override = os.environ.get("CLOUDSDK_CONFIG")
    if override:
        return Path(override).absolute()
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise PiccoloError(
                "APPDATA is required to locate the Windows Cloud SDK config"
            )
        return Path(appdata) / "gcloud"
    return Path.home() / ".config" / "gcloud"
