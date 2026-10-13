# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""registry.py — Select providers without importing optional SDKs eagerly."""

from piccolo.config.models import Config
from piccolo.errors import PiccoloError
from piccolo.providers.base import Provider


def create(config: Config) -> Provider:
    """Construct the selected provider and explain missing optional dependencies."""
    if config.provider != "gcp":
        raise PiccoloError(f"Unsupported provider: {config.provider}")
    try:
        from piccolo.providers.gcp.provider import GCPProvider
    except ImportError as exc:
        raise PiccoloError(
            "Install the GCP dependencies with pip install 'piccolo[gcp]'"
        ) from exc
    return GCPProvider(config)
