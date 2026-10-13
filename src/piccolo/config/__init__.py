# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""__init__.py — Strict configuration discovery and validation."""

from piccolo.config.loader import load
from piccolo.config.models import Config

__all__ = ["Config", "load"]
