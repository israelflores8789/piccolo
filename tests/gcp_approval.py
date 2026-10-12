# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""gcp_approval.py — Show the local profile and digest for operator review."""

import argparse
from pathlib import Path

from gcp_live_support.gcp_live import approval_digest

from piccolo.config import load
from piccolo.config.models import canonical_value
from piccolo.logger import emit


def main() -> None:
    """Display proposed settings without credentials, SDK clients, or cloud calls."""
    parser = argparse.ArgumentParser(description="Review a live GCP approval digest")
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    config = load(args.config)
    emit(
        {
            "approval_sha256": approval_digest(config),
            "project": config.gcp.project_id,
            "settings": canonical_value(config.gcp),
            "deadline_seconds": 2700,
            "cleanup_seconds": 300,
            "dollar_limit_enforced": False,
        }
    )


if __name__ == "__main__":
    main()
