# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""logger.py — Central sanitized console rendering and notification behavior."""

import json
import sys
from collections.abc import Callable

from piccolo.data import Document
from piccolo.privacy import sanitize, sanitize_text


def log(message: str, *, err: bool = False) -> None:
    """Print a sanitized message to the selected console stream."""
    print(sanitize_text(message), file=sys.stderr if err else sys.stdout, flush=True)


def emit(result: Document) -> None:
    """Render sanitized JSON in a stable form suitable for diagnostic logs."""
    print(
        json.dumps(sanitize(result, diagnostic=True), indent=2, sort_keys=True),
        file=sys.stdout,
        flush=True,
    )


def reporter(sink: Callable[[str], None]) -> Callable[[str], None]:
    """Protect an injected notification sink with the same redaction policy."""

    def report(message: str) -> None:
        """Deliver one sanitized notification."""
        sink(sanitize_text(message))

    return report
