# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""iap.py — Binary native OpenSSH proxy without a command-shim parsing boundary."""

import base64
import json
import subprocess
import sys


def main() -> int:
    """Launch the internally encoded gcloud argv with inherited binary streams."""
    if len(sys.argv) != 2:
        return 2
    try:
        raw: object = json.loads(base64.urlsafe_b64decode(sys.argv[1]))
        if (
            not isinstance(raw, list)
            or not raw
            or not all(isinstance(item, str) for item in raw)
        ):
            return 2
        arguments: list[str] = [item for item in raw if isinstance(item, str)]
        result = subprocess.run(
            arguments,
            shell=False,
            stdin=sys.stdin.buffer,
            stdout=sys.stdout.buffer,
            stderr=sys.stderr.buffer,
            check=False,
        )
        return result.returncode
    except (OSError, ValueError):
        print("Cannot start the Piccolo IAP proxy", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
