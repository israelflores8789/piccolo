# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""iap.py — Binary native OpenSSH proxy without a command-shim parsing boundary."""

import base64
import json
import os
import subprocess
import sys
import threading


def windows_proxy(arguments: list[str]) -> int:
    """Relay binary input and stop the SDK when OpenSSH closes its input pipe."""
    import msvcrt

    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    closed = threading.Event()
    with subprocess.Popen(
        arguments,
        shell=False,
        stdin=subprocess.PIPE,
        stdout=sys.stdout.buffer,
        stderr=sys.stderr.buffer,
        bufsize=0,
    ) as process:
        assert process.stdin is not None
        destination = process.stdin.fileno()

        def forward() -> None:
            """Keep raw bytes unchanged and distinguish caller EOF from SDK failure."""
            try:
                while data := os.read(sys.stdin.fileno(), 65536):
                    view = memoryview(data)
                    while view:
                        written = os.write(destination, view)
                        view = view[written:]
            except OSError:
                return
            closed.set()
            if process.poll() is None:
                process.terminate()

        worker = threading.Thread(target=forward, daemon=True)
        worker.start()
        result = process.wait()
        return 0 if closed.is_set() else result


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
        if sys.platform == "win32":
            return windows_proxy(arguments)
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
