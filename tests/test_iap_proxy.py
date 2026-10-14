# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_iap_proxy.py — Native binary forwarding and clean caller EOF regressions."""

import base64
import json
import subprocess
import sys
import threading
from queue import Queue

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Native Windows pipes")


def proxy_arguments(script: str) -> list[str]:
    """Encode a harmless SDK stand-in through the production proxy entrypoint."""
    command = [sys.executable, "-c", script, "space café λ"]
    encoded = base64.urlsafe_b64encode(json.dumps(command).encode()).decode()
    return [sys.executable, "-m", "piccolo.providers.gcp.iap", encoded]


def test_proxy_preserves_binary_bytes_and_stops_sdk_before_caller_eof() -> None:
    """Prevent the SDK from interpreting the finished SSH caller as a pipe error."""
    from piccolo.win32process import process_job

    script = (
        "import os,sys; assert sys.argv[1] == 'space café λ'; "
        "data=os.read(0,4); os.write(1,data); "
        "os.read(0,1); print('unexpected SDK EOF',file=sys.stderr,flush=True)"
    )
    with (
        subprocess.Popen(
            proxy_arguments(script),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as process,
        process_job(process.pid),
    ):
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        received: Queue[bytes] = Queue()
        output = process.stdout
        reader = threading.Thread(
            target=lambda: received.put(output.read(4)), daemon=True
        )
        reader.start()
        payload = b"\x00\xff\r\n"
        process.stdin.write(payload)
        process.stdin.flush()
        assert received.get(timeout=10) == payload
        reader.join(timeout=2)
        process.stdin.close()
        assert process.wait(timeout=10) == 0
        assert process.stderr.read() == b""


def test_proxy_retains_sdk_failure_status_and_diagnostic() -> None:
    """Keep real SDK errors visible while the SSH caller still has input open."""
    from piccolo.win32process import process_job

    script = (
        "import sys; print('fixture permission failure',file=sys.stderr); sys.exit(7)"
    )
    with (
        subprocess.Popen(
            proxy_arguments(script),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as process,
        process_job(process.pid),
    ):
        assert process.stderr is not None
        assert process.wait(timeout=10) == 7
        assert b"fixture permission failure" in process.stderr.read()
