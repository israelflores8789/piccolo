# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""process.py — Bounded capture and foreground execution with Windows job cleanup."""

import codecs
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from typing import BinaryIO

from piccolo.errors import PiccoloError


@contextmanager
def managed_process(
    command: list[str],
    environment: dict[str, str],
    *,
    capture: bool,
    prompts: bool = False,
) -> Generator[subprocess.Popen[bytes]]:
    """Keep Windows children suspended until they belong to a kill-on-close job."""
    flags = 0
    if sys.platform == "win32":
        import win32con

        flags = win32con.CREATE_SUSPENDED
    process = subprocess.Popen(
        command,
        shell=False,
        env=environment,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture and not prompts else None,
        creationflags=flags,
    )
    try:
        if sys.platform == "win32":
            from piccolo.windows_process import process_job

            with process_job(process.pid):
                yield process
        else:
            yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def read_chunks(stream: BinaryIO, chunks: queue.Queue[bytes | OSError | None]) -> None:
    """Read blocking pipes off the main thread, including the EOF/error event."""
    try:
        while chunk := os.read(stream.fileno(), 4096):
            chunks.put(chunk)
    except OSError as exc:
        chunks.put(exc)
    finally:
        chunks.put(None)


def run_command(
    command: list[str],
    environment: dict[str, str],
    *,
    timeout: float | None = 60,
    capture: bool = True,
    prompts: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Capture commands with a deadline while leaving foreground terminal IO intact."""
    if prompts and not (sys.stdin.isatty() and sys.stderr.isatty()):
        raise PiccoloError("Passphrase prompts require an interactive terminal")
    deadline = None if timeout is None else time.monotonic() + timeout
    with managed_process(
        command, environment, capture=capture, prompts=prompts
    ) as process:
        if not (prompts and capture):
            stdout, stderr = process.communicate(timeout=timeout)
            return subprocess.CompletedProcess(
                command,
                process.returncode,
                (stdout or b"").decode("utf-8", errors="replace"),
                (stderr or b"").decode("utf-8", errors="replace"),
            )
        stream = process.stdout
        if stream is None:
            raise PiccoloError("Command stdout is unavailable")
        chunks: queue.Queue[bytes | OSError | None] = queue.Queue()
        reader = threading.Thread(
            target=read_chunks, args=(stream, chunks), daemon=True
        )
        reader.start()
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        output: list[str] = []
        try:
            while True:
                if (
                    timeout is not None
                    and deadline is not None
                    and time.monotonic() >= deadline
                ):
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    chunk = chunks.get(timeout=0.05)
                except queue.Empty:
                    continue
                if chunk is None:
                    break
                if isinstance(chunk, OSError):
                    raise chunk
                rendered = decoder.decode(chunk)
                output.append(rendered)
                sys.stdout.write(rendered)
                sys.stdout.flush()
            rendered = decoder.decode(b"", final=True)
            output.append(rendered)
            sys.stdout.write(rendered)
            sys.stdout.flush()
            remaining = (
                None if deadline is None else max(0, deadline - time.monotonic())
            )
            code = process.wait(timeout=remaining)
            return subprocess.CompletedProcess(command, code, "".join(output), "")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            # Closing the enclosing Windows job terminates any descendant pipe holders.
            reader.join(timeout=0.2)
