# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""lock.py — Kernel-released environment locks for Linux, macOS, and Windows."""

import os
from collections.abc import Generator
from contextlib import contextmanager

from piccolo.config.models import Config
from piccolo.errors import PiccoloError
from piccolo.state.journal import state_directory


@contextmanager
def environment_lock(config: Config) -> Generator[None]:
    """Serialize local mutations and release automatically after process exit."""
    directory = state_directory(config)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / "lock").open("a+b") as stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise PiccoloError(
                "Another Piccolo process holds the environment lock"
            ) from exc
        try:
            yield
        finally:
            if os.name == "nt":
                import msvcrt

                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
