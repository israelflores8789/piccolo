# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""lock.py — Kernel-released locks using validated private state storage."""

import hashlib
import os
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from piccolo.config.models import Config
from piccolo.errors import PiccoloError
from piccolo.state.journal import state_directory
from piccolo.state.storage import private_directory, private_file


@contextmanager
def environment_lock(config: Config) -> Generator[None]:
    """Serialize environment and same-name VM mutations within one state root."""
    directory = state_directory(config)
    private_directory(directory.parent)
    private_directory(directory)
    identity = f"{config.provider}:{config.gcp.project_id}:{config.gcp.name}"
    key = hashlib.sha256(identity.encode()).hexdigest()[:24]
    with (
        file_lock(directory / "lock"),
        file_lock(directory.parent / f"resource-{key}.lock"),
    ):
        yield


@contextmanager
def file_lock(path: Path) -> Generator[None]:
    """Hold one nonblocking kernel lock and release it on every exit path."""
    private_directory(path.parent)
    with os.fdopen(private_file(path, create=True), "r+b") as stream:
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
