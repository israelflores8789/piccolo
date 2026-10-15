# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""storage.py — Owned private state directories and no-follow regular files."""

import os
import stat
import sys
import tempfile
import uuid
import weakref
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from piccolo.errors import PiccoloError


def private_directory(path: Path, *, create: bool = True) -> None:
    """Reject redirected paths and enforce current-user private directories."""
    if sys.platform == "win32":
        from piccolo.state.windows import private_directory as windows_directory

        windows_directory(path, create=create)
    else:
        if ".." in path.parts:
            raise PiccoloError("State directory cannot contain parent traversal")
        absolute = Path(os.path.abspath(path))
        for component in (*reversed(absolute.parents), absolute):
            if component.is_symlink():
                raise PiccoloError(
                    f"State directory cannot contain a symlink: {component}"
                )
        if not absolute.exists() and not create:
            return
        absolute.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(absolute, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid():
                raise PiccoloError(
                    f"State directory is not owned by this user: {absolute}"
                )
            os.fchmod(descriptor, 0o700)
        finally:
            os.close(descriptor)


def private_file(path: Path, *, create: bool = False, exclusive: bool = False) -> int:
    """Open an owned single-link regular file without following a symlink."""
    if sys.platform == "win32":
        from piccolo.state.windows import private_file as windows_file

        return windows_file(path, create=create, exclusive=exclusive)
    else:
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        if create:
            flags |= os.O_CREAT
        if exclusive:
            flags |= os.O_EXCL
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise PiccoloError(f"Cannot open private state file {path}: {exc}") from exc
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            os.close(descriptor)
            raise PiccoloError(
                f"State file must be an owned regular file with one link: {path}"
            )
        os.fchmod(descriptor, 0o600)
        return descriptor


def temporary_file(directory: Path, prefix: str = "piccolo-") -> tuple[int, Path]:
    """Create a unique file with private permissions before writing any bytes."""
    path = directory / f"{prefix}{uuid.uuid4().hex}"
    return private_file(path, create=True, exclusive=True), path


@contextmanager
def temporary_directory(prefix: str = "piccolo-") -> Generator[Path]:
    """Create and clean a private temporary directory using the platform backend."""
    directory = PrivateTemporaryDirectory(prefix)
    try:
        yield Path(directory.name)
    finally:
        directory.cleanup()


class PrivateTemporaryDirectory:
    """Own a protected temporary directory until explicit cleanup or collection."""

    def __init__(self, prefix: str) -> None:
        """Create an unpredictable private directory before exposing its path."""
        import shutil

        path = Path(tempfile.gettempdir()).resolve() / f"{prefix}{uuid.uuid4().hex}"
        private_directory(path)
        self.name = str(path)
        self._cleanup = weakref.finalize(self, shutil.rmtree, path)

    def cleanup(self) -> None:
        """Remove the directory once all child process handles have been closed."""
        self._cleanup()
