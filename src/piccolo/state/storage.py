# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""storage.py — Owned private state directories and no-follow regular files."""

import os
import stat
from pathlib import Path

from piccolo.errors import PiccoloError


def private_directory(path: Path, *, create: bool = True) -> None:
    """Reject redirected paths and repair owned POSIX state directories to 0700."""
    if os.name == "nt":
        raise PiccoloError(
            "Private state requires POSIX ownership/modes; "
            "Windows ACL verification is unsupported"
        )
    if ".." in path.parts:
        raise PiccoloError("State directory cannot contain parent traversal")
    absolute = Path(os.path.abspath(path))
    for component in (*reversed(absolute.parents), absolute):
        if component.is_symlink():
            raise PiccoloError(f"State directory cannot contain a symlink: {component}")
    if not absolute.exists() and not create:
        return
    absolute.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(absolute, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid():
            raise PiccoloError(f"State directory is not owned by this user: {absolute}")
        os.fchmod(descriptor, 0o700)
    finally:
        os.close(descriptor)


def private_file(path: Path, *, create: bool = False) -> int:
    """Open an owned single-link regular file without following a symlink."""
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT
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
