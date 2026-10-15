# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""windows.py — Handle-verified private storage with protected current-user ACLs."""

from __future__ import annotations

import msvcrt
import os
import sys
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, cast

import ntsecuritycon
import pywintypes
import win32api
import win32con
import win32file
import win32security

from piccolo.errors import PiccoloError

if TYPE_CHECKING:
    from _win32typing import PyHANDLE, PySECURITY_ATTRIBUTES, PySID


def current_sid() -> PySID:
    """Read the process token's user without consulting account names."""
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
    )
    try:
        return cast(
            "tuple[PySID, int]",
            win32security.GetTokenInformation(token, win32security.TokenUser),
        )[0]
    finally:
        win32api.CloseHandle(token)


def attributes(*, directory: bool = False) -> PySECURITY_ATTRIBUTES:
    """Create objects with a protected, user-only DACL from their first instant."""
    sid = current_sid()
    acl = win32security.ACL()
    inheritance = (
        (win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE)
        if directory
        else 0
    )
    acl.AddAccessAllowedAceEx(
        win32security.ACL_REVISION, inheritance, ntsecuritycon.FILE_ALL_ACCESS, sid
    )
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(sid, False)
    descriptor.SetSecurityDescriptorDacl(True, acl, False)
    descriptor.SetSecurityDescriptorControl(
        win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED
    )
    result = win32security.SECURITY_ATTRIBUTES()
    result.SECURITY_DESCRIPTOR = descriptor
    result.bInheritHandle = False
    return result


def secure_handle(handle: PyHANDLE, path: Path, *, directory: bool = False) -> None:
    """Repair an owned object and verify its complete resulting descriptor."""
    sid = current_sid()
    flags = (
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION
    )
    descriptor = win32security.GetSecurityInfo(
        int(handle), win32security.SE_FILE_OBJECT, flags
    )
    if descriptor.GetSecurityDescriptorOwner() != sid:
        raise PiccoloError(f"Private path is not owned by this user: {path}")
    acl = attributes(
        directory=directory
    ).SECURITY_DESCRIPTOR.GetSecurityDescriptorDacl()
    win32security.SetSecurityInfo(
        int(handle),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        sid,
        sid,
        acl,
        win32security.ACL(),
    )
    checked = win32security.GetSecurityInfo(
        int(handle), win32security.SE_FILE_OBJECT, flags
    )
    actual = checked.GetSecurityDescriptorDacl()
    control, _revision = checked.GetSecurityDescriptorControl()
    if actual is None or actual.GetAceCount() != 1:
        raise PiccoloError(f"Cannot enforce a private Windows DACL: {path}")
    (kind, ace_flags), mask, owner = actual.GetAce(0)
    if (
        checked.GetSecurityDescriptorOwner() != sid
        or not control & win32security.SE_DACL_PROTECTED
        or kind != win32security.ACCESS_ALLOWED_ACE_TYPE
        or ace_flags
        != (
            (win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE)
            if directory
            else 0
        )
        or mask != ntsecuritycon.FILE_ALL_ACCESS
        or owner != sid
    ):
        raise PiccoloError(f"Cannot verify private Windows permissions: {path}")


def open_handle(
    path: Path,
    *,
    create: bool = False,
    exclusive: bool = False,
    directory: bool = False,
    writable: bool = True,
) -> PyHANDLE:
    """Open the leaf itself, rejecting reparses and multiply linked files."""
    access = ntsecuritycon.FILE_READ_ATTRIBUTES
    if directory and not writable:
        access |= win32con.GENERIC_READ
    if writable:
        access |= win32con.READ_CONTROL
    if writable:
        access |= win32con.WRITE_DAC
        if not directory:
            access |= win32con.GENERIC_READ | win32con.GENERIC_WRITE
    disposition = (
        win32con.CREATE_NEW
        if exclusive
        else (win32con.OPEN_ALWAYS if create else win32con.OPEN_EXISTING)
    )
    sharing = win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE
    if not directory:
        sharing |= win32con.FILE_SHARE_DELETE
    handle = win32file.CreateFile(
        str(path),
        access,
        sharing,
        attributes() if create else None,
        disposition,
        win32file.FILE_FLAG_OPEN_REPARSE_POINT | win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    try:
        info = win32file.GetFileInformationByHandle(int(handle))
        if (
            info[0] & win32con.FILE_ATTRIBUTE_REPARSE_POINT
            or bool(info[0] & win32con.FILE_ATTRIBUTE_DIRECTORY) != directory
            or (not directory and info[7] != 1)
            or win32file.GetFileType(int(handle)) != win32con.FILE_TYPE_DISK
        ):
            raise PiccoloError(
                "Private path must be an unredirected "
                f"{'directory' if directory else 'regular file with one link'}: {path}"
            )
        return handle
    except BaseException:
        handle.Close()
        raise


@contextmanager
def parents(path: Path, *, create: bool = False) -> Generator[None]:
    """Pin local parent directories against replacement without changing their ACLs."""
    if ".." in path.parts:
        raise PiccoloError("Private path cannot contain parent traversal")
    absolute = path.absolute()
    if absolute.drive.startswith("\\\\"):
        raise PiccoloError(
            "Private Windows storage requires a local ACL-capable filesystem"
        )
    with ExitStack() as stack:
        for parent in reversed(absolute.parents):
            try:
                handle = open_handle(parent, directory=True, writable=False)
            except pywintypes.error as exc:
                if exc.winerror not in (2, 3) or not create:
                    raise
                win32file.CreateDirectory(str(parent), attributes(directory=True))
                handle = open_handle(parent, directory=True, writable=False)
            stack.callback(handle.Close)
        yield


def private_directory(path: Path, *, create: bool = True) -> None:
    """Secure only the requested directory, allowing ordinary profile ancestors."""
    try:
        with parents(path, create=create):
            try:
                handle = open_handle(path, directory=True)
            except pywintypes.error as exc:
                if exc.winerror not in (2, 3):
                    raise
                if not create:
                    return
                win32file.CreateDirectory(str(path), attributes(directory=True))
                handle = open_handle(path, directory=True)
            try:
                secure_handle(handle, path, directory=True)
            finally:
                handle.Close()
    except pywintypes.error as exc:
        if not create and exc.winerror in (2, 3):
            return
        raise PiccoloError(
            f"Cannot enforce private Windows directory permissions for {path} "
            f"(Windows error {exc.winerror}); "
            "use local NTFS storage owned by this user"
        ) from exc


def private_file(path: Path, *, create: bool = False, exclusive: bool = False) -> int:
    """Transfer one validated Windows handle to one binary Python descriptor."""
    try:
        with parents(path):
            handle = open_handle(path, create=create, exclusive=exclusive)
            try:
                secure_handle(handle, path)
                if sys.platform == "win32":
                    descriptor = msvcrt.open_osfhandle(
                        int(handle), os.O_RDWR | os.O_BINARY
                    )
                    handle.Detach()
                    return descriptor
                else:
                    raise PiccoloError("Windows storage requires native Windows Python")
            except BaseException:
                handle.Close()
                raise
    except pywintypes.error as exc:
        raise PiccoloError(
            f"Cannot open private Windows file {path} "
            f"(Windows error {exc.winerror}); "
            "check ownership and local filesystem ACL support"
        ) from exc
