# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""platform_support.py — Inspect real private permissions and test redirects."""

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest


def assert_private(path: Path, *, directory: bool = False) -> None:
    """Verify actual ACLs on Windows or ownership/modes on POSIX."""
    if sys.platform == "win32":
        import ntsecuritycon
        import win32security

        from piccolo.state.windows import current_sid

        descriptor = win32security.GetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION,
        )
        assert descriptor.GetSecurityDescriptorOwner() == current_sid()
        assert (
            descriptor.GetSecurityDescriptorControl()[0]
            & win32security.SE_DACL_PROTECTED
        )
        acl = descriptor.GetSecurityDescriptorDacl()
        assert acl is not None and acl.GetAceCount() == 1
        (kind, _flags), rights, sid = acl.GetAce(0)
        assert kind == win32security.ACCESS_ALLOWED_ACE_TYPE
        assert sid == current_sid() and rights == ntsecuritycon.FILE_ALL_ACCESS
    else:
        assert path.stat().st_uid == os.getuid()
        assert stat.S_IMODE(path.stat().st_mode) == (0o700 if directory else 0o600)


def redirect(path: Path, target: Path, *, directory: bool = False) -> None:
    """Create junctions without elevation, or symlinks when the platform permits."""
    if sys.platform == "win32" and directory:
        result = subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(path), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return
    try:
        path.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        if sys.platform == "win32" and exc.winerror == 1314:
            pytest.skip(
                "File symlink creation needs Windows Developer Mode; "
                "junction and hardlink tests still run"
            )
        raise
