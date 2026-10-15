# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""win32process.py — Assign suspended children to jobs before allowing execution."""

import ctypes
import sys
from collections.abc import Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable

    from _win32typing import PyHANDLE

import pywintypes
import win32api
import win32con
import win32job

from piccolo.errors import PiccoloError


@contextmanager
def process_job(pid: int) -> Generator[None]:
    """Close the whole process tree on timeout, cancellation, or normal exit."""
    create_job = cast("Callable[[object, str], PyHANDLE]", win32job.CreateJobObject)
    job = create_job(None, "")
    try:
        info: dict[str, object] = win32job.QueryInformationJobObject(
            int(job), win32job.JobObjectExtendedLimitInformation
        )
        limits = cast("dict[str, int]", info["BasicLimitInformation"])
        limits["LimitFlags"] = win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(
            int(job), win32job.JobObjectExtendedLimitInformation, info
        )
        # pywin32 does not expose NtResumeProcess; resuming the suspended root this
        # way avoids starting an IAP proxy before its job membership is established.
        open_process = cast(
            "Callable[[int, bool, int], PyHANDLE]", win32api.OpenProcess
        )
        handle = open_process(
            win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE | 0x0800, False, pid
        )
        try:
            win32job.AssignProcessToJobObject(int(job), int(handle))
            if sys.platform == "win32":
                resume = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)(
                    ("NtResumeProcess", ctypes.WinDLL("ntdll"))
                )
                if resume(int(handle)) != 0:
                    raise PiccoloError(
                        "Cannot resume the protected Windows child process"
                    )
            else:
                raise PiccoloError("Windows process jobs require native Windows Python")
        finally:
            handle.Close()
        yield
    except pywintypes.error as exc:
        raise PiccoloError(
            f"Cannot contain the Windows connection process (error {exc.winerror})"
        ) from exc
    finally:
        job.Close()
