# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_process.py — Offline binary capture, foreground handles, and process cleanup."""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from piccolo.errors import PiccoloError
from piccolo.process import run_command


def test_argument_list_preserves_spaces_unicode_and_metacharacters() -> None:
    arguments = ["two words", "unicode-\u00e9", "$(unchanged)", "literal%PATH%", "a&b"]
    result = run_command(
        [
            sys.executable,
            "-c",
            "import json,sys; print(json.dumps(sys.argv[1:]))",
            *arguments,
        ],
        os.environ.copy(),
    )
    assert result.returncode == 0
    assert json.loads(result.stdout) == arguments


def test_prompt_capture_decodes_split_utf8_and_has_no_reader_leak(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    before = set(threading.enumerate())
    code = "import os,time; os.write(1,b'\\xc3'); time.sleep(.02); os.write(1,b'\\xa9')"
    result = run_command([sys.executable, "-c", code], os.environ.copy(), prompts=True)
    assert result.stdout == "\u00e9"
    assert "\u00e9" in capsys.readouterr().out
    assert set(threading.enumerate()) == before


def test_prompt_capture_requires_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(PiccoloError, match="interactive terminal"):
        run_command([sys.executable, "-c", "pass"], os.environ.copy(), prompts=True)


def test_foreground_inherits_stdio_and_preserves_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import piccolo.process as process_module

    real_popen = subprocess.Popen
    launch = Mock(side_effect=real_popen)
    monkeypatch.setattr(process_module.subprocess, "Popen", launch)
    result = run_command(
        [sys.executable, "-c", "raise SystemExit(7)"], os.environ.copy(), capture=False
    )
    assert result.returncode == 7
    assert launch.call_args.kwargs["stdout"] is None
    assert launch.call_args.kwargs["stderr"] is None
    assert "stdin" not in launch.call_args.kwargs
    assert launch.call_args.kwargs["shell"] is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows child job containment")
@pytest.mark.parametrize("prompts", [True, False])
def test_timeout_terminates_descendant_pipe_holders(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prompts: bool
) -> None:
    import pywintypes
    import win32api
    import win32con
    import win32event

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    pid_path = tmp_path / "descendant.pid"
    code = (
        "import subprocess,sys,time; from pathlib import Path; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
        "Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(30)"
    )
    before = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_command(
            [sys.executable, "-c", code, str(pid_path)],
            os.environ.copy(),
            timeout=0.5,
            prompts=prompts,
        )
    assert time.monotonic() - before < 3
    assert pid_path.exists()
    pid = int(pid_path.read_text())
    try:
        handle = win32api.OpenProcess(win32con.SYNCHRONIZE, False, pid)
    except pywintypes.error as exc:
        assert exc.winerror == 87
    else:
        try:
            assert (
                win32event.WaitForSingleObject(handle, 2000) == win32event.WAIT_OBJECT_0
            )
        finally:
            win32api.CloseHandle(handle)
