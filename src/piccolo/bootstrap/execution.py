# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""execution.py — Durable authorization and guest-side receipts for opaque scripts."""

import hashlib
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from piccolo.bootstrap.staging import home_path, private_path, upload
from piccolo.config.models import Config
from piccolo.data import Document, document, text
from piccolo.errors import PiccoloError, UncertainError
from piccolo.providers.base import Connection
from piccolo.state.journal import Journal


def receipt(journal: Journal, connection: Connection, zone: str) -> Document:
    """Inspect an existing attempt without authorizing a retry."""
    record = document(journal.data.get("bootstrap", {}))
    if text(record, "status") not in {"started", "uncertain", "completed", "failed"}:
        return record or {"status": "unknown", "eligible": False}
    path = home_path(text(record, "receipt"))
    output = connection.execute(
        zone,
        (
            f"if test -f {path}/exit-code; then cat "
            f"{path}/exit-code; elif test -d {path}; then "
            f"printf started; else printf unknown; fi"
        ),
    )
    if output.isdecimal():
        record["exit_code"] = int(output)
        record["status"] = "completed" if output == "0" else "failed"
    else:
        record["status"] = "started" if output == "started" else "uncertain"
    journal.data["bootstrap"] = record
    journal.save()
    return record


def execute(
    config: Config,
    journal: Journal,
    connection: Connection,
    zone: str,
    disk_id: str,
    *,
    dry_run: bool = False,
    status: bool = False,
    verify: Callable[[], Document] | None = None,
) -> Document:
    """Launch only an explicitly authorized first attempt and retain uncertainty."""
    setup = config.bootstrap
    if setup is None:
        raise PiccoloError("No bootstrap script is configured")
    if status:
        return receipt(journal, connection, zone)
    record = document(journal.data.get("bootstrap", {}))
    eligible = (
        text(record, "status") == "staged"
        and text(record, "disk_id") == disk_id
        and text(journal.data, "fresh_disk_id") == disk_id
    )
    description: Document = {
        "eligible": eligible,
        "script": str(setup.script),
        "remote_path": text(record, "remote_path"),
        "execution_user": setup.execution_user,
        "status": text(record, "status", "unknown"),
    }
    if dry_run:
        return description
    if not eligible:
        raise PiccoloError(
            "Bootstrap is blocked: disk is not recorded "
            "fresh, or an attempt already occurred. "
            "Inspect --status; v1 has no repeat/force "
            "bypass"
        )
    if hashlib.sha256(setup.script.read_bytes()).hexdigest() != text(record, "digest"):
        raise PiccoloError(
            "Local bootstrap changed since staging; execution is blocked"
        )
    if setup.remote_path != text(record, "remote_path") or setup.execution_user != text(
        record, "execution_user"
    ):
        raise PiccoloError(
            "Bootstrap target configuration differs from the staged artifact"
        )
    connection.ready(zone)
    if verify is not None:
        verify()
    script = home_path(text(record, "remote_path"))
    connection.execute(zone, private_path(text(record, "remote_path")))
    digest = connection.execute(zone, f"sha256sum {script}").split()[0]
    if digest != text(record, "digest"):
        raise PiccoloError("Staged bootstrap digest changed; refusing execution")
    attempt_path = text(record, "receipt")
    attempt = home_path(attempt_path)
    runner = f"{attempt_path}.runner.sh"
    wrapper = f"""#!/bin/bash
# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

umask 077
attempt={attempt}
{private_path(text(record, "remote_path"))}
exec 3< {script}
expected={text(record, "digest")}
test "$(sha256sum /proc/self/fd/3 | cut -d ' ' -f1)" = "$expected" || exit 125
set +e
bash /proc/self/fd/3
rc=$?
printf '%s\\n' "$rc" > "$attempt/exit-code.tmp"
mv "$attempt/exit-code.tmp" "$attempt/exit-code"
exit "$rc"
"""
    with tempfile.TemporaryDirectory(prefix="piccolo-bootstrap-") as temporary:
        local = Path(temporary) / "runner.sh"
        local.write_text(wrapper)
        runner_digest = hashlib.sha256(local.read_bytes()).hexdigest()
        upload(connection, zone, local, runner, runner_digest)
    record["status"] = "started"
    record["authorized_at"] = time.time()
    record["log_path"] = f"{attempt_path}/output.log"
    journal.data["bootstrap"] = record
    journal.save()
    try:
        connection.execute(
            zone,
            (
                private_path(runner) + "; " + f"exec 4< {home_path(runner)}; "
                f"test \"$(sha256sum /proc/self/fd/4 | cut -d ' ' -f1)\" = "
                f"{runner_digest}; "
                f"umask 077; test ! -L {attempt}; "
                f"mkdir -m 700 {attempt} && (nohup bash "
                f"/proc/self/fd/4 >{attempt}/output.log "
                f"2>&1 </dev/null &)"
            ),
        )
    except PiccoloError as exc:
        record["status"] = "uncertain"
        journal.data["bootstrap"] = record
        journal.save()
        raise UncertainError(
            "Bootstrap launch outcome is uncertain; "
            "inspect --status and guest logs. Another "
            "attempt is blocked"
        ) from exc
    deadline = time.monotonic() + setup.timeout
    while time.monotonic() < deadline:
        current = receipt(journal, connection, zone)
        if text(current, "status") in {"completed", "failed"}:
            if text(current, "status") == "failed":
                raise PiccoloError(
                    f"Bootstrap failed with exit code "
                    f"{current.get('exit_code')}; inspect "
                    f"~/{text(current, 'log_path')}"
                )
            return current
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise UncertainError(
        "Bootstrap is still running or uncertain; "
        "inspect --status and guest logs. It will "
        "never be retried automatically"
    )
