# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""staging.py — Stage immutable project-owned bootstrap bytes without running them."""

import hashlib
import shlex

from piccolo.config.models import Config
from piccolo.data import Document, document, text
from piccolo.errors import PiccoloError
from piccolo.providers.base import Connection
from piccolo.state.journal import Journal


def home_path(path: str) -> str:
    """Quote a validated relative path while expanding the remote user's home."""
    return '"$HOME"/' + shlex.quote(path)


def stage(
    config: Config, journal: Journal, connection: Connection, zone: str, disk_id: str
) -> None:
    """Copy only to a recorded fresh disk and verify the staged digest."""
    setup = config.bootstrap
    if setup is None:
        return
    if text(journal.data, "fresh_disk_id") != disk_id:
        raise PiccoloError(
            "Bootstrap staging requires Piccolo's recorded fresh boot disk"
        )
    source = setup.script.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    record = document(journal.data.get("bootstrap", {}))
    if record and text(record, "digest") != digest:
        raise PiccoloError(
            "Bootstrap source changed; staged artifacts cannot be replaced implicitly"
        )
    if record.get("status") == "staged":
        return
    if record and record.get("status") != "staging":
        raise PiccoloError("A bootstrap attempt already exists; staging is blocked")
    record: Document = {
        "status": "staging",
        "disk_id": disk_id,
        "digest": digest,
        "remote_path": setup.remote_path,
        "execution_user": setup.execution_user,
        "receipt": f".piccolo/bootstrap/attempt-{disk_id}",
    }
    journal.data["bootstrap"] = record
    journal.save()
    connection.ready(zone)
    destination = home_path(setup.remote_path)
    parent = setup.remote_path.rsplit("/", 1)[0] if "/" in setup.remote_path else "."
    connection.execute(
        zone,
        (
            f"mkdir -p {home_path(parent)}; if test -e "
            f"{destination}; then sha256sum {destination}; "
            f"fi"
        ),
    )
    temporary = f"{setup.remote_path}.upload-{digest[:12]}"
    connection.copy(zone, setup.script, temporary)
    observed = connection.execute(zone, f"sha256sum {home_path(temporary)}").split()[0]
    if observed != digest:
        raise PiccoloError("Bootstrap digest mismatch after transfer")
    connection.execute(
        zone,
        (
            f"chmod 600 {home_path(temporary)}; if test -e "
            f'{destination}; then test "$(sha256sum '
            f"{destination} | cut -d ' ' -f1)\" = "
            f"{shlex.quote(digest)} && rm -f "
            f"{home_path(temporary)}; else mv -n "
            f"{home_path(temporary)} {destination}; fi"
        ),
    )
    verified = connection.execute(zone, f"sha256sum {destination}").split()[0]
    if verified != digest:
        raise PiccoloError("Existing remote artifact differs; refusing to overwrite it")
    record["status"] = "staged"
    journal.save()
