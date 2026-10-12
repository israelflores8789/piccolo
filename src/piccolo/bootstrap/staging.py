# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""staging.py — Stage immutable project-owned bootstrap bytes without running them."""

import hashlib
import shlex
import tempfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from piccolo.config.models import Config
from piccolo.data import Document, document, text
from piccolo.errors import PiccoloError
from piccolo.providers.base import Connection
from piccolo.state.journal import Journal


def home_path(path: str) -> str:
    """Quote a validated relative path while expanding the remote user's home."""
    return '"$HOME"/' + shlex.quote(path)


def private_path(path: str, *, prepare: bool = False) -> str:
    """Check home-relative ownership and symlinks before creating private paths."""
    parts = PurePosixPath(path).parts
    if not parts or path.startswith("/") or ".." in parts:
        raise PiccoloError("Unsafe remote artifact path")
    commands = [
        "set -eu",
        "umask 077",
        'test ! -L "$HOME"',
        'test "$(stat -c %u "$HOME")" = "$(id -u)"',
    ]
    for index in range(1, len(parts)):
        parent = home_path("/".join(parts[:index]))
        commands.extend(
            [
                f"test ! -L {parent}",
                (
                    f"if test -e {parent}; then test -d {parent}; "
                    f'test "$(stat -c %u {parent})" = "$(id -u)"; '
                    f"chmod 700 {parent}; else mkdir -m 700 {parent}; fi"
                ),
            ]
        )
    target = home_path(path)
    commands.extend(
        [
            f"test ! -L {target}",
            (
                f"if test -e {target}; then test -f {target}; "
                f'test "$(stat -c %u {target})" = "$(id -u)"; '
                f'test "$(stat -c %h {target})" = 1; chmod 600 {target}; fi'
            ),
        ]
    )
    if prepare:
        commands.append(f"if ! test -e {target}; then (set -C; : > {target}); fi")
    return "; ".join(commands)


def upload(
    connection: Connection, zone: str, source: Path, destination: str, digest: str
) -> None:
    """Create a private regular destination before SCP, then verify its digest."""
    contents = source.read_bytes()
    if hashlib.sha256(contents).hexdigest() != digest:
        raise PiccoloError("Local artifact changed before transfer")
    connection.execute(zone, private_path(destination, prepare=True))
    with tempfile.TemporaryDirectory(prefix="piccolo-upload-") as directory:
        private_source = Path(directory) / "artifact"
        private_source.write_bytes(contents)
        private_source.chmod(0o600)
        connection.copy(zone, private_source, destination)
    connection.execute(zone, private_path(destination))
    observed = connection.execute(zone, f"sha256sum {home_path(destination)}").split()
    if not observed or observed[0] != digest:
        raise PiccoloError("Artifact digest mismatch after transfer")


def stage(
    config: Config,
    journal: Journal,
    connection: Connection,
    zone: str,
    disk_id: str,
    *,
    verify: Callable[[], Document] | None = None,
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
    if verify is not None:
        verify()
    destination = home_path(setup.remote_path)
    connection.execute(zone, private_path(setup.remote_path))
    temporary = f"{setup.remote_path}.upload-{digest[:12]}"
    with tempfile.TemporaryDirectory(prefix="piccolo-stage-") as temporary_directory:
        local = Path(temporary_directory) / "script.sh"
        local.write_bytes(source)
        upload(connection, zone, local, temporary, digest)
    connection.execute(
        zone,
        private_path(setup.remote_path)
        + "; "
        + private_path(temporary)
        + "; "
        + (
            f"if test -e {destination}; then "
            f"test \"$(sha256sum {destination} | cut -d ' ' -f1)\" = "
            f"{shlex.quote(digest)}; "
            f"rm -f {home_path(temporary)}; else "
            f"mv -n {home_path(temporary)} {destination}; fi"
        ),
    )
    verified = connection.execute(zone, f"sha256sum {destination}").split()[0]
    if verified != digest:
        raise PiccoloError("Existing remote artifact differs; refusing to overwrite it")
    if verify is not None:
        verify()
    record["status"] = "staged"
    journal.save()
