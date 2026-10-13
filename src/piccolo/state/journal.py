# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""journal.py — Atomic environment state with retained operation history."""

import hashlib
import json
import os
from pathlib import Path

from piccolo.config.models import Config
from piccolo.data import Document, Value, decode, document, text
from piccolo.errors import PiccoloError
from piccolo.privacy import sanitize
from piccolo.state.paths import state_root
from piccolo.state.storage import private_directory, private_file, temporary_file


def state_directory(config: Config) -> Path:
    """Return a project/environment key shared across configuration paths."""
    root = state_root()
    identity = f"{config.provider}:{config.gcp.project_id}:{config.environment}"
    key = hashlib.sha256(identity.encode()).hexdigest()[:24]
    return root / key


class Journal:
    """Persist intent, results, bootstrap eligibility, and completed operations."""

    def __init__(self, config: Config) -> None:
        """Load and check environment identity without creating state files."""
        self.config = config
        self.directory = state_directory(config)
        self.path = self.directory / "state.json"
        private_directory(self.directory.parent, create=False)
        private_directory(self.directory, create=False)
        self.data: Document
        try:
            if self.path.exists() or self.path.is_symlink():
                with os.fdopen(private_file(self.path)) as stream:
                    self.data = decode(stream.read())
            else:
                self.data = {
                    "schema_version": 1,
                    "project": config.gcp.project_id,
                    "environment": config.environment,
                    "history": [],
                }
        except (OSError, ValueError) as exc:
            raise PiccoloError(f"Cannot read journal {self.path}: {exc}") from exc
        if (
            self.data.get("schema_version") != 1
            or self.data.get("project") != config.gcp.project_id
            or self.data.get("environment") != config.environment
        ):
            raise PiccoloError("Journal identity or version mismatch; inspect state")

    @property
    def operation(self) -> Document:
        """Return the unresolved operation, or an empty object."""
        return document(self.data.get("operation", {}))

    def check_fingerprint(self) -> None:
        """Block recovery with a changed configuration."""
        operation = self.operation
        if operation and text(operation, "fingerprint") != self.config.fingerprint:
            raise PiccoloError(
                "Configuration changed during an operation; "
                "restore the original settings before resume"
            )

    def save(self) -> None:
        """Replace state atomically after flushing the temporary file."""
        private_directory(self.directory.parent)
        private_directory(self.directory)
        if self.path.exists() or self.path.is_symlink():
            os.close(private_file(self.path))
        descriptor, temporary = temporary_file(self.directory, "state-")
        try:
            with os.fdopen(descriptor, "w") as stream:
                json.dump(sanitize(self.data), stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name != "nt":
                directory = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def begin(self, operation: Document) -> None:
        """Persist a new operation before its first mutation."""
        if self.operation:
            raise PiccoloError("An unresolved operation exists; run piccolo resume")
        operation["fingerprint"] = self.config.fingerprint
        actions: list[Value] = []
        operation["actions"] = actions
        self.data["operation"] = operation
        self.save()

    def update(self, operation: Document) -> None:
        """Flush an updated operation record."""
        self.data["operation"] = operation
        self.save()

    def finish(self) -> None:
        """Archive a resolved operation and preserve its resource references."""
        history = self.data.get("history", [])
        if not isinstance(history, list):
            raise PiccoloError("Invalid journal history")
        operation = self.operation
        operation["stage"] = "complete"
        history.append(operation)
        self.data["history"] = history
        self.data.pop("operation", None)
        self.save()
