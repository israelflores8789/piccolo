# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""journal.py — Atomic environment state with retained operation history."""

import hashlib
import json
import os
import tempfile
from pathlib import Path

from piccolo.config.models import Config
from piccolo.data import Document, Value, decode, document, text
from piccolo.errors import PiccoloError


def state_directory(config: Config) -> Path:
    """Return a project/environment key shared across configuration paths."""
    root = Path(os.environ.get("PICCOLO_STATE_DIR", str(Path.home() / ".piccolo")))
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
        self.data: Document
        try:
            self.data = (
                decode(self.path.read_text())
                if self.path.exists()
                else {
                    "schema_version": 1,
                    "project": config.gcp.project_id,
                    "environment": config.environment,
                    "history": [],
                }
            )
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
                "restore the original TOML before resume"
            )

    def save(self) -> None:
        """Replace state atomically after flushing the temporary file."""
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary = tempfile.mkstemp(dir=self.directory, prefix="state-")
        try:
            with os.fdopen(descriptor, "w") as stream:
                json.dump(self.data, stream, indent=2, sort_keys=True)
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
            Path(temporary).unlink(missing_ok=True)

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
