# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""base.py — Infrastructure and opaque bootstrap connection contracts."""

from pathlib import Path
from typing import Protocol

from piccolo.data import Document


class Connection(Protocol):
    """Provide authenticated sessions and opaque file transfer."""

    def ready(self, zone: str) -> None:
        """Wait for authenticated SSH and optional project-owned readiness."""
        ...

    def execute(self, zone: str, command: str, timeout: int = 60) -> str:
        """Execute a remote command and return captured standard output."""
        ...

    def copy(self, zone: str, source: Path, destination: str) -> None:
        """Copy a file to the connection user's home directory."""
        ...

    def shell(self, zone: str) -> None:
        """Open a foreground SSH session."""
        ...

    def tunnel(self, zone: str) -> None:
        """Open a foreground loopback-bound IAP tunnel."""
        ...


class Provider(Protocol):
    """Expose environment operations while leaving recovery provider-specific."""

    capabilities: frozenset[str]
    connection: Connection

    def inspect(self) -> Document:
        """Inspect observed environment state."""
        ...

    def plan(self) -> Document:
        """Describe reconciliation without changing infrastructure."""
        ...

    def init(self) -> None:
        """Provision infrastructure and stage an optional script."""
        ...

    def start(self) -> str:
        """Start the selected environment and return its zone."""
        ...

    def stop(self) -> None:
        """Stop the selected environment."""
        ...

    def active(self) -> Document:
        """Select the single unambiguous active instance."""
        ...

    def move(self, destination: str | None) -> None:
        """Relocate using provider-specific recovery rules."""
        ...

    def resume(self) -> None:
        """Reconcile an interrupted infrastructure operation."""
        ...

    def rollback(self) -> None:
        """Restart a source only after settling replacement requests."""
        ...

    def cleanup(self, apply: bool) -> Document:
        """Preview or delete eligible owned recovery artifacts."""
        ...

    def bootstrap(self, dry_run: bool, status: bool) -> Document:
        """Explicitly invoke or inspect an opaque staged script."""
        ...
