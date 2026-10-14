# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""deadline.py — Cooperative live-session deadline with reserved cleanup time."""

from __future__ import annotations

import math
import os
import subprocess
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Literal, cast
from unittest.mock import patch
from weakref import WeakSet

from google.api_core import exceptions

from piccolo.errors import PiccoloError

if TYPE_CHECKING:
    from pathlib import Path

    from piccolo.providers.gcp.clients import Clients
    from piccolo.providers.gcp.connection import GCloudConnection
    from piccolo.providers.gcp.ssh import SSHTransport

TOTAL_SECONDS = 45 * 60
MAX_SECONDS = 145 * 60
CLEANUP_SECONDS = 5 * 60
INVENTORY_SECONDS = 60
SERVICE_USAGE_INTERVAL = 1.05
type Phase = Literal["work", "cleanup", "inventory"]
ACTIVE: ContextVar[Deadline | None] = ContextVar("piccolo_live_deadline", default=None)
_BOUND_CLIENTS: WeakSet[object] = WeakSet()


class Deadline:
    """Share a monotonic deadline across all tests, RPCs, and teardown phases."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        total_seconds: int = TOTAL_SECONDS,
    ) -> None:
        """Reserve the final five minutes, including one minute for inventory."""
        self.clock = clock
        if not CLEANUP_SECONDS < total_seconds <= MAX_SECONDS:
            raise PiccoloError(
                "Live duration must exceed cleanup reserve and be at most 8700 seconds"
            )
        self.total_seconds = total_seconds
        self.started = clock()
        self.phase: Phase = "work"
        self.work_expired = False
        self.last_service_usage: float | None = None

    def pace_service_usage(self) -> None:
        """Space Service Usage attempts across clients without exceeding this phase."""
        if self.last_service_usage is not None:
            delay = SERVICE_USAGE_INTERVAL - (self.clock() - self.last_service_usage)
            if delay > 0:
                if delay >= self.remaining():
                    if self.phase == "work":
                        self.work_expired = True
                    raise PiccoloError(
                        "Live deadline cannot accommodate Service Usage pacing"
                    )
                time.sleep(delay)
        self.remaining()
        self.last_service_usage = self.clock()

    def remaining(self) -> float:
        """Return the remaining time for this phase, raising before new calls."""
        reserve = {
            "work": CLEANUP_SECONDS,
            "cleanup": INVENTORY_SECONDS,
            "inventory": 0,
        }
        remaining = (
            self.started + self.total_seconds - reserve[self.phase] - self.clock()
        )
        if remaining <= 0:
            if self.phase == "work":
                self.work_expired = True
            raise PiccoloError(
                f"Live-test {self.phase} deadline expired; "
                "retain manifest and report residual resources"
            )
        return remaining

    @contextmanager
    def during(self, phase: Phase) -> Generator[None]:
        """Change phase temporarily without granting a fresh time allowance."""
        previous = self.phase
        self.phase = phase
        try:
            yield
        finally:
            self.phase = previous


def check_work() -> None:
    """Prevent work or cloud mutations after the active phase expires."""
    current = ACTIVE.get()
    if current is not None:
        current.remaining()


def fixture_time_available() -> bool:
    """Skip a new VM fixture when less than two work minutes remain."""
    current = ACTIVE.get()
    if current is not None and current.remaining() < 120:
        current.work_expired = True
        return False
    return True


def timeout(seconds: float = 30) -> float:
    """Bound one in-flight request by the current remaining phase allowance."""
    current = ACTIVE.get()
    return min(seconds, current.remaining()) if current is not None else seconds


@contextmanager
def phase(name: Phase) -> Generator[None]:
    """Enter cleanup or inventory while preserving a single session deadline."""
    current = ACTIVE.get()
    if current is None:
        yield
    else:
        with current.during(name):
            yield


def bounded_rpc(
    method: object,
    *,
    retry_service_read: bool = False,
    pace_service_usage: bool = False,
) -> Callable[..., object]:
    """Wrap a generated SDK transport call, including pager's subsequent calls."""
    call = cast(Callable[..., object], method)

    def invoke(*args: object, **kwargs: object) -> object:
        """Disable retries and recompute remaining time before every RPC."""
        supplied = kwargs.get("timeout")
        seconds = float(supplied) if isinstance(supplied, int | float) else 30.0
        for attempt in range(3):
            current = ACTIVE.get()
            if pace_service_usage and current is not None:
                current.pace_service_usage()
            kwargs["timeout"] = timeout(min(30.0, seconds))
            kwargs["retry"] = None
            try:
                return call(*args, **kwargs)
            except exceptions.ServiceUnavailable:
                if not retry_service_read or attempt == 2:
                    raise
                time.sleep(timeout(0.5 * (attempt + 1)))
        raise PiccoloError("Service Usage read attempts exhausted")

    return invoke


def bind_client(client: object) -> None:
    """Install phase-aware deadlines in the pinned SDK's generated transport map."""
    if ACTIVE.get() is None or client in _BOUND_CLIENTS:
        return
    transport: object = getattr(client, "_transport", None)
    methods: object = getattr(transport, "_wrapped_methods", None)
    if not isinstance(methods, dict):
        raise PiccoloError("SDK client cannot enforce live RPC deadlines")
    mapping = cast(dict[object, object], methods)
    from google.cloud import service_usage_v1

    service_usage = isinstance(client, service_usage_v1.ServiceUsageClient)
    for key, method in mapping.items():
        if not callable(method):
            raise PiccoloError("Unexpected SDK transport method")
        mapping[key] = bounded_rpc(
            method,
            retry_service_read=key == getattr(transport, "get_service", None),
            pace_service_usage=service_usage,
        )
    _BOUND_CLIENTS.add(client)


def bind_clients(clients: Clients) -> None:
    """Bound all services used by the live adapter and its access reconciler."""
    for name in (
        "instances",
        "compute_projects",
        "disks",
        "snapshots",
        "firewalls",
        "networks",
        "subnets",
        "zone_operations",
        "global_operations",
        "projects",
        "folders",
        "organizations",
        "secrets",
        "iam",
        "services",
    ):
        bind_client(getattr(clients, name))


@contextmanager
def live_session() -> Generator[Deadline]:
    """Bound gcloud as well as SDK calls in pytest or the independent janitor."""
    existing = ACTIVE.get()
    if existing is not None:
        yield existing
        return
    from piccolo.providers.gcp.connection import GCloudConnection

    deadline = Deadline(total_seconds=duration_seconds())
    from piccolo.providers.gcp.ssh import SSHTransport

    anchor = os.environ.get("PICCOLO_GCP_LIVE_STARTED_MONOTONIC")
    if anchor is not None:
        try:
            started = float(anchor)
        except ValueError as exc:
            raise PiccoloError(
                "Live-session start must be a monotonic timestamp"
            ) from exc
        if not math.isfinite(started) or started > deadline.started:
            raise PiccoloError(
                "Live-session start must be finite and not in the future"
            )
        deadline.started = started
    token = ACTIVE.set(deadline)
    original_run = GCloudConnection.run
    original_invoke = GCloudConnection.invoke
    original_native = SSHTransport.native_result
    original_native_copy = SSHTransport.native_copy

    def bounded_run(
        self: GCloudConnection,
        arguments: list[str],
        *,
        timeout: int | None = 60,
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Recompute remaining phase time before any gcloud operation."""
        current = ACTIVE.get()
        seconds = min(30.0, float(timeout) if timeout is not None else 30.0)
        if current is not None:
            seconds = min(seconds, current.remaining())
        if seconds < 1:
            raise PiccoloError("Live transport deadline expired")
        return original_run(self, arguments, timeout=int(seconds), capture=capture)

    def bounded_invoke(
        self: GCloudConnection,
        arguments: list[str],
        environment: dict[str, str],
        *,
        timeout: int | None = 60,
        capture: bool = True,
        use_flags: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Include config inspection and recompute after nested identity checks."""
        current = ACTIVE.get()
        seconds = min(30.0, float(timeout) if timeout is not None else 30.0)
        if current is not None:
            seconds = min(seconds, current.remaining())
        if seconds < 1:
            raise PiccoloError("Live transport deadline expired")
        return original_invoke(
            self,
            arguments,
            environment,
            timeout=int(seconds),
            capture=capture,
            use_flags=use_flags,
        )

    def bounded_native(
        self: SSHTransport,
        zone: str,
        command: str | None,
        *,
        timeout: int | None = 60,
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Bound native preparation, REST authorization, and SSH by the live phase."""
        current = ACTIVE.get()
        seconds = float(timeout) if timeout is not None else 120.0
        if current is not None:
            seconds = min(seconds, current.remaining())
        if seconds < 1:
            raise PiccoloError("Live transport deadline expired")
        return original_native(
            self, zone, command, timeout=int(seconds), capture=capture
        )

    def bounded_native_copy(
        self: SSHTransport, zone: str, source: Path, destination: str
    ) -> None:
        """Keep native transfers within the same cumulative approval deadline."""
        current = ACTIVE.get()
        seconds = min(120.0, current.remaining()) if current is not None else 120.0
        if seconds < 1:
            raise PiccoloError("Live transport deadline expired")
        with self.bounded(int(seconds)):
            original_native_copy(self, zone, source, destination)

    try:
        with (
            patch.object(GCloudConnection, "run", bounded_run),
            patch.object(GCloudConnection, "invoke", bounded_invoke),
            patch.object(SSHTransport, "native_result", bounded_native),
            patch.object(SSHTransport, "native_copy", bounded_native_copy),
        ):
            yield deadline
    finally:
        ACTIVE.reset(token)


def duration_seconds() -> int:
    """Read the explicitly approved duration shared by review and execution."""
    try:
        seconds = int(os.environ.get("PICCOLO_GCP_LIVE_SECONDS", str(TOTAL_SECONDS)))
    except ValueError as exc:
        raise PiccoloError("PICCOLO_GCP_LIVE_SECONDS must be an integer") from exc
    if not CLEANUP_SECONDS < seconds <= MAX_SECONDS:
        raise PiccoloError("Live duration must be between 301 and 8700 seconds")
    return seconds
