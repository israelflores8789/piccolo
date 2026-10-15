# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""conftest.py — Isolated configuration, fake cloud, and local guest fixtures."""

import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Generator
from pathlib import Path

import pytest
from gcp_live_support.deadline import Deadline, live_session
from platform_support import guest_bash

from piccolo.config import Config, load
from piccolo.config.models import GCP
from piccolo.data import Document, document, objects, text
from piccolo.errors import PiccoloError, UncertainError
from piccolo.providers.gcp.connection import GCloudConnection

LIVE_DEADLINE = pytest.StashKey[Deadline]()


@pytest.fixture(autouse=True)
def gcloud_transport_backend(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Retain POSIX gcloud regression tests; native transport has its own suite."""
    if request.module.__name__ not in {
        "test_connection",
        "test_gcloud_connection",
        "test_ssh_expiry",
    }:
        return
    original = GCloudConnection.__init__

    def initialise(
        self: GCloudConnection,
        config: GCP,
        target: Callable[[str], Document] | None = None,
        host_keys: Callable[[str], Document] | None = None,
    ) -> None:
        original(self, config, target, host_keys)
        self.windows = False

    monkeypatch.setattr(GCloudConnection, "__init__", initialise)


@pytest.fixture(scope="session", autouse=True)
def live_deadline(request: pytest.FixtureRequest) -> Generator[None]:
    """Apply one cooperative deadline and transport bounds only for live runs."""
    if not (
        request.config.getoption("--gcp-live")
        or request.config.getoption("--gcp-win-live")
    ):
        yield
        return
    with live_session() as deadline:
        request.config.stash[LIVE_DEADLINE] = deadline
        yield


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    """Skip subsequent live tests before fixtures when the work deadline expires."""
    if (
        item.get_closest_marker("gcp_live") or item.get_closest_marker("gcp_win_live")
    ) and (
        item.config.getoption("--gcp-live") or item.config.getoption("--gcp-win-live")
    ):
        current = item.config.stash.get(LIVE_DEADLINE, None)
        if current is not None:
            try:
                current.remaining()
            except PiccoloError as exc:
                pytest.skip(str(exc))


def pytest_sessionfinish(session: pytest.Session) -> None:
    """Return failure when the deadline leaves part of the live matrix unrun."""
    current = session.config.stash.get(LIVE_DEADLINE, None)
    if (
        current is not None
        and current.work_expired
        and session.exitstatus == pytest.ExitCode.OK
    ):
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


CONFIG = """schema_version = 1
environment = "test-env"
provider = "gcp"
[gcp]
project_id = "test-project"
[gcp.instance]
name = "test-vm"
machine_type = "n2-standard-4"
service_account = "test-vm@test-project.iam.gserviceaccount.com"
[gcp.placement]
zones = ["us-west1-a", "us-east1-b", "us-east1-c"]
[gcp.disk]
image = "projects/debian-cloud/global/images/debian-13"
[gcp.ssh]
user = "researcher"
"""


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--gcp-win-live",
        action="store_true",
        default=False,
        help="Explicitly select the gated native Windows GCP suite",
    )
    parser.addoption(
        "--gcp-live",
        action="store_true",
        default=False,
        help="Explicitly select the gated disposable-project GCP suite",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.getoption("--gcp-live") and config.getoption("--gcp-win-live"):
        raise pytest.UsageError("Select --gcp-live or --gcp-win-live separately")
    if not config.getoption("--gcp-win-live"):
        for item in items:
            if item.get_closest_marker("gcp_win_live"):
                item.add_marker(
                    pytest.mark.skip(reason="requires explicit --gcp-win-live")
                )
    if not config.getoption("--gcp-live"):
        for item in items:
            if item.get_closest_marker("gcp_live"):
                item.add_marker(pytest.mark.skip(reason="requires explicit --gcp-live"))


@pytest.fixture(autouse=True)
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PICCOLO_STATE_DIR", str(tmp_path / "state"))


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    path = tmp_path / "piccolo.toml"
    path.write_text(CONFIG)
    return path


@pytest.fixture
def config(config_path: Path) -> Config:
    return load(config_path)


class FakeCloud:
    def __init__(self) -> None:
        self.resources: dict[tuple[str, str, str], Document] = {}
        self.operations: dict[str, Document] = {}
        self.requests: dict[str, str] = {}
        self.recovery_calls: list[tuple[str, str]] = []
        self.calls: list[tuple[str, str, str, str]] = []
        self.errors: dict[tuple[str, str], str] = {}
        self.uncertain: set[tuple[str, str]] = set()
        self.lost_response: set[tuple[str, str]] = set()
        self.crash_poll = False
        self.metadata: Document = {}
        self.access_calls = 0
        self.sequence = 100

    def get(self, kind: str, name: str, zone: str = "") -> Document | None:
        resource = self.resources.get((kind, name, zone))
        return document(resource) if resource else None

    def list(self, kind: str) -> list[Document]:
        return [
            document(item)
            for (resource_kind, _, _), item in self.resources.items()
            if resource_kind == kind
        ]

    def submit(
        self, kind: str, name: str, zone: str, resource: Document, request_id: str
    ) -> str:
        self.calls.append((kind, name, zone, request_id))
        if (kind, zone) in self.uncertain:
            raise UncertainError("Injected lost submission outcome")
        operation_id = f"op-{len(self.calls)}"
        self.requests[request_id] = operation_id
        error = self.errors.get((kind, zone))
        if error:
            self.operations[operation_id] = {
                "status": "DONE",
                "error": {"errors": [{"code": error, "message": "injected failure"}]},
            }
        else:
            self.operations[operation_id] = {"status": "DONE"}
            self.mutate(kind, name, zone, resource)
            if kind.endswith(".insert"):
                self.operations[operation_id]["target_id"] = self.resources[
                    (kind.split(".")[0], name, zone)
                ]["id"]
        if (kind, zone) in self.lost_response:
            self.lost_response.remove((kind, zone))
            raise UncertainError("Injected disconnect after cloud acceptance")
        return operation_id

    def mutate(self, kind: str, name: str, zone: str, resource: Document) -> None:
        resource_kind, action = kind.split(".")
        key = (resource_kind, name, zone)
        if action == "insert":
            self.sequence += 1
            created = document(resource)
            created.update(
                {
                    "name": name,
                    "id": str(self.sequence),
                    "status": "RUNNING" if resource_kind == "instance" else "READY",
                    "self_link": (
                        f"projects/test-project/zones/{zone}/{resource_kind}s/{name}"
                    ),
                }
            )
            if zone:
                created["zone"] = f"projects/test-project/zones/{zone}"
            if resource_kind == "disk":
                created["users"] = []
                snapshot_name = text(created, "source_snapshot").split("/")[-1]
                if snapshot_name:
                    created["source_snapshot_id"] = self.resources[
                        ("snapshot", snapshot_name, "")
                    ]["id"]
                    created["contents"] = self.resources[
                        ("snapshot", snapshot_name, "")
                    ].get("contents", "")
            if resource_kind == "instance":
                disk = objects(created, "disks")[0]
                disk_key = ("disk", text(disk, "source").split("/")[-1], zone)
                self.resources[disk_key]["users"] = [text(created, "self_link")]
            if resource_kind == "snapshot":
                source = text(created, "source_disk")
                source_zone = source.split("/zones/")[1].split("/")[0]
                source_disk = source.split("/")[-1]
                assert (
                    self.resources[("instance", "test-vm", source_zone)]["status"]
                    == "TERMINATED"
                )
                created["source_disk_id"] = self.resources[
                    ("disk", source_disk, source_zone)
                ]["id"]
                created["contents"] = self.resources[
                    ("disk", source_disk, source_zone)
                ].get("contents", "")
            self.resources[key] = created
        elif action in {"start", "stop"}:
            self.resources[key]["status"] = (
                "RUNNING" if action == "start" else "TERMINATED"
            )
        elif action == "protect":
            disks = objects(self.resources[key], "disks")
            disks[0]["auto_delete"] = False
            self.resources[key]["disks"] = disks
        elif action == "delete":
            existing = self.resources.pop(key, None)
            if resource_kind == "instance" and existing:
                disk = objects(existing, "disks")[0]
                disk_key = ("disk", text(disk, "source").split("/")[-1], zone)
                self.resources[disk_key]["users"] = []

    def poll(self, name: str, zone: str) -> Document:
        if self.crash_poll:
            raise UncertainError(f"Cannot observe {name} in {zone}")
        return self.operations[name]

    def recover(self, request_id: str, zone: str) -> str:
        self.recovery_calls.append((request_id, zone))
        return self.requests.get(request_id, "")

    def access(self) -> None:
        self.access_calls += 1

    def access_plan(self) -> Document:
        return {"apis": [], "service_account": {"exists": True}}

    def subnet(self, zone: str) -> str:
        region = zone.rsplit("-", 1)[0]
        return f"projects/test-project/regions/{region}/subnetworks/default"

    def move_policy(self, instance: Document, disk: Document) -> None:
        pass

    def connection_policy(self, instance: Document) -> None:
        pass

    def host_keys(self, zone: str) -> Document:
        del zone
        return {}

    def permission_denied(self, kind: str, detail: str = "") -> PiccoloError:
        return PiccoloError(f"GCP permission denied for {kind}: {detail}")

    def project_metadata(self) -> Document:
        return self.metadata


class GuestConnection:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.bash = guest_bash()
        self.guest_home = str(directory)
        if sys.platform == "win32":
            converted = subprocess.run(
                [str(Path(self.bash).with_name("cygpath.exe")), "-u", str(directory)],
                text=True,
                capture_output=True,
                check=True,
            )
            self.guest_home = converted.stdout.strip()
        directory.mkdir(parents=True, exist_ok=True)
        self.commands: list[str] = []
        self.copies = 0
        self.copy_zones: list[str] = []
        self.readiness_failure = False
        self.launch_failure = False

    def ready(self, zone: str) -> None:
        if self.readiness_failure:
            raise PiccoloError(f"SSH unavailable in {zone}")

    def execute(self, zone: str, command: str, timeout: int = 60) -> str:
        if command == "command -v setsid >/dev/null" and sys.platform != "linux":
            pytest.skip("Detached guest runner needs Linux setsid and /proc/self/fd")
        self.commands.append(command)
        if self.launch_failure and "nohup" in command:
            raise PiccoloError(f"Connection interrupted in {zone}")
        guest_command = command.replace('"$HOME"', shlex.quote(self.guest_home))
        result = subprocess.run(
            [self.bash, "-x", "-c", guest_command],
            cwd=self.directory,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
            env={**os.environ, "HOME": self.guest_home},
        )
        if result.returncode:
            raise PiccoloError(
                f"Local guest emulation failed in {zone} (exit {result.returncode})\n"
                f"Shell: {self.bash}\n"
                f"Command: {guest_command}\n"
                f"stdout: {result.stdout.strip() or '<empty>'}\n"
                f"stderr (Bash trace):\n{result.stderr.strip() or '<empty>'}"
            )
        return result.stdout.strip()

    def copy(self, zone: str, source: Path, destination: str) -> None:
        self.copy_zones.append(zone)
        target = self.directory / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        self.copies += 1

    def shell(self, zone: str) -> None:
        self.commands.append(f"shell:{zone}")

    def tunnel(self, zone: str) -> None:
        self.commands.append(f"tunnel:{zone}")


@pytest.fixture
def cloud() -> FakeCloud:
    return FakeCloud()


@pytest.fixture
def connection(tmp_path: Path) -> GuestConnection:
    return GuestConnection(tmp_path / "guest")
