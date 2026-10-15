# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_live_deadline.py — Offline deadline, inventory, and approval checks."""

import subprocess
import time
from collections.abc import Generator
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from gcp_live_support.deadline import (
    ACTIVE,
    CLEANUP_SECONDS,
    TOTAL_SECONDS,
    Deadline,
    bind_client,
    bounded_rpc,
    fixture_time_available,
    live_session,
    phase,
)
from gcp_live_support.gcp_live import approval_digest, profile, run_config
from gcp_live_support.gcp_sdk import LiveCloud
from gcp_live_support.manifest import Manifest, cleanup, resource_key
from google.api_core import exceptions
from google.auth.credentials import AnonymousCredentials
from google.cloud import compute_v1, secretmanager_v1
from test_gcp_live_safety import RUN, TEST_PROJECT, MemoryBackend

from piccolo.config import Config, load
from piccolo.data import document, objects
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.connection import GCloudConnection


def test_restarted_live_process_preserves_session_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Include prior setup and reruns in the remaining phase allowance."""
    started = time.monotonic() - 200
    monkeypatch.setenv("PICCOLO_GCP_LIVE_STARTED_MONOTONIC", str(started))
    with live_session() as first:
        assert first.started == started
        remaining = first.remaining()
    with live_session() as second:
        assert second.started == started
        assert second.remaining() <= remaining
        # Windows Python 3.12 can observe both calls within one clock tick.
        assert second.remaining() <= TOTAL_SECONDS - CLEANUP_SECONDS - 200


def test_explicit_duration_extension_preserves_anchor_and_changes_approval(
    monkeypatch: pytest.MonkeyPatch,
    config: Config,
) -> None:
    """Bind a reviewed extension to the same start and a new approval digest."""
    original = approval_digest(config)
    started = time.monotonic() - 200
    monkeypatch.setenv("PICCOLO_GCP_LIVE_STARTED_MONOTONIC", str(started))
    monkeypatch.setenv("PICCOLO_GCP_LIVE_SECONDS", "3600")
    assert approval_digest(config) != original
    with live_session() as deadline:
        assert deadline.started == started
        assert deadline.total_seconds == 3600
    monkeypatch.setenv("PICCOLO_GCP_LIVE_SECONDS", "8701")
    with pytest.raises(PiccoloError, match="duration"):
        approval_digest(config)


def test_gcloud_config_inspection_obeys_remaining_deadline(
    monkeypatch: pytest.MonkeyPatch,
    config: Config,
) -> None:
    """Bound direct invocation used before a connection command is constructed."""
    invoke = Mock(return_value=subprocess.CompletedProcess([], 0, "{}", ""))
    monkeypatch.setattr(GCloudConnection, "invoke", invoke)
    with live_session() as deadline:
        now = [deadline.started + TOTAL_SECONDS - CLEANUP_SECONDS - 3]
        deadline.clock = lambda: now[0]
        connection = GCloudConnection(config.gcp)
        connection.invoke(["config", "list"], {}, use_flags=False)
        assert invoke.call_args.kwargs["timeout"] == 3
        now[0] += 3
        with pytest.raises(PiccoloError, match="work deadline"):
            connection.invoke(["config", "list"], {}, use_flags=False)
        assert invoke.call_count == 1


def test_live_process_accepts_negative_monotonic_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept finite anchors below zero because monotonic origins are arbitrary."""
    started = -200.0
    monkeypatch.setenv("PICCOLO_GCP_LIVE_STARTED_MONOTONIC", str(started))
    with live_session() as deadline:
        assert deadline.started == started


@pytest.mark.parametrize("anchor", ["nan", "inf", "-inf", "1e300", "invalid"])
def test_live_process_rejects_invalid_session_start(
    monkeypatch: pytest.MonkeyPatch,
    anchor: str,
) -> None:
    """Reject anchors that disable the deadline or refer to another clock."""
    monkeypatch.setenv("PICCOLO_GCP_LIVE_STARTED_MONOTONIC", anchor)
    with pytest.raises(PiccoloError, match="start must be"), live_session():
        pytest.fail("Invalid start was accepted")


@pytest.fixture
def active_deadline() -> Generator[tuple[Deadline, list[float]]]:
    now = [0.0]
    deadline = Deadline(clock=lambda: now[0])
    token = ACTIVE.set(deadline)
    try:
        yield deadline, now
    finally:
        ACTIVE.reset(token)


def test_rpc_deadline_blocks_new_work_and_reserves_cleanup(
    active_deadline: tuple[Deadline, list[float]],
) -> None:
    deadline, now = active_deadline
    transport = Mock(return_value="accepted")
    rpc = bounded_rpc(transport)
    now[0] = TOTAL_SECONDS - CLEANUP_SECONDS - 5
    assert rpc(timeout=30, retry="retry") == "accepted"
    assert transport.call_args.kwargs == {"timeout": 5, "retry": None}
    now[0] += 5
    with pytest.raises(PiccoloError, match="work deadline"):
        rpc()
    assert transport.call_count == 1
    with phase("cleanup"):
        assert rpc() == "accepted"
    assert deadline.phase == "work"
    now[0] = TOTAL_SECONDS
    with phase("inventory"), pytest.raises(PiccoloError, match="inventory deadline"):
        rpc()


def test_transient_service_read_retry_rechecks_deadline(
    active_deadline: tuple[Deadline, list[float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Retry only selected idempotent reads without resetting the phase budget."""
    _, now = active_deadline
    method = Mock(side_effect=[exceptions.ServiceUnavailable("temporary"), "available"])

    def advance(delay: float) -> None:
        """Advance the fixture clock for a bounded retry delay."""
        now[0] += delay

    monkeypatch.setattr("gcp_live_support.deadline.time.sleep", advance)
    rpc = bounded_rpc(method, retry_service_read=True)
    now[0] = TOTAL_SECONDS - CLEANUP_SECONDS - 5
    assert rpc() == "available"
    assert method.call_args.kwargs == {"timeout": 4.5, "retry": None}
    method.reset_mock(side_effect=True)
    method.side_effect = exceptions.ServiceUnavailable("temporary")
    now[0] = TOTAL_SECONDS - CLEANUP_SECONDS - 0.25
    with pytest.raises(PiccoloError, match="work deadline"):
        rpc()
    assert method.call_count == 1


def test_service_usage_pacing_is_shared_and_covers_retry_attempts(
    active_deadline: tuple[Deadline, list[float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Space independent clients and retry attempts by at least 1.05 seconds."""
    _, now = active_deadline
    starts: list[float] = []
    sleeps: list[float] = []

    def sleep(delay: float) -> None:
        sleeps.append(delay)
        now[0] += delay

    def read(**kwargs: object) -> str:
        del kwargs
        starts.append(now[0])
        if len(starts) == 3:
            raise exceptions.ServiceUnavailable("temporary")
        return "enabled"

    monkeypatch.setattr("gcp_live_support.deadline.time.sleep", sleep)
    first = bounded_rpc(read, pace_service_usage=True, retry_service_read=True)
    second = bounded_rpc(read, pace_service_usage=True, retry_service_read=True)
    assert first() == "enabled"
    assert second() == "enabled"
    assert first() == "enabled"
    assert starts == pytest.approx([0, 1.05, 2.10, 3.15])
    assert sum(sleeps) == pytest.approx(3.15)


def test_service_usage_pacing_refuses_a_call_without_time_for_its_delay(
    active_deadline: tuple[Deadline, list[float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leave the cleanup reserve intact instead of sleeping past the work limit."""
    deadline, now = active_deadline
    method = Mock(return_value="enabled")
    sleeper = Mock()
    monkeypatch.setattr("gcp_live_support.deadline.time.sleep", sleeper)
    now[0] = TOTAL_SECONDS - CLEANUP_SECONDS - 0.5
    rpc = bounded_rpc(method, pace_service_usage=True)
    assert rpc() == "enabled"
    with pytest.raises(PiccoloError, match="pacing"):
        rpc()
    assert method.call_count == 1
    assert deadline.work_expired
    sleeper.assert_not_called()


def test_short_remaining_work_skips_new_fixtures_and_marks_matrix_incomplete(
    active_deadline: tuple[Deadline, list[float]],
) -> None:
    """Stop before new provisioning while keeping time for current cleanup."""
    deadline, now = active_deadline
    now[0] = TOTAL_SECONDS - CLEANUP_SECONDS - 120
    assert fixture_time_available()
    now[0] += 1
    assert not fixture_time_available()
    assert deadline.work_expired
    with phase("cleanup"):
        assert deadline.remaining() == 359


@pytest.mark.parametrize("error", [exceptions.ServiceUnavailable, exceptions.Forbidden])
def test_mutations_never_retry_after_service_or_permission_failure(
    error: type[exceptions.GoogleAPICallError],
) -> None:
    """Leave mutating transports uncertain or rejected after their single attempt."""
    method = Mock(side_effect=error("failure"))
    with pytest.raises(error):
        bounded_rpc(method)()
    assert method.call_count == 1


def test_only_service_usage_get_transport_retries_503(
    active_deadline: tuple[Deadline, list[float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise the pinned REST transport map without retrying its enable mutation."""
    from google.cloud import service_usage_v1

    del active_deadline
    monkeypatch.setattr("gcp_live_support.deadline.time.sleep", Mock(return_value=None))
    client = service_usage_v1.ServiceUsageClient(
        credentials=AnonymousCredentials(), transport="rest"
    )
    read = Mock(
        side_effect=[
            exceptions.ServiceUnavailable("temporary"),
            service_usage_v1.Service(state=service_usage_v1.State.ENABLED),
        ]
    )
    write = Mock(side_effect=exceptions.ServiceUnavailable("uncertain write"))
    client._transport._wrapped_methods[client._transport.get_service] = read
    client._transport._wrapped_methods[client._transport.enable_service] = write
    bind_client(client)
    assert (
        client.get_service(
            request=service_usage_v1.GetServiceRequest(
                name="projects/123/services/compute.googleapis.com"
            )
        ).state
        == service_usage_v1.State.ENABLED
    )
    assert read.call_count == 2
    with pytest.raises(exceptions.ServiceUnavailable):
        client.enable_service(
            request=service_usage_v1.EnableServiceRequest(
                name="projects/123/services/compute.googleapis.com"
            )
        )
    assert write.call_count == 1


def test_expired_session_skips_before_fixture_setup_and_fails_the_run(
    active_deadline: tuple[Deadline, list[float]],
) -> None:
    from conftest import LIVE_DEADLINE, pytest_runtest_setup, pytest_sessionfinish

    deadline, now = active_deadline
    now[0] = TOTAL_SECONDS - CLEANUP_SECONDS
    item = Mock(spec=pytest.Item)
    item.config = Mock()
    item.config.stash = {LIVE_DEADLINE: deadline}
    item.config.getoption.return_value = True
    item.get_closest_marker.return_value = pytest.mark.gcp_live
    with pytest.raises(pytest.skip.Exception, match="work deadline"):
        pytest_runtest_setup(item)
    session = Mock(spec=pytest.Session)
    session.config = item.config
    session.exitstatus = pytest.ExitCode.OK
    pytest_sessionfinish(session)
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


def test_pinned_sdk_pager_checks_deadline_before_next_page(
    active_deadline: tuple[Deadline, list[float]],
) -> None:
    _, now = active_deadline
    clients = Clients(AnonymousCredentials())
    transport = clients.disks._transport
    call = Mock(
        return_value=compute_v1.DiskList(
            items=[compute_v1.Disk(name="first")], next_page_token="second"
        )
    )
    transport._wrapped_methods[transport.list] = call
    bind_client(clients.disks)
    pager = clients.disks.list(project="test-project", zone="us-west1-a")
    iterator = iter(pager)
    assert next(iterator).name == "first"
    now[0] = TOTAL_SECONDS - CLEANUP_SECONDS
    with pytest.raises(PiccoloError, match="work deadline"):
        next(iterator)
    assert call.call_count == 1


def test_live_and_janitor_sessions_bound_transport_and_restore_context(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(GCloudConnection, "run", transport)
    connection = GCloudConnection(config.gcp)
    with live_session() as deadline:
        now = [deadline.started + TOTAL_SECONDS - CLEANUP_SECONDS - 3]
        deadline.clock = lambda: now[0]
        connection.run(["auth", "list"])
        assert transport.call_args.kwargs["timeout"] == 3
        now[0] += 3
        with pytest.raises(PiccoloError, match="work deadline"):
            connection.run(["auth", "list"])
        assert transport.call_count == 1
        with phase("cleanup"):
            connection.run(["auth", "list"], timeout=10)
        assert transport.call_args.kwargs["timeout"] == 10
        with live_session() as nested:
            assert nested is deadline
    assert ACTIVE.get() is None


def test_shorter_live_session_preserves_cleanup_reserve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Narrow a subsequent run without resetting its cleanup allowance."""
    monkeypatch.setenv("PICCOLO_GCP_LIVE_SECONDS", "400")
    with live_session() as deadline:
        deadline.clock = lambda: deadline.started
        assert deadline.remaining() == pytest.approx(100)
        with phase("cleanup"):
            assert deadline.remaining() == pytest.approx(340)
        with phase("inventory"):
            assert deadline.remaining() == pytest.approx(400)


@pytest.mark.parametrize("duration", ["0", "300", "8701", "-1", "invalid"])
def test_live_session_rejects_invalid_or_extended_duration(
    monkeypatch: pytest.MonkeyPatch, duration: str
) -> None:
    """Reject invalid durations and attempts to extend the approved maximum."""
    monkeypatch.setenv("PICCOLO_GCP_LIVE_SECONDS", duration)
    with pytest.raises(PiccoloError), live_session():
        pytest.fail("Invalid deadline was accepted")


def make_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config: Config
) -> Manifest:
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", TEST_PROJECT)
    return Manifest.create(
        tmp_path / "run" / "manifest.json", config.path, RUN, project=TEST_PROJECT
    )


def test_failed_cleanup_still_reports_leftovers_and_unverified_inventory(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = make_manifest(tmp_path, monkeypatch, config)
    backend = MemoryBackend(manifest)
    name = f"{RUN}-disk"
    entry = manifest.register("disk", name, "us-west1-a", {})
    entry["id"] = "42"
    manifest.put("resources", entry)
    backend.resources[resource_key("disk", name, "us-west1-a")] = {
        "id": "42",
        "name": name,
        "zone": "us-west1-a",
        "run": RUN,
        "status": "READY",
    }
    manifest.intent("disk.insert", name, "us-west1-a")
    backend.pending = True
    backend.fail_inventory = "instance"
    assert cleanup(manifest, backend, apply=True)
    report = document(Manifest.open(manifest.path).data["residual_cost_exposure"])
    assert report["dollar_limit_enforced"] is False
    assert report["unverified_inventory"] == ["instance"]
    assert objects(report, "remaining_resources")[0]["id"] == "42"
    assert report["unverified_cleanup"]
    assert not manifest.data["complete"]


def test_expired_cleanup_reports_unknowns_without_cloud_calls(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    active_deadline: tuple[Deadline, list[float]],
) -> None:
    manifest = make_manifest(tmp_path, monkeypatch, config)
    backend = MemoryBackend(manifest)
    inventory = Mock(side_effect=AssertionError("Expired inventory must not call GCP"))
    monkeypatch.setattr(backend, "inventory", inventory)
    _, now = active_deadline
    now[0] = TOTAL_SECONDS
    assert cleanup(manifest, backend, apply=True)
    inventory.assert_not_called()
    report = document(manifest.data["residual_cost_exposure"])
    inventory = report["unverified_inventory"]
    assert isinstance(inventory, list)
    assert len(inventory) == 7
    assert "recoverable_snapshot" in inventory
    assert not manifest.data["complete"]


def test_approval_digest_rejects_changed_settings_locally(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", config.gcp.project_id)
    base = replace(
        config,
        gcp=replace(
            config.gcp, enable_apis=False, connection_account="owner@example.com"
        ),
    )
    generated = run_config(base, tmp_path / "generated", RUN, create_account=False)
    content = generated.path.read_text()
    generated.path.write_text(
        content[: content.index("[bootstrap]")] + content[content.index("[gcp]") :]
    )
    approved = load(generated.path)
    with pytest.raises(PiccoloError, match="APPROVAL_SHA256"):
        profile(generated.path)
    monkeypatch.setenv("PICCOLO_GCP_LIVE_APPROVAL_SHA256", approval_digest(approved))
    assert profile(generated.path).fingerprint == approved.fingerprint
    generated.path.write_text(
        generated.path.read_text().replace("n2-standard-4", "n2-standard-8")
    )
    with pytest.raises(PiccoloError, match="APPROVAL_SHA256"):
        profile(generated.path)


@pytest.mark.parametrize(
    "label,payload",
    [(False, b"TEST_thisisadummytestsecret_TEST"), (True, b"not-the-dummy-payload")],
)
def test_existing_secret_is_verified_before_any_guest_grant(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    label: bool,
    payload: bytes,
) -> None:
    manifest = make_manifest(tmp_path, monkeypatch, config)
    approved = replace(
        config,
        environment=RUN,
        gcp=replace(
            config.gcp,
            project_id=TEST_PROJECT,
            enable_apis=False,
            secrets=("approved-secret",),
        ),
    )
    clients = Clients(AnonymousCredentials())
    cloud = LiveCloud(approved, clients, manifest)
    monkeypatch.setattr(
        cloud,
        "get",
        Mock(
            return_value={
                "id": "42",
                "name": f"projects/{TEST_PROJECT}/secrets/approved-secret",
                "labels": {"piccolo-live-dummy": "true"} if label else {},
            }
        ),
    )
    reader = Mock(
        return_value=secretmanager_v1.AccessSecretVersionResponse(
            name=f"projects/{TEST_PROJECT}/secrets/approved-secret/versions/1",
            payload=secretmanager_v1.SecretPayload(data=payload),
        )
    )
    monkeypatch.setattr(clients.secrets, "access_secret_version", reader)
    writer = Mock(side_effect=AssertionError("No grant is allowed"))
    monkeypatch.setattr(clients.secrets, "set_iam_policy", writer)
    with pytest.raises(PiccoloError, match="dummy"):
        cloud.preserve_external("secret", "approved-secret")
    assert not manifest.entries("external_resources")
    assert not manifest.entries("bindings")
    writer.assert_not_called()
    assert reader.call_count == int(label)


@pytest.mark.parametrize("project_name", [TEST_PROJECT, "123456789"])
def test_dummy_version_matches_returned_canonical_secret_identity(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    project_name: str,
) -> None:
    manifest = make_manifest(tmp_path, monkeypatch, config)
    approved = replace(
        config,
        environment=RUN,
        gcp=replace(
            config.gcp,
            project_id=TEST_PROJECT,
            enable_apis=False,
            secrets=("approved-secret",),
        ),
    )
    clients = Clients(AnonymousCredentials())
    cloud = LiveCloud(approved, clients, manifest)
    canonical = f"projects/{project_name}/secrets/approved-secret"
    monkeypatch.setattr(
        cloud,
        "get",
        Mock(
            return_value={
                "id": "42",
                "name": canonical,
                "labels": {"piccolo-live-dummy": "true"},
            }
        ),
    )
    reader = Mock(
        return_value=secretmanager_v1.AccessSecretVersionResponse(
            name=f"{canonical}/versions/3",
            payload=secretmanager_v1.SecretPayload(
                data=b"TEST_thisisadummytestsecret_TEST"
            ),
        )
    )
    monkeypatch.setattr(clients.secrets, "access_secret_version", reader)
    cloud.preserve_external("secret", "approved-secret")
    entry = manifest.lookup("secret", "approved-secret")
    assert entry is not None and entry["dummy_version"] == f"{canonical}/versions/3"
