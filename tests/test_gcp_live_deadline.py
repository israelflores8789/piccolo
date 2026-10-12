# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_live_deadline.py — Offline deadline, inventory, and approval checks."""

import subprocess
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
    live_session,
    phase,
)
from gcp_live_support.gcp_live import approval_digest, profile, run_config
from gcp_live_support.gcp_sdk import LiveCloud
from gcp_live_support.manifest import Manifest, cleanup, resource_key
from google.auth.credentials import AnonymousCredentials
from google.cloud import compute_v1, secretmanager_v1
from test_gcp_live_safety import RUN, TEST_PROJECT, MemoryBackend

from piccolo.config import Config, load
from piccolo.data import document, objects
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.connection import GCloudConnection


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
    assert len(report["unverified_inventory"]) == 6
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
