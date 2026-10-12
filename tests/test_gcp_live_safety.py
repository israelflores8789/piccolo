# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_live_safety.py — Offline interruption, ownership, and janitor failures.

Live use requires PICCOLO_GCP_LIVE_PROJECT; offline fixtures set it locally.
"""

import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from gcp_live_support.gcp_live import (
    approval_digest,
    local_preflight,
    preflight,
    profile,
    provisioner_identity,
    run_config,
)
from gcp_live_support.gcp_sdk import LiveAccess, LiveCloud
from gcp_live_support.manifest import (
    Manifest,
    approved_project,
    cleanup,
    gate,
    resource_key,
)
from google.api_core import exceptions
from google.auth.credentials import AnonymousCredentials
from google.cloud import compute_v1, iam_admin_v1, resourcemanager_v3, service_usage_v1
from google.iam.v1 import iam_policy_pb2, policy_pb2

from piccolo.config import Config, load
from piccolo.data import Document, document, objects, text
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.connection import GCloudConnection
from piccolo.providers.gcp.provision import labels
from piccolo.providers.gcp.resources import READ_RETRY

TEST_PROJECT = "piccolo-offline-tests"
RUN = "plive-0123456789abcdef"
ZONE = "us-west1-a"


@pytest.fixture
def approved(monkeypatch: pytest.MonkeyPatch, config: Config) -> Config:
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", TEST_PROJECT)
    return replace(
        config,
        environment=RUN,
        gcp=replace(
            config.gcp,
            project_id=TEST_PROJECT,
            name=f"{RUN}-vm",
            auth=replace(
                config.gcp.auth,
                impersonate_service_account=f"provisioner@{TEST_PROJECT}.iam.gserviceaccount.com",
            ),
            service_account=f"{RUN}-vm@{TEST_PROJECT}.iam.gserviceaccount.com",
            connection_account="owner@example.com",
            enable_apis=False,
        ),
    )


@pytest.fixture
def manifest(tmp_path: Path, approved: Config) -> Manifest:
    return Manifest.create(
        tmp_path / "run" / "manifest.json",
        approved.path,
        RUN,
        project=approved.gcp.project_id,
    )


class MemoryBackend:
    def __init__(self, manifest: Manifest) -> None:
        self.manifest = manifest
        self.resources: dict[str, Document] = {}
        self.deleted: list[str] = []
        self.bindings_removed: list[str] = []
        self.ssh_keys_removed: list[str] = []
        self.pending = False
        self.fail_delete = ""
        self.fail_inventory = ""
        self.interrupt_delete = False
        self.read_failure = False

    def get(self, kind: str, name: str, zone: str = "") -> Document | None:
        if self.read_failure:
            raise PiccoloError("Injected denied read")
        return self.resources.get(resource_key(kind, name, zone))

    def inventory(self, kind: str) -> list[Document]:
        if kind == self.fail_inventory:
            raise PiccoloError("Injected incomplete inventory")
        return [
            document(r)
            for key, r in self.resources.items()
            if key.startswith(f"{kind}:")
        ]

    def settle(self, action: Document) -> bool:
        if self.pending:
            return False
        action["settled"] = True
        self.manifest.put("actions", action)
        return True

    def owns(self, entry: Document, observed: Document) -> bool:
        return entry.get("id") == observed.get("id") and observed.get("run") == RUN

    def delete(self, entry: Document) -> None:
        if self.interrupt_delete:
            raise KeyboardInterrupt
        key = text(entry, "key")
        if text(entry, "kind") == self.fail_delete:
            raise PiccoloError("Injected deletion failure")
        self.deleted.append(key)
        self.resources.pop(key)

    def remove_binding(self, entry: Document) -> None:
        self.bindings_removed.append(text(entry, "key"))

    def remove_ssh_key(self, entry: Document) -> None:
        self.ssh_keys_removed.append(text(entry, "key"))

    def purge_snapshots(self) -> None:
        """Represent a backend with no recoverable snapshots."""
        return

    def add(self, kind: str, suffix: str, *, zone: str = "") -> Document:
        name = f"{RUN}-{suffix}"
        entry = self.manifest.register(kind, name, zone, {"run": RUN})
        entry["id"] = suffix
        self.manifest.put("resources", entry)
        self.resources[text(entry, "key")] = {
            "id": suffix,
            "name": name,
            "run": RUN,
            "users": [],
            "disks": [],
        }
        return entry


@pytest.mark.parametrize(
    "opt_in,env_project,config_project",
    [
        ("0", TEST_PROJECT, TEST_PROJECT),
        ("true", TEST_PROJECT, TEST_PROJECT),
        ("1", "other-project", TEST_PROJECT),
        ("1", TEST_PROJECT, "other-project"),
        ("1", TEST_PROJECT + " ", TEST_PROJECT),
        ("1", "", TEST_PROJECT),
        ("1", "123456789", TEST_PROJECT),
        ("1", "projects/other-project", TEST_PROJECT),
    ],
)
def test_gate_requires_exact_approval(
    monkeypatch: pytest.MonkeyPatch,
    opt_in: str,
    env_project: str,
    config_project: str,
) -> None:
    monkeypatch.setenv("PICCOLO_GCP_LIVE", opt_in)
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", env_project)
    with pytest.raises(PiccoloError, match="exact project"):
        gate(config_project)


def test_missing_project_has_no_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PICCOLO_GCP_LIVE_PROJECT", raising=False)
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    with pytest.raises(PiccoloError, match="Set PICCOLO_GCP_LIVE_PROJECT"):
        gate(TEST_PROJECT)


def test_metadata_regression_write_is_scoped_and_journaled(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients = Clients(AnonymousCredentials())
    cloud = LiveCloud(approved, clients, manifest)
    entry = manifest.register(
        "instance", approved.gcp.name, ZONE, {"labels": labels(approved)}
    )
    entry["id"] = "123"
    manifest.put("resources", entry)
    instance: Document = {
        "id": "123",
        "labels": labels(approved),
        "metadata": {"fingerprint": "original-fingerprint", "items": []},
    }
    monkeypatch.setattr(cloud, "get", Mock(return_value=instance))
    setter = Mock(return_value=Mock())
    setter.return_value.name = "metadata-operation"
    monkeypatch.setattr(clients.instances, "set_metadata", setter)
    monkeypatch.setattr(cloud, "poll", Mock(return_value={"status": "DONE"}))
    cloud.set_metadata(ZONE, "123", [{"key": "shutdown-script", "value": "true"}])
    request = setter.call_args.kwargs["request"]
    assert request.project == approved.gcp.project_id
    assert request.instance == approved.gcp.name
    assert request.zone == ZONE
    assert request.metadata_resource.fingerprint == "original-fingerprint"
    assert setter.call_args.kwargs["retry"] is None
    action = manifest.entries("actions")[-1]
    assert action["key"] == request.request_id
    assert action["operation"] == "metadata-operation"
    assert action["settled"] is True
    with pytest.raises(PiccoloError, match="unproven"):
        cloud.set_metadata(ZONE, "replacement-id", [])
    assert setter.call_count == 1


@pytest.mark.parametrize("project", ["downstream-test-alpha", "downstream-test-beta"])
def test_downstream_project_is_used_for_config_manifest_and_urls(
    approved: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    project: str,
) -> None:
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", project)
    assert approved_project() == project
    gate(project)
    base = replace(
        approved,
        gcp=replace(
            approved.gcp,
            project_id=project,
            auth=replace(
                approved.gcp.auth,
                impersonate_service_account=f"provisioner@{project}.iam.gserviceaccount.com",
            ),
        ),
    )
    generated = run_config(base, tmp_path / "generated", RUN, create_account=True)
    assert (
        generated.gcp.service_account == f"{RUN}-vm@{project}.iam.gserviceaccount.com"
    )
    manifest = Manifest.create(
        tmp_path / "manifest.json",
        generated.path,
        RUN,
        project=project,
    )
    entry = manifest.register("disk", f"{RUN}-boot", ZONE, {"run": RUN})
    durable = Manifest.open(manifest.path)
    assert durable.data["project"] == project
    assert f"/projects/{project}/" in text(entry, "url")


def test_changed_approval_cannot_retarget_manifest_or_cleanup(
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", "downstream-other-project")
    reopened = Manifest.open(manifest.path)
    entry = reopened.register("disk", f"{RUN}-boot", ZONE, {"run": RUN})
    assert reopened.data["project"] == TEST_PROJECT
    assert f"/projects/{TEST_PROJECT}/" in text(entry, "url")
    backend = MemoryBackend(reopened)
    with pytest.raises(PiccoloError, match="exact project"):
        cleanup(reopened, backend, apply=True)
    assert not backend.deleted


def test_manifest_creation_rejects_unapproved_target_before_writing(
    approved: Config,
    tmp_path: Path,
) -> None:
    path = tmp_path / "other-project" / "manifest.json"
    with pytest.raises(PiccoloError, match="exact project"):
        Manifest.create(path, approved.path, RUN, project="downstream-other-project")
    assert not path.exists()


def test_cloud_adapter_rejects_project_manifest_mismatch(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = "downstream-other-project"
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", project)
    config = replace(approved, gcp=replace(approved.gcp, project_id=project))
    with pytest.raises(PiccoloError, match="matching project/run"):
        LiveCloud(config, Clients(AnonymousCredentials()), manifest)


def test_changed_approval_blocks_mutation_after_adapter_creation(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients = Clients(AnonymousCredentials())
    cloud = LiveCloud(approved, clients, manifest)
    getter, insert = Mock(), Mock()
    monkeypatch.setattr(clients.disks, "get", getter)
    monkeypatch.setattr(clients.disks, "insert", insert)
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", "downstream-other-project")
    with pytest.raises(PiccoloError, match="exact project"):
        cloud.submit("disk.insert", f"{RUN}-boot", ZONE, {}, "request")
    getter.assert_not_called()
    insert.assert_not_called()
    assert not manifest.entries("actions")


def test_existing_secret_target_is_preserved_and_requires_exact_identity(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = replace(
        approved, gcp=replace(approved.gcp, secrets=("approved-secret",))
    )
    cloud = LiveCloud(approved, Clients(AnonymousCredentials()), manifest)
    observed: Document = {
        "id": "original",
        "name": f"projects/{TEST_PROJECT}/secrets/approved-secret",
        "labels": {"piccolo-live-dummy": "true"},
    }
    monkeypatch.setattr(cloud, "get", Mock(return_value=observed))
    from google.cloud import secretmanager_v1

    monkeypatch.setattr(
        cloud.clients.secrets,
        "access_secret_version",
        Mock(
            return_value=secretmanager_v1.AccessSecretVersionResponse(
                name=f"projects/{TEST_PROJECT}/secrets/approved-secret/versions/1",
                payload=secretmanager_v1.SecretPayload(
                    data=b"TEST_thisisadummytestsecret_TEST"
                ),
            )
        ),
    )
    cloud.preserve_external("secret", "approved-secret")
    entry = manifest.lookup("secret", "approved-secret")
    assert entry is not None and cloud.owns(entry, observed)
    assert not manifest.entries("resources")
    with pytest.raises(PiccoloError, match="cannot be deleted"):
        cloud.delete(entry)
    assert not cloud.owns(entry, {"id": "replacement"})
    with pytest.raises(PiccoloError, match="explicitly approved"):
        cloud.preserve_external("secret", "unapproved-secret")


@pytest.mark.parametrize("change_approval", [False, True])
def test_janitor_rejects_project_mismatch_before_loading_credentials(
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
    change_approval: bool,
) -> None:
    from gcp_live_support.gcp_live import main

    if change_approval:
        monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", "downstream-other-project")
    monkeypatch.setattr(
        sys, "argv", ["gcp_janitor.py", "--manifest", str(manifest.path)]
    )
    credentials = Mock(side_effect=AssertionError("Credentials must not be loaded"))
    monkeypatch.setattr("piccolo.providers.gcp.auth.credentials", credentials)
    # The fixture TOML names test-project, while its manifest records the approval.
    with pytest.raises(PiccoloError, match="exact project"):
        main()
    credentials.assert_not_called()


def test_profile_and_generated_config_are_local(
    approved: Config,
    tmp_path: Path,
) -> None:
    generated = run_config(approved, tmp_path / "generated", RUN, create_account=True)
    assert generated.gcp.project_id == TEST_PROJECT
    assert (
        generated.gcp.auth.impersonate_service_account
        == approved.gcp.auth.impersonate_service_account
    )
    assert generated.gcp.connection_account == "owner@example.com"
    assert generated.gcp.create_service_account
    assert generated.bootstrap is not None
    assert "piccolo live marker" in generated.bootstrap.script.read_text()
    with pytest.raises(PiccoloError, match="Live profile"):
        profile(generated.path)


def test_manifest_persisted_before_sdk_mutation(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients = Clients(AnonymousCredentials())
    monkeypatch.setattr(
        clients.disks, "get", Mock(side_effect=exceptions.NotFound("absent"))
    )
    name = f"{RUN}-boot"

    def insert(
        *, request: compute_v1.InsertDiskRequest, retry: None, timeout: int
    ) -> Mock:
        assert retry is None and timeout == 30
        durable = Manifest.open(manifest.path)
        assert durable.lookup("disk", name, ZONE)
        assert text(durable.entries("actions")[0], "key") == request.request_id
        operation = Mock()
        operation.name = "op-created"
        return operation

    monkeypatch.setattr(clients.disks, "insert", insert)
    cloud = LiveCloud(approved, clients, manifest)
    assert (
        cloud.submit(
            "disk.insert",
            name,
            ZONE,
            {"name": name, "labels": labels(approved, "operation")},
            "request",
        )
        == "op-created"
    )
    with pytest.raises(PiccoloError, match="already recorded"):
        cloud.submit("disk.insert", name, ZONE, {}, "request-again")


def test_preexisting_resource_blocks_creation_without_write(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients = Clients(AnonymousCredentials())
    insert = Mock()
    monkeypatch.setattr(clients.disks, "insert", insert)
    monkeypatch.setattr(
        clients.disks,
        "get",
        Mock(return_value=compute_v1.Disk(id=123, name=f"{RUN}-boot")),
    )
    with pytest.raises(PiccoloError, match="pre-existing"):
        LiveCloud(approved, clients, manifest).submit(
            "disk.insert", f"{RUN}-boot", ZONE, {}, "request"
        )
    insert.assert_not_called()
    assert not manifest.entries("actions")


def test_unknown_create_never_retries_or_cleans_dependencies(
    manifest: Manifest,
) -> None:
    backend = MemoryBackend(manifest)
    backend.add("disk", "boot", zone=ZONE)
    manifest.intent("instance.insert", f"{RUN}-vm", ZONE)
    backend.pending = True
    assert cleanup(manifest, backend, apply=True)
    assert not backend.deleted
    assert Manifest.open(manifest.path).data["complete"] is False


def test_lost_compute_response_reconciles_existing_operation(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients = Clients(AnonymousCredentials())
    cloud = LiveCloud(approved, clients, manifest)
    action = manifest.intent("disk.insert", f"{RUN}-boot", ZONE)
    recover = Mock(return_value="accepted-operation")
    monkeypatch.setattr(cloud, "recover", recover)
    monkeypatch.setattr(cloud, "poll", Mock(return_value={"status": "DONE"}))
    assert cloud.settle(action)
    assert action["settled"] is True
    recover.assert_called_once_with(text(action, "key"), ZONE)
    assert (
        text(Manifest.open(manifest.path).entries("actions")[0], "operation")
        == "accepted-operation"
    )


@pytest.mark.parametrize(
    "kind", ["instance", "disk", "snapshot", "firewall", "secret", "account"]
)
def test_replaced_id_preserves_resource(manifest: Manifest, kind: str) -> None:
    backend = MemoryBackend(manifest)
    entry = backend.add(kind, "resource")
    backend.resources[text(entry, "key")]["id"] = "replacement"
    assert cleanup(manifest, backend, apply=True)
    assert not backend.deleted


def test_cleanup_order_and_preexisting_preservation(manifest: Manifest) -> None:
    backend = MemoryBackend(manifest)
    for kind in ("account", "secret", "firewall", "snapshot", "disk", "instance"):
        backend.add(kind, kind)
    backend.resources["instance::unrelated"] = {"name": "unrelated", "id": "foreign"}
    manifest.put("bindings", {"key": "temporary-actAs"})
    assert not cleanup(manifest, backend, apply=True)
    assert [key.split(":")[0] for key in backend.deleted] == [
        "instance",
        "disk",
        "snapshot",
        "firewall",
        "secret",
        "account",
    ]
    assert backend.bindings_removed == ["temporary-actAs"]
    assert "instance::unrelated" in backend.resources
    assert Manifest.open(manifest.path).data["complete"] is True
    assert not cleanup(manifest, backend, apply=True)


def test_attached_disk_failure_keeps_accounts_and_apis(manifest: Manifest) -> None:
    backend = MemoryBackend(manifest)
    disk = backend.add("disk", "boot")
    backend.add("account", "vm")
    backend.resources[text(disk, "key")]["users"] = ["foreign-instance"]
    manifest.data["baseline_apis"] = ["compute.googleapis.com"]
    manifest.save()
    assert cleanup(manifest, backend, apply=True)
    assert not backend.deleted
    assert manifest.data["baseline_apis"] == ["compute.googleapis.com"]


def test_foreign_or_auto_delete_disk_blocks_vm_deletion(manifest: Manifest) -> None:
    backend = MemoryBackend(manifest)
    vm = backend.add("instance", "vm", zone=ZONE)
    backend.resources[text(vm, "key")]["disks"] = [
        {
            "source": f"projects/{TEST_PROJECT}/zones/{ZONE}/disks/foreign",
            "auto_delete": False,
        }
    ]
    assert cleanup(manifest, backend, apply=True)
    assert not backend.deleted


def test_cleanup_failure_is_retained_and_new_janitor_can_finish(
    manifest: Manifest,
) -> None:
    backend = MemoryBackend(manifest)
    backend.add("instance", "vm")
    backend.add("account", "vm")
    backend.fail_delete = "instance"
    assert cleanup(manifest, backend, apply=True)
    assert not backend.bindings_removed
    reopened = Manifest.open(manifest.path)
    assert reopened.data["cleanup_failures"]
    backend.manifest = reopened
    backend.fail_delete = ""
    assert not cleanup(reopened, backend, apply=True)


def test_keyboard_interrupt_keeps_manifest_for_independent_cleanup(
    manifest: Manifest,
) -> None:
    backend = MemoryBackend(manifest)
    backend.add("instance", "vm")
    backend.interrupt_delete = True
    with pytest.raises(KeyboardInterrupt):
        cleanup(manifest, backend, apply=True)
    assert Manifest.open(manifest.path).entries("resources")
    backend.interrupt_delete = False
    assert not cleanup(Manifest.open(manifest.path), backend, apply=True)


def test_incomplete_inventory_never_claims_zero_leftovers(manifest: Manifest) -> None:
    backend = MemoryBackend(manifest)
    backend.fail_inventory = "disk"
    assert cleanup(manifest, backend, apply=True)
    assert not manifest.data["complete"]


def test_unregistered_run_prefixed_resource_is_reported_not_deleted(
    manifest: Manifest,
) -> None:
    backend = MemoryBackend(manifest)
    backend.resources[f"disk::{RUN}-stray"] = {"name": f"{RUN}-stray", "id": "stray"}
    assert cleanup(manifest, backend, apply=True)
    assert not backend.deleted


def test_cleanup_preview_and_rechecked_gate_do_not_write(
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = MemoryBackend(manifest)
    backend.add("instance", "vm")
    assert not cleanup(manifest, backend)
    assert not backend.deleted
    monkeypatch.delenv("PICCOLO_GCP_LIVE")
    with pytest.raises(PiccoloError):
        cleanup(manifest, backend, apply=True)
    assert not backend.deleted


def test_hard_kill_retains_flushed_manifest(tmp_path: Path, approved: Config) -> None:
    del approved
    path = tmp_path / "killed" / "manifest.json"
    code = "\n".join(
        [
            "import sys, time",
            "from pathlib import Path",
            "from gcp_live_support.manifest import Manifest",
            "m = Manifest.create(Path(sys.argv[1]), Path(sys.argv[1]), "
            f"'{RUN}', project='{TEST_PROJECT}')",
            f"m.register('disk', '{RUN}-boot', '{ZONE}', {{'run': '{RUN}'}})",
            "print('durable', flush=True)",
            "time.sleep(60)",
        ]
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(__file__).parent)
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(path)],
        env=environment,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while not path.exists():
            if child.poll() is not None or time.monotonic() >= deadline:
                pytest.fail("Child failed to write manifest")
            time.sleep(0.01)
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "durable"
        child.kill()
        child.wait(timeout=5)
        durable = Manifest.open(path)
        assert durable.lookup("disk", f"{RUN}-boot", ZONE)
        assert not cleanup(durable, MemoryBackend(durable), apply=True)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


def test_created_account_interrupt_reconciles_without_second_create(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = replace(approved, gcp=replace(approved.gcp, create_service_account=True))
    clients = Clients(AnonymousCredentials())
    account = iam_admin_v1.ServiceAccount(
        email=approved.gcp.service_account,
        unique_id="1234",
        display_name=f"Piccolo {RUN}",
    )
    created = False

    def get(*, name: str, retry: object, timeout: int) -> iam_admin_v1.ServiceAccount:
        del name, retry, timeout
        if not created:
            raise exceptions.NotFound("absent")
        return account

    def create(
        *, request: iam_admin_v1.CreateServiceAccountRequest, retry: None, timeout: int
    ) -> None:
        nonlocal created
        del request, retry, timeout
        assert Manifest.open(manifest.path).lookup(
            "account", approved.gcp.service_account
        )
        created = True
        raise KeyboardInterrupt

    monkeypatch.setattr(clients.iam, "get_service_account", get)
    creator = Mock(side_effect=create)
    monkeypatch.setattr(clients.iam, "create_service_account", creator)
    cloud = LiveCloud(approved, clients, manifest)
    with pytest.raises(KeyboardInterrupt):
        LiveAccess(cloud).service_account()
    action = manifest.entries("actions")[0]
    assert cloud.settle(action)
    monkeypatch.setattr(cloud, "binding", Mock())
    monkeypatch.setattr(
        clients.iam,
        "test_iam_permissions",
        Mock(
            return_value=iam_policy_pb2.TestIamPermissionsResponse(
                permissions=["iam.serviceAccounts.actAs"]
            )
        ),
    )
    LiveAccess(cloud).service_account()
    creator.assert_called_once()
    assert cloud.binding.call_count == 2


def test_existing_account_uses_no_temporary_binding(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = replace(
        approved,
        gcp=replace(
            approved.gcp,
            service_account=f"existing@{TEST_PROJECT}.iam.gserviceaccount.com",
        ),
    )
    clients = Clients(AnonymousCredentials())
    monkeypatch.setattr(
        clients.iam,
        "get_service_account",
        Mock(return_value=iam_admin_v1.ServiceAccount(unique_id="existing")),
    )
    monkeypatch.setattr(
        clients.iam,
        "test_iam_permissions",
        Mock(return_value=iam_policy_pb2.TestIamPermissionsResponse(permissions=[])),
    )
    cloud = LiveCloud(approved, clients, manifest)
    bind = Mock()
    monkeypatch.setattr(cloud, "binding", bind)
    with pytest.raises(PiccoloError, match="actAs"):
        LiveAccess(cloud).service_account()
    bind.assert_not_called()
    assert not manifest.entries("bindings")
    assert not manifest.entries("resources")


def test_iam_cleanup_preserves_conditions_members_and_fresh_etag(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients = Clients(AnonymousCredentials())
    name = f"{RUN}-vm@{TEST_PROJECT}.iam.gserviceaccount.com"
    entry = manifest.register("account", name, "", {"displayName": f"Piccolo {RUN}"})
    entry["id"] = "1234"
    manifest.put("resources", entry)
    account = iam_admin_v1.ServiceAccount(
        unique_id="1234", display_name=f"Piccolo {RUN}"
    )
    monkeypatch.setattr(clients.iam, "get_service_account", Mock(return_value=account))
    role, member = "roles/iam.serviceAccountUser", "user:owner@example.com"
    policy = policy_pb2.Policy(version=3, etag=b"fresh")
    policy.bindings.add(role=role, members=[member, "user:unrelated@example.com"])
    conditional = policy.bindings.add(role=role, members=[member])
    conditional.condition.expression = "true"
    monkeypatch.setattr(clients.iam, "get_iam_policy", Mock(return_value=policy))
    setter = Mock()
    monkeypatch.setattr(clients.iam, "set_iam_policy", setter)
    binding: Document = {
        "key": "actAs",
        "kind": "account",
        "name": name,
        "target_id": "1234",
        "absent_before": True,
        "resource": f"projects/{TEST_PROJECT}/serviceAccounts/{name}",
        "role": role,
        "member": member,
    }
    LiveCloud(approved, clients, manifest).remove_binding(binding)
    updated = setter.call_args.kwargs["request"].policy
    assert updated.etag == b"fresh"
    assert updated.bindings[0].members == ["user:unrelated@example.com"]
    assert updated.bindings[1].condition.expression == "true"
    assert updated.bindings[1].members == [member]


def test_reopened_manifest_preserves_secret_cleanup_identifiers(
    manifest: Manifest,
) -> None:
    """Recover secret deletion and IAM removal from persisted public identities."""
    backend = MemoryBackend(manifest)
    entry = backend.add("secret", "dummy")
    resource = f"projects/{TEST_PROJECT}/secrets/{text(entry, 'name')}"
    role = "roles/secretmanager.secretAccessor"
    member = f"serviceAccount:{RUN}-vm@{TEST_PROJECT}.iam.gserviceaccount.com"
    key = f"{resource}:{role}:{member}"
    binding: Document = {
        "key": key,
        "kind": "secret",
        "name": text(entry, "name"),
        "resource": resource,
        "role": role,
        "member": member,
        "target_id": "dummy",
        "absent_before": True,
    }
    manifest.put("bindings", binding)
    reopened = Manifest.open(manifest.path)
    assert reopened.lookup("secret", text(entry, "name")) == entry
    assert reopened.entries("bindings") == [binding]
    backend.manifest = reopened
    assert cleanup(reopened, backend, apply=True) == []
    assert backend.deleted == [text(entry, "key")]
    assert backend.bindings_removed == [key]
    assert reopened.data["complete"] is True


def test_live_recipe_preserves_pytest_argument_boundaries(tmp_path: Path) -> None:
    """Pass spaced selections and literal shell syntax through the live recipe."""
    binary = tmp_path / "bin"
    binary.mkdir()
    stub = binary / "uv"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "# Copyright 2026 Israel Flores-Arbolay\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        '"""uv — Record arguments without running cloud clients."""\n'
        "import json, sys\nfrom pathlib import Path\n"
        "Path('.test_logs').mkdir(exist_ok=True)\n"
        "if 'pytest' in sys.argv:\n"
        "    Path('arguments.json').write_text(json.dumps(sys.argv[1:]))\n"
    )
    stub.chmod(0o700)
    environment = os.environ.copy()
    environment["PATH"] = str(binary) + os.pathsep + environment["PATH"]
    environment["PICCOLO_GCP_LIVE_PROJECT"] = TEST_PROJECT
    environment["PICCOLO_GCP_LIVE_APPROVAL_SHA256"] = "offline-review"
    profile_path = "approved profile $(touch unexpected-file).toml"
    selection = "credential_guards or shutdown_metadata"
    result = subprocess.run(
        [
            "just",
            "--justfile",
            str(Path("justfile").resolve()),
            "--working-directory",
            str(tmp_path),
            "test-gcp-live",
            profile_path,
            "tests/test_gcp_live.py",
            "-k",
            selection,
            "--maxfail=1",
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    arguments: list[str] = json.loads((tmp_path / "arguments.json").read_text())
    assert arguments[-4:] == ["tests/test_gcp_live.py", "-k", selection, "--maxfail=1"]
    assert not (tmp_path / "unexpected-file").exists()


def test_default_collection_is_cloud_free_even_with_opt_in_environment(
    approved: Config,
) -> None:
    del approved
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_gcp_live.py", "-q"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("sssss")


def test_preflight_requires_delete_permissions_before_writes(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients = Clients(AnonymousCredentials())
    monkeypatch.setattr(
        clients.projects,
        "get_project",
        Mock(
            return_value=resourcemanager_v3.Project(
                name="projects/123", project_id=TEST_PROJECT
            )
        ),
    )
    tester = Mock(return_value=iam_policy_pb2.TestIamPermissionsResponse())
    monkeypatch.setattr(clients.projects, "test_iam_permissions", tester)
    creator = Mock()
    monkeypatch.setattr(clients.secrets, "create_secret", creator)
    with pytest.raises(PiccoloError, match="teardown permissions"):
        preflight(
            approved,
            LiveCloud(approved, clients, manifest),
            GCloudConnection(approved.gcp),
        )
    requested = tester.call_args.kwargs["request"].permissions
    assert "compute.instances.delete" in requested
    assert "compute.disks.delete" in requested
    assert "iam.serviceAccounts.delete" not in requested
    assert "secretmanager.secrets.delete" in requested
    creator.assert_not_called()
    assert not manifest.entries("actions")


def test_disabled_api_preflight_never_enables_it(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients = Clients(AnonymousCredentials())
    monkeypatch.setattr(
        clients.projects,
        "get_project",
        Mock(return_value=resourcemanager_v3.Project(name="projects/123")),
    )

    def permissions(
        *,
        request: iam_policy_pb2.TestIamPermissionsRequest,
        retry: object,
        timeout: int,
    ) -> iam_policy_pb2.TestIamPermissionsResponse:
        del retry, timeout
        return iam_policy_pb2.TestIamPermissionsResponse(
            permissions=request.permissions
        )

    monkeypatch.setattr(clients.projects, "test_iam_permissions", permissions)
    monkeypatch.setattr(
        clients.services,
        "get_service",
        Mock(
            return_value=service_usage_v1.Service(state=service_usage_v1.State.DISABLED)
        ),
    )
    enable = Mock()
    monkeypatch.setattr(clients.services, "enable_service", enable)
    with pytest.raises(PiccoloError, match="out of band"):
        preflight(
            approved,
            LiveCloud(approved, clients, manifest),
            GCloudConnection(approved.gcp),
        )
    enable.assert_not_called()
    assert not manifest.entries("actions")


def test_iam_intent_is_durable_before_temporary_act_as_grant(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients = Clients(AnonymousCredentials())
    name = approved.gcp.service_account
    manifest.register("account", name, "", {"displayName": f"Piccolo {RUN}"})
    monkeypatch.setattr(
        clients.iam,
        "get_service_account",
        Mock(
            return_value=iam_admin_v1.ServiceAccount(
                unique_id="1234", display_name=f"Piccolo {RUN}"
            )
        ),
    )
    monkeypatch.setattr(
        clients.iam,
        "get_iam_policy",
        Mock(return_value=policy_pb2.Policy(version=3, etag=b"fresh")),
    )

    def setter(
        *, request: iam_policy_pb2.SetIamPolicyRequest, retry: None, timeout: int
    ) -> policy_pb2.Policy:
        assert retry is None and timeout == 30
        durable = Manifest.open(manifest.path).entries("bindings")
        assert len(durable) == 1
        assert durable[0]["role"] == "roles/iam.serviceAccountUser"
        assert durable[0]["absent_before"] is True
        assert durable[0]["target_id"] == "1234"
        return request.policy

    monkeypatch.setattr(clients.iam, "set_iam_policy", setter)
    LiveCloud(approved, clients, manifest).binding(
        "account", name, "roles/iam.serviceAccountUser", "user:owner@example.com"
    )


def test_unobserved_sync_create_stays_uncertain_without_retry(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = replace(
        approved,
        gcp=replace(approved.gcp, create_service_account=True, operation_timeout=0),
    )
    clients = Clients(AnonymousCredentials())
    monkeypatch.setattr(
        clients.iam,
        "get_service_account",
        Mock(side_effect=exceptions.NotFound("absent")),
    )
    creator = Mock(side_effect=exceptions.ServiceUnavailable("lost response"))
    monkeypatch.setattr(clients.iam, "create_service_account", creator)
    cloud = LiveCloud(approved, clients, manifest)
    with pytest.raises(exceptions.ServiceUnavailable):
        LiveAccess(cloud).service_account()
    assert not cloud.settle(manifest.entries("actions")[0])
    with pytest.raises(PiccoloError, match="already recorded"):
        LiveAccess(cloud).service_account()
    creator.assert_called_once()


def test_sync_account_visibility_is_reconciled_with_reads_only(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = approved.gcp.service_account
    manifest.register("account", name, "", {"displayName": f"Piccolo {RUN}"})
    observed: Document = {"id": "immutable", "displayName": f"Piccolo {RUN}"}
    cloud = LiveCloud(approved, Clients(AnonymousCredentials()), manifest)
    getter = Mock(side_effect=[None, observed, observed, None])
    monkeypatch.setattr(cloud, "get", getter)
    wait = Mock()
    monkeypatch.setattr("gcp_live_support.gcp_sdk.time.sleep", wait)
    create = manifest.intent("account.create", name, "")
    assert cloud.settle(create)
    delete = manifest.intent("account.delete", name, "")
    assert cloud.settle(delete)
    assert getter.call_count == 4
    assert wait.call_count == 2


def test_definitively_rejected_create_allows_zero_leftover_cleanup(
    approved: Config,
    manifest: Manifest,
) -> None:
    clients = Clients(AnonymousCredentials())
    cloud = LiveCloud(approved, clients, manifest)
    action = manifest.intent("account.create", approved.gcp.service_account, "")
    with pytest.raises(exceptions.Forbidden):
        cloud.perform(action, Mock(side_effect=exceptions.Forbidden("denied")))
    assert action["settled"] is True
    assert not cleanup(manifest, MemoryBackend(manifest), apply=True)


def test_firewall_sdk_request_has_run_intent_and_idempotency(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = replace(approved, gcp=replace(approved.gcp, firewall_name=f"{RUN}-iap"))
    clients = Clients(AnonymousCredentials())
    monkeypatch.setattr(
        clients.firewalls, "get", Mock(side_effect=exceptions.NotFound("absent"))
    )

    def insert(
        *, request: compute_v1.InsertFirewallRequest, retry: None, timeout: int
    ) -> Mock:
        assert retry is None and timeout == 30
        durable = Manifest.open(manifest.path)
        assert durable.lookup("firewall", approved.gcp.firewall_name)
        assert durable.entries("actions")[0]["key"] == request.request_id
        operation = Mock()
        operation.name = "firewall-op"
        return operation

    monkeypatch.setattr(clients.firewalls, "insert", insert)
    cloud = LiveCloud(approved, clients, manifest)
    monkeypatch.setattr(cloud, "poll", Mock(return_value={"status": "DONE"}))
    LiveAccess(cloud).firewall()


@pytest.mark.parametrize("direct", [False, True])
def test_created_account_waits_for_act_as_without_recreating(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
    direct: bool,
) -> None:
    provisioner = approved.gcp.auth.impersonate_service_account
    if direct:
        approved = replace(
            approved,
            gcp=replace(
                approved.gcp,
                auth=replace(approved.gcp.auth, impersonate_service_account=""),
            ),
        )
    clients = Clients(AnonymousCredentials())
    name = approved.gcp.service_account
    manifest.register("account", name, "", {"displayName": f"Piccolo {RUN}"})
    monkeypatch.setattr(
        clients.iam,
        "get_service_account",
        Mock(
            return_value=iam_admin_v1.ServiceAccount(
                unique_id="1234", display_name=f"Piccolo {RUN}"
            )
        ),
    )
    tester = Mock(
        side_effect=[
            iam_policy_pb2.TestIamPermissionsResponse(),
            iam_policy_pb2.TestIamPermissionsResponse(
                permissions=["iam.serviceAccounts.actAs"]
            ),
        ]
    )
    monkeypatch.setattr(clients.iam, "test_iam_permissions", tester)
    creator = Mock()
    monkeypatch.setattr(clients.iam, "create_service_account", creator)
    wait = Mock()
    monkeypatch.setattr("gcp_live_support.gcp_sdk.time.sleep", wait)
    cloud = LiveCloud(approved, clients, manifest, provisioner=provisioner)
    monkeypatch.setattr(cloud, "binding", Mock())
    LiveAccess(cloud).service_account()
    assert tester.call_count == 2
    wait.assert_called_once_with(2)
    creator.assert_not_called()
    cloud.binding.assert_any_call(
        "account", name, "roles/iam.serviceAccountUser", f"serviceAccount:{provisioner}"
    )


def test_direct_profile_and_identity(
    approved: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approved = replace(
        approved,
        gcp=replace(
            approved.gcp,
            auth=replace(approved.gcp.auth, impersonate_service_account=""),
        ),
    )
    generated = run_config(approved, tmp_path / "direct", RUN, create_account=False)
    content = generated.path.read_text()
    generated.path.write_text(
        content[: content.index("[bootstrap]")] + content[content.index("[gcp]") :]
    )
    monkeypatch.setenv(
        "PICCOLO_GCP_LIVE_APPROVAL_SHA256", approval_digest(load(generated.path))
    )
    assert not profile(generated.path).gcp.auth.impersonate_service_account
    provisioner = f"provisioner@{TEST_PROJECT}.iam.gserviceaccount.com"
    assert (
        provisioner_identity(Mock(service_account_email=provisioner), generated)
        == provisioner
    )
    with pytest.raises(PiccoloError, match="provisioner"):
        provisioner_identity(
            Mock(service_account_email=generated.gcp.service_account), generated
        )


def test_missing_openssh_fails_locally(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "gcp_live_support.gcp_live.shutil.which",
        lambda name: None if name == "ssh" else "/installed",
    )
    with pytest.raises(PiccoloError, match="ssh"):
        local_preflight()


def test_janitor_removes_recorded_ssh_keys_only_when_applied(
    manifest: Manifest,
) -> None:
    backend = MemoryBackend(manifest)
    manifest.put("ssh_keys", {"key": "disposable-key", "status": "publishing"})
    assert cleanup(manifest, backend, apply=False) == []
    assert not backend.ssh_keys_removed
    assert cleanup(manifest, backend, apply=True) == []
    assert backend.ssh_keys_removed == ["disposable-key"]


def test_janitor_keeps_ssh_keys_while_compute_cleanup_is_unresolved(
    manifest: Manifest,
) -> None:
    backend = MemoryBackend(manifest)
    backend.add("disk", "boot", zone=ZONE)
    backend.fail_delete = "disk"
    manifest.put("ssh_keys", {"key": "disposable-key", "status": "publishing"})
    assert cleanup(manifest, backend, apply=True)
    assert not backend.ssh_keys_removed
    assert manifest.data["complete"] is False


def test_janitor_preserves_failed_ssh_key_cleanup_for_recovery(
    manifest: Manifest, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = MemoryBackend(manifest)
    manifest.put("ssh_keys", {"key": "disposable-key", "status": "publishing"})
    monkeypatch.setattr(
        backend,
        "remove_ssh_key",
        Mock(side_effect=PiccoloError("connector unavailable")),
    )
    failures = cleanup(manifest, backend, apply=True)
    assert failures and "SSH key disposable-key" in failures[0]
    assert manifest.data["complete"] is False
    assert manifest.entries("ssh_keys")[0]["status"] == "publishing"


@pytest.mark.parametrize("mode", ["oslogin", "metadata"])
def test_login_mode_is_selected_before_first_vm_access(
    approved: Config, manifest: Manifest, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    from piccolo.providers.gcp.resources import SDKCloud

    cloud = LiveCloud(approved, Clients(AnonymousCredentials()), manifest)
    cloud.ssh_login_mode = mode
    monkeypatch.setattr(cloud, "get", Mock(return_value=None))
    submit = Mock(return_value="created-operation")
    monkeypatch.setattr(SDKCloud, "submit", submit)
    resource: Document = {
        "name": approved.gcp.name,
        "labels": labels(approved),
        "metadata": {"items": [{"key": "enable-guest-attributes", "value": "TRUE"}]},
    }
    cloud.submit("instance.insert", approved.gcp.name, ZONE, resource, "request")
    payload = submit.call_args.args[3]
    metadata = document(payload["metadata"])
    settings = {
        text(item, "key"): text(item, "value") for item in objects(metadata, "items")
    }
    assert settings["enable-guest-attributes"] == "TRUE"
    assert settings["enable-oslogin"] == ("TRUE" if mode == "oslogin" else "FALSE")
    if mode == "metadata":
        assert settings["block-project-ssh-keys"] == "TRUE"


@pytest.mark.parametrize(
    "baseline", ["absent", "present", "conditional", "interrupted"]
)
def test_project_grant_restoration_preserves_baseline_and_concurrent_changes(
    approved: Config, manifest: Manifest, monkeypatch: pytest.MonkeyPatch, baseline: str
) -> None:
    """Recover a durable project grant without removing existing or later grants."""
    approved = replace(
        approved, gcp=replace(approved.gcp, project_roles=("roles/compute.viewer",))
    )
    clients = Clients(AnonymousCredentials())
    cloud = LiveCloud(approved, clients, manifest)
    member = f"serviceAccount:{approved.gcp.service_account}"
    stored = policy_pb2.Policy(version=3, etag=b"original")
    stored.bindings.add(role="roles/viewer", members=["user:other@example.com"])
    if baseline in {"present", "conditional"}:
        binding = stored.bindings.add(role="roles/compute.viewer", members=[member])
        if baseline == "conditional":
            binding.condition.expression = (
                "request.time < timestamp('2030-01-01T00:00:00Z')"
            )
    original = policy_pb2.Policy()
    original.CopyFrom(stored)
    monkeypatch.setattr(
        clients.projects,
        "get_project",
        Mock(
            return_value=resourcemanager_v3.Project(
                name="projects/123", project_id=TEST_PROJECT
            )
        ),
    )
    monkeypatch.setattr(
        clients.iam,
        "get_service_account",
        Mock(return_value=iam_admin_v1.ServiceAccount(unique_id="guest-original")),
    )

    def read(
        *, request: iam_policy_pb2.GetIamPolicyRequest, retry: object, timeout: int
    ) -> policy_pb2.Policy:
        del retry, timeout
        assert request.resource == f"projects/{TEST_PROJECT}"
        assert request.options.requested_policy_version == 3
        result = policy_pb2.Policy()
        result.CopyFrom(stored)
        return result

    def write(
        *, request: iam_policy_pb2.SetIamPolicyRequest, retry: None, timeout: int
    ) -> None:
        del retry, timeout
        assert request.resource == f"projects/{TEST_PROJECT}"
        assert request.policy.etag == stored.etag
        assert Manifest.open(manifest.path).entries("bindings")
        stored.CopyFrom(request.policy)
        if baseline == "interrupted" and setter.call_count == 1:
            raise KeyboardInterrupt

    monkeypatch.setattr(clients.projects, "get_iam_policy", read)
    setter = Mock(side_effect=write)
    monkeypatch.setattr(clients.projects, "set_iam_policy", setter)
    if baseline == "conditional":
        with pytest.raises(PiccoloError, match="Conditional-only"):
            LiveAccess(cloud).grant(
                f"projects/{TEST_PROJECT}", "roles/compute.viewer", secret=False
            )
        assert stored == original
        setter.assert_not_called()
        return
    if baseline == "interrupted":
        with pytest.raises(KeyboardInterrupt):
            LiveAccess(cloud).grant(
                f"projects/{TEST_PROJECT}", "roles/compute.viewer", secret=False
            )
    else:
        LiveAccess(cloud).grant(
            f"projects/{TEST_PROJECT}", "roles/compute.viewer", secret=False
        )
    stored.bindings.add(role="roles/compute.viewer", members=["user:later@example.com"])
    restored = LiveCloud(approved, clients, Manifest.open(manifest.path))
    for entry in restored.manifest.entries("bindings"):
        restored.remove_binding(entry)
    original.bindings.add(
        role="roles/compute.viewer", members=["user:later@example.com"]
    )
    assert stored == original
    if baseline == "present":
        setter.assert_not_called()


@pytest.mark.parametrize("mismatch", ["project", "role", "member"])
def test_project_grant_rejects_unapproved_scope_before_cloud_access(
    approved: Config, manifest: Manifest, monkeypatch: pytest.MonkeyPatch, mismatch: str
) -> None:
    """Reject project, role, and guest overrides before reading or writing IAM."""
    approved = replace(
        approved, gcp=replace(approved.gcp, project_roles=("roles/compute.viewer",))
    )
    cloud = LiveCloud(approved, Clients(AnonymousCredentials()), manifest)
    getter = Mock()
    monkeypatch.setattr(cloud, "get", getter)
    with pytest.raises(PiccoloError, match="approved guest roles"):
        cloud.binding(
            "project",
            "other-project" if mismatch == "project" else TEST_PROJECT,
            "roles/owner" if mismatch == "role" else "roles/compute.viewer",
            "user:other@example.com"
            if mismatch == "member"
            else f"serviceAccount:{approved.gcp.service_account}",
        )
    getter.assert_not_called()


def test_run_config_retains_approved_project_roles(
    approved: Config, tmp_path: Path
) -> None:
    """Keep guest role approval in each fixture's fingerprint and recovery config."""
    approved = replace(
        approved, gcp=replace(approved.gcp, project_roles=("roles/compute.viewer",))
    )
    generated = run_config(approved, tmp_path / "generated", RUN, create_account=False)
    assert generated.gcp.project_roles == approved.gcp.project_roles


@pytest.mark.parametrize("interrupted", [False, True])
@pytest.mark.parametrize("mode", ["oslogin", "metadata"])
def test_fixture_login_metadata_is_verified_on_creation_and_resume(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
    interrupted: bool,
    mode: str,
) -> None:
    """Exercise strict creation verification after genuine fixture metadata overlay."""
    from conftest import FakeCloud
    from gcp_live_support.gcp_sdk import LiveProvider

    from piccolo.errors import UncertainError

    fake = FakeCloud()
    cloud = LiveCloud(approved, Clients(AnonymousCredentials()), manifest)
    cloud.ssh_login_mode = mode
    for method in (
        "get",
        "list",
        "submit",
        "poll",
        "recover",
        "access",
        "access_plan",
        "subnet",
        "project_metadata",
        "connection_policy",
        "host_keys",
    ):
        monkeypatch.setattr(cloud, method, getattr(fake, method))
    if interrupted:
        fake.lost_response.add(("instance.insert", ZONE))
    provider = LiveProvider(approved, cloud)
    if interrupted:
        with pytest.raises(UncertainError):
            provider.init()
        provider = LiveProvider(approved, cloud)
        provider.resume()
    else:
        provider.init()
    assert not provider.journal.operation
    metadata = document(provider.active()["metadata"])
    settings = {text(i, "key"): text(i, "value") for i in objects(metadata, "items")}
    assert settings["enable-oslogin"] == ("TRUE" if mode == "oslogin" else "FALSE")
    if mode == "metadata":
        assert settings["block-project-ssh-keys"] == "TRUE"
    assert sum(kind == "instance.insert" for kind, *_ in fake.calls) == 1


def test_initial_zone_restriction_blocks_capacity_fallback_before_cloud_access(
    approved: Config, manifest: Manifest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep initial placement within an operator's narrower zone authorization."""
    from gcp_live_support.gcp_sdk import LiveProvider

    monkeypatch.setenv("PICCOLO_GCP_LIVE_INIT_ZONE", ZONE)
    cloud = LiveCloud(approved, Clients(AnonymousCredentials()), manifest)
    getter = Mock()
    monkeypatch.setattr(cloud, "get", getter)
    provider = LiveProvider(approved, cloud)
    provider.journal.begin({"kind": "init"})
    with pytest.raises(PiccoloError, match="initial zone"):
        provider.created("disk", "candidate-boot", "us-east1-b", {})
    getter.assert_not_called()


@pytest.mark.parametrize("listed_id", ["original", "replacement", "absent"])
def test_recorded_account_notfound_is_checked_against_inventory(
    approved: Config,
    manifest: Manifest,
    monkeypatch: pytest.MonkeyPatch,
    listed_id: str,
) -> None:
    """Avoid dropping a created account after an inconsistent direct IAM read."""
    cloud = LiveCloud(approved, Clients(AnonymousCredentials()), manifest)
    name = approved.gcp.service_account
    entry = manifest.register("account", name, "", {"displayName": f"Piccolo {RUN}"})
    entry["id"] = "original"
    manifest.put("resources", entry)
    monkeypatch.setattr(
        cloud.clients.iam,
        "get_service_account",
        Mock(side_effect=exceptions.NotFound("temporary absence")),
    )
    lister = Mock(
        return_value=[]
        if listed_id == "absent"
        else [
            iam_admin_v1.ServiceAccount(
                email=name, unique_id=listed_id, display_name=f"Piccolo {RUN}"
            )
        ]
    )
    monkeypatch.setattr(cloud.clients.iam, "list_service_accounts", lister)
    observed = cloud.get("account", name)
    lister.assert_called_once_with(
        name=f"projects/{TEST_PROJECT}", retry=READ_RETRY, timeout=30
    )
    if listed_id == "absent":
        assert observed is None
    else:
        assert observed is not None
        assert cloud.owns(entry, observed) is (listed_id == "original")
