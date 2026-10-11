# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_live_safety.py — Offline interruption, ownership, and janitor failures.

Live use requires PICCOLO_GCP_LIVE_PROJECT; offline fixtures set it locally.
"""

import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from gcp_live_support.gcp_live import preflight, profile, run_config
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

from piccolo.config import Config
from piccolo.data import Document, document, text
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.connection import GCloudConnection
from piccolo.providers.gcp.provision import labels

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
    assert result.stdout.startswith("ssss")


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
    assert "iam.serviceAccounts.delete" in requested
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
    approved = replace(approved, gcp=replace(approved.gcp, create_service_account=True))
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


def test_created_account_waits_for_act_as_without_recreating(
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
    cloud = LiveCloud(approved, clients, manifest)
    monkeypatch.setattr(cloud, "binding", Mock())
    LiveAccess(cloud).service_account()
    assert tester.call_count == 2
    wait.assert_called_once_with(2)
    creator.assert_not_called()
