# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""gcp_sdk.py — Manifest-backed test adapter; never used by ordinary CLI commands."""

import json
import os
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import override

from google.api_core import exceptions
from google.cloud import compute_v1, iam_admin_v1, resourcemanager_v3, secretmanager_v1
from google.iam.v1 import iam_policy_pb2, options_pb2, policy_pb2

from gcp_live_support.deadline import bind_clients, check_work, timeout
from gcp_live_support.manifest import Manifest, gate
from piccolo.config.models import Config
from piccolo.data import Document, decode, document, objects, text
from piccolo.errors import PiccoloError, UncertainError
from piccolo.providers.gcp.access import Access, add_binding
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.operations import failure
from piccolo.providers.gcp.provider import GCPProvider
from piccolo.providers.gcp.provision import labels
from piccolo.providers.gcp.resources import READ_RETRY, SDKCloud
from piccolo.state.storage import private_file


class LiveCloud(SDKCloud):
    """Record all test provisioning and janitor writes before sending requests."""

    def __init__(
        self,
        config: Config,
        clients: Clients,
        manifest: Manifest,
        *,
        provisioner: str = "",
    ) -> None:
        """Reject config/manifest mismatches before using supplied SDK clients."""
        manifest.validate()
        gate(config.gcp.project_id)
        if (
            config.gcp.project_id != text(manifest.data, "project")
            or config.environment != text(manifest.data, "run")
            or config.gcp.enable_apis
        ):
            raise PiccoloError(
                "Live runs require matching project/run and pre-enabled APIs"
            )
        super().__init__(config, clients)
        bind_clients(clients)
        self.manifest = manifest
        self.provisioner = provisioner or config.gcp.auth.impersonate_service_account
        self.ssh_login_mode = os.environ.get("PICCOLO_GCP_LIVE_LOGIN_MODE", "oslogin")

    @override
    def get(self, kind: str, name: str, zone: str = "") -> Document | None:
        """Inspect fixture resources without conflating absence and read errors."""
        try:
            match kind:
                case "project":
                    if name != self.project:
                        raise PiccoloError("Project policy target is outside approval")
                    project = self.clients.projects.get_project(
                        name=f"projects/{self.project}", retry=READ_RETRY, timeout=30
                    )
                    result = decode(resourcemanager_v3.Project.to_json(project))
                    result["id"] = project.name
                case "account":
                    account = self.clients.iam.get_service_account(
                        name=f"projects/{self.project}/serviceAccounts/{name}",
                        retry=READ_RETRY,
                        timeout=30,
                    )
                    result = decode(iam_admin_v1.ServiceAccount.to_json(account))
                    result["id"] = account.unique_id
                case "secret":
                    secret = self.clients.secrets.get_secret(
                        name=f"projects/{self.project}/secrets/{name}",
                        retry=READ_RETRY,
                        timeout=30,
                    )
                    result = decode(secretmanager_v1.Secret.to_json(secret))
                    result["id"] = str(secret.create_time)
                case "firewall":
                    firewall = self.clients.firewalls.get(
                        project=self.project,
                        firewall=name,
                        retry=READ_RETRY,
                        timeout=30,
                    )
                    result = decode(
                        compute_v1.Firewall.to_json(
                            firewall, preserving_proto_field_name=True
                        )
                    )
                case _:
                    result = super().get(kind, name, zone)
        except exceptions.NotFound:
            entry = self.manifest.lookup(kind, name, zone)
            if (
                kind != "account"
                or entry is None
                or entry.get("absent_before") is not True
                or not text(entry, "id")
            ):
                return None
            # IAM reads can temporarily disagree after account creation/deletion.
            for account in self.clients.iam.list_service_accounts(
                name=f"projects/{self.project}", retry=READ_RETRY, timeout=30
            ):
                if account.email == name:
                    deleted = any(
                        text(action, "kind") == "account.delete"
                        and text(action, "name") == name
                        and action.get("settled") is True
                        and not text(action, "error")
                        for action in self.manifest.entries("actions")
                    )
                    if deleted and account.unique_id == text(entry, "id"):
                        # A stale list must not resurrect an authoritatively absent ID.
                        return None
                    result = decode(iam_admin_v1.ServiceAccount.to_json(account))
                    result["id"] = account.unique_id
                    break
            else:
                return None
        if result:
            entry = self.manifest.lookup(kind, name, zone)
            if entry and not text(entry, "id") and self.owns(entry, result):
                entry["id"] = text(result, "id")
                self.manifest.put("resources", entry)
        return result

    def owns(self, entry: Document, observed: Document) -> bool:
        """Require absent baseline, exact run name, marker, and recorded identity."""
        name = text(entry, "name")
        proof = document(entry.get("proof", {}))
        kind = text(entry, "kind")
        run = text(self.manifest.data, "run")
        if entry.get("preserve") is True:
            allowed = (
                (kind == "secret" and name in self.config.gcp.secrets)
                or (
                    kind == "account"
                    and name == self.config.gcp.auth.impersonate_service_account
                )
                or (kind == "project" and name == self.project)
            )
            return (
                allowed
                and entry.get("absent_before") is False
                and bool(text(entry, "id"))
                and text(entry, "id") == text(observed, "id")
            )
        required_proof: Document
        if kind in {"instance", "disk", "snapshot"}:
            required_proof = {"labels": labels(self.config)}
        elif kind == "secret":
            required_proof = {"labels": {"piccolo-live-run": run}}
        elif kind == "account":
            required_proof = {"displayName": f"Piccolo {run}"}
        elif kind == "firewall":
            required_proof = {"description": f"Piccolo {self.project}/{run}"}
        else:
            return False
        if (
            entry.get("absent_before") is not True
            or not name.startswith(f"{text(self.manifest.data, 'run')}-")
            or not proof
            or not text(observed, "id")
            or (text(entry, "id") and text(entry, "id") != text(observed, "id"))
        ):
            return False
        for key, required in required_proof.items():
            if key == "labels":
                recorded = document(proof.get("labels", {}))
                if any(recorded.get(k) != v for k, v in document(required).items()):
                    return False
            elif proof.get(key) != required:
                return False
        for key, expected in proof.items():
            if key == "labels":
                actual = document(observed.get("labels", {}))
                if any(actual.get(k) != v for k, v in document(expected).items()):
                    return False
            elif observed.get(key) != expected:
                return False
        return True

    def set_metadata(self, zone: str, instance_id: str, items: list[Document]) -> None:
        """Journal harmless metadata regression writes to an exact run-owned VM."""
        gate(self.project)
        name = self.config.gcp.name
        observed = self.get("instance", name, zone)
        entry = self.manifest.lookup("instance", name, zone)
        if (
            observed is None
            or entry is None
            or not self.owns(entry, observed)
            or text(observed, "id") != instance_id
        ):
            raise PiccoloError("Refusing metadata changes to an unproven run VM")
        metadata = document(observed.get("metadata", {}))
        action = self.manifest.intent("instance.metadata", name, zone)
        request = compute_v1.SetMetadataInstanceRequest(
            project=self.project,
            zone=zone,
            instance=name,
            request_id=text(action, "key"),
            metadata_resource=compute_v1.Metadata(
                fingerprint=text(metadata, "fingerprint"),
                items=items,
            ),
        )
        operation = self.perform(
            action,
            lambda: self.clients.instances.set_metadata(
                request=request,
                retry=None,
                timeout=30,
            ),
        )
        action["operation"] = operation.name
        self.manifest.put("actions", action)
        if not self.settle(action):
            raise UncertainError("Live metadata write remains unresolved")
        if text(action, "error"):
            raise PiccoloError("Live metadata regression write failed")

    def preserve_external(self, kind: str, name: str) -> None:
        """Track an approved existing policy target without authorizing deletion."""
        allowed = (
            (kind == "secret" and name in self.config.gcp.secrets)
            or (
                kind == "account"
                and name == self.config.gcp.auth.impersonate_service_account
            )
            or (kind == "project" and name == self.project)
        )
        if not allowed:
            raise PiccoloError("Existing target was not explicitly approved")
        observed = self.get(kind, name)
        if observed is None:
            raise PiccoloError("Approved existing policy target is missing")
        previous = self.manifest.lookup(kind, name)
        if previous is not None:
            if not self.owns(previous, observed):
                raise PiccoloError("Existing target identity changed")
            return
        dummy_version = ""
        if kind == "secret":
            if document(observed.get("labels", {})).get("piccolo-live-dummy") != "true":
                raise PiccoloError(
                    "Approved existing secret must be labelled "
                    "piccolo-live-dummy=true before any IAM grant"
                )
            canonical_name = text(observed, "name")
            if (
                re.fullmatch(
                    rf"projects/(?:{re.escape(self.project)}|[1-9][0-9]*)/secrets/{re.escape(name)}",
                    canonical_name,
                )
                is None
            ):
                raise PiccoloError(
                    "Existing secret has an unexpected canonical resource name"
                )
            response = self.clients.secrets.access_secret_version(
                name=f"projects/{self.project}/secrets/{name}/versions/latest",
                retry=None,
                timeout=timeout(),
            )
            dummy_version = response.name
            prefix = f"{canonical_name}/versions/"
            if (
                not dummy_version.startswith(prefix)
                or not dummy_version.removeprefix(prefix).isdecimal()
                or response.payload.data != b"TEST_thisisadummytestsecret_TEST"
            ):
                raise PiccoloError(
                    "Existing live secret is not the approved dummy payload/version; "
                    "guest grants are blocked"
                )
        from gcp_live_support.manifest import resource_key

        self.manifest.put(
            "external_resources",
            {
                "key": resource_key(kind, name),
                "kind": kind,
                "name": name,
                "zone": "",
                "id": text(observed, "id"),
                "absent_before": False,
                "preserve": True,
                "dummy_version": dummy_version,
            },
        )

    def prepare(self, kind: str, name: str, zone: str, proof: Document) -> Document:
        """Require an absent target and persist its reservation before creation."""
        gate(self.project)
        if self.manifest.lookup(kind, name, zone):
            raise PiccoloError(
                "Creation already recorded; reconcile instead of retrying"
            )
        if self.get(kind, name, zone) is not None:
            raise PiccoloError(f"Preserving pre-existing {kind} {name}")
        return self.manifest.register(kind, name, zone, proof)

    def perform[T](self, action: Document, operation: Callable[[], T]) -> T:
        """Keep transport failures uncertain but record definitive rejected writes."""
        gate(self.project)
        check_work()
        try:
            return operation()
        except (
            exceptions.BadRequest,
            exceptions.Forbidden,
            exceptions.Unauthorized,
            exceptions.NotFound,
            exceptions.Conflict,
        ) as exc:
            action["settled"] = True
            action["error"] = str(exc)
            self.manifest.put("actions", action)
            raise

    def instance_settings(self, resource: Document) -> Document:
        """Apply explicit fixture login metadata before submission and verification."""
        resource = document(resource)
        metadata = document(resource.get("metadata", {}))
        items = objects(metadata, "items")
        if self.ssh_login_mode not in {"oslogin", "metadata"}:
            raise PiccoloError("Unsupported live SSH login mode")
        self.manifest.data["ssh_login_mode"] = self.ssh_login_mode
        self.manifest.save()
        if not any(text(item, "key") == "enable-oslogin" for item in items):
            items.append(
                {
                    "key": "enable-oslogin",
                    "value": "TRUE" if self.ssh_login_mode == "oslogin" else "FALSE",
                }
            )
        if self.ssh_login_mode == "metadata" and not any(
            text(item, "key") == "block-project-ssh-keys" for item in items
        ):
            items.append({"key": "block-project-ssh-keys", "value": "TRUE"})
        metadata["items"] = [item for item in items]
        resource["metadata"] = metadata
        return resource

    @override
    def submit(
        self, kind: str, name: str, zone: str, resource: Document, request_id: str
    ) -> str:
        """Gate and journal every Compute mutation, including lifecycle operations."""
        gate(self.project)
        check_work()
        self.reserve_transfer(kind, zone, resource, request_id)
        resource_kind, verb = kind.split(".")
        if verb == "insert":
            if resource_kind == "instance":
                resource = self.instance_settings(resource)
            self.prepare(
                resource_kind, name, zone, {"labels": resource.get("labels", {})}
            )
        else:
            entry = self.manifest.lookup(resource_kind, name, zone)
            observed = self.get(resource_kind, name, zone)
            if entry is None or observed is None or not self.owns(entry, observed):
                raise PiccoloError("Refusing to mutate an unproven run resource")
            if kind == "instance.delete":
                for attached in objects(observed, "disks"):
                    source = text(attached, "source")
                    disk_name = source.rsplit("/", 1)[-1]
                    disk_entry = self.manifest.lookup("disk", disk_name, zone)
                    disk = self.get("disk", disk_name, zone)
                    if (
                        disk_entry is None
                        or disk is None
                        or attached.get("auto_delete") is True
                        or not self.owns(disk_entry, disk)
                        or not source.endswith(
                            f"projects/{self.project}/zones/{zone}/disks/{disk_name}"
                        )
                    ):
                        raise PiccoloError("Refusing to detach an unproven disk")
        action = self.manifest.intent(kind, name, zone, request_id)
        try:
            operation = super().submit(kind, name, zone, resource, request_id)
        except PiccoloError as exc:
            from piccolo.errors import UncertainError

            if not isinstance(exc, UncertainError):
                action["settled"] = True
                self.manifest.put("actions", action)
            raise
        action["operation"] = operation
        self.manifest.put("actions", action)
        return operation

    def reserve_transfer(
        self, kind: str, zone: str, resource: Document, request_id: str
    ) -> None:
        """Persist conservative transfer charges before an approved session request."""
        path = os.environ.get("PICCOLO_GCP_LIVE_BUDGET_FILE")
        if not path or kind not in {
            "snapshot.insert",
            "disk.insert",
            "instance.insert",
        }:
            return
        if (
            self.config.gcp.machine_type != "e2-small"
            or self.config.gcp.size_gb > 10
            or self.config.gcp.external_ip
            or self.config.gcp.snapshot_location != "us-west1"
        ):
            raise PiccoloError("Session budget requires the reviewed regional profile")
        charge = 0
        if kind == "snapshot.insert":
            source = text(resource, "source_disk")
            source_zone = source.split("/zones/")[-1].split("/")[0]
            if source_zone.rsplit("-", 1)[0] != "us-west1":
                # Reserve transfer of the entire approved 10 GiB disk.
                charge = 200_000
        elif kind == "disk.insert" and text(resource, "source_snapshot"):
            snapshot_name = text(resource, "source_snapshot").rsplit("/", 1)[-1]
            entry = self.manifest.lookup("snapshot", snapshot_name)
            snapshot = self.get("snapshot", snapshot_name)
            if entry is None or snapshot is None or not self.owns(entry, snapshot):
                raise PiccoloError("Budget snapshot identity is unproven")
            stored = snapshot.get("storage_bytes")
            if not isinstance(stored, int | str) or not str(stored).isdecimal():
                raise PiccoloError("Snapshot transfer size is unavailable")
            if not 0 < int(stored) <= 2**30:
                raise PiccoloError("Snapshot exceeds the one GiB transfer allowance")
            if zone.rsplit("-", 1)[0] != "us-west1":
                charge = 20_000
        if not charge:
            return
        import fcntl

        with os.fdopen(private_file(Path(path)), "r+") as stream:
            while True:
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(timeout(0.1))
            ledger = decode(stream.read())
            reservations = document(ledger["reservations"])
            if request_id in reservations:
                return
            spent = ledger["reserved_micro_usd"]
            limit = ledger["limit_micro_usd"]
            if (
                not isinstance(spent, int)
                or not isinstance(limit, int)
                or limit > 800_000
            ):
                raise PiccoloError("Invalid approved session budget")
            if spent + charge > limit:
                raise PiccoloError("Cumulative live budget cannot fund this transfer")
            reservations[request_id] = charge
            ledger["reservations"] = reservations
            ledger["reserved_micro_usd"] = spent + charge
            stream.seek(0)
            json.dump(ledger, stream, indent=2)
            stream.flush()
            stream.truncate()
            os.fsync(stream.fileno())

    @override
    def poll(self, name: str, zone: str) -> Document:
        """Persist terminal outcomes and creation IDs before operations expire."""
        result = super().poll(name, zone)
        if text(result, "status") == "DONE":
            for action in self.manifest.entries("actions"):
                if text(action, "operation") != name or text(action, "zone") != zone:
                    continue
                action["settled"] = True
                action["error"] = str(failure(result) or "")
                self.manifest.put("actions", action)
                if text(action, "kind").endswith(".insert") and not failure(result):
                    kind = text(action, "kind").split(".")[0]
                    entry = self.manifest.lookup(kind, text(action, "name"), zone)
                    target_id = text(result, "target_id")
                    if entry and target_id:
                        if text(entry, "id") and text(entry, "id") != target_id:
                            raise PiccoloError(
                                "Operation target ID differs from manifest"
                            )
                        entry["id"] = target_id
                        self.manifest.put("resources", entry)
        return result

    def settle(self, action: Document) -> bool:
        """Poll accepted requests; missing operations remain unresolved."""
        kind = text(action, "kind")
        name = text(action, "name")
        zone = text(action, "zone")
        if kind in {
            "account.create",
            "secret.create",
            "account.delete",
            "secret.delete",
        }:
            resource_kind, verb = kind.split(".")
            deadline = time.monotonic() + self.config.gcp.operation_timeout
            absent_reads = 0
            while True:
                check_work()
                observed = self.get(resource_kind, name)
                if verb == "delete" and observed is None:
                    absent_reads += 1
                    if resource_kind != "account" or absent_reads >= 3:
                        break
                else:
                    absent_reads = 0
                if verb == "create" and observed is not None:
                    entry = self.manifest.lookup(resource_kind, name)
                    if entry is None or not self.owns(entry, observed):
                        return False
                    break
                if time.monotonic() >= deadline:
                    return False
                time.sleep(2)
        else:
            operation = text(action, "operation") or self.recover(
                text(action, "key"), zone
            )
            if not operation:
                return False
            action["operation"] = operation
            self.manifest.put("actions", action)
            deadline = time.monotonic() + self.config.gcp.operation_timeout
            while True:
                check_work()
                result = self.poll(operation, zone)
                if text(result, "status") == "DONE":
                    action["error"] = str(failure(result) or "")
                    break
                if time.monotonic() >= deadline:
                    return False
                time.sleep(2)
        action["settled"] = True
        self.manifest.put("actions", action)
        return True

    def inventory(self, kind: str) -> list[Document]:
        """Enumerate globally or across every zone, including replacement candidates."""
        match kind:
            case "recoverable_snapshot":
                from gcp_live_support.recycle_bin import RecycleBin

                return RecycleBin(self.project, self.clients.credentials).inventory()
            case "account":
                return [
                    decode(iam_admin_v1.ServiceAccount.to_json(a))
                    for a in self.clients.iam.list_service_accounts(
                        name=f"projects/{self.project}", retry=READ_RETRY, timeout=30
                    )
                ]
            case "secret":
                return [
                    decode(secretmanager_v1.Secret.to_json(s))
                    for s in self.clients.secrets.list_secrets(
                        parent=f"projects/{self.project}", retry=READ_RETRY, timeout=30
                    )
                ]
            case "firewall":
                return [
                    decode(compute_v1.Firewall.to_json(f))
                    for f in self.clients.firewalls.list(
                        project=self.project, retry=READ_RETRY, timeout=30
                    )
                ]
            case _:
                return self.list(kind)

    def purge_snapshots(self) -> None:
        """Purge only original snapshot identities proven by this run's manifest."""
        from gcp_live_support.recycle_bin import RecycleBin

        RecycleBin(self.project, self.clients.credentials).purge(self.manifest)

    def remove_ssh_key(self, entry: Document) -> None:
        """Use the configured connector to clean up its exact disposable test key."""
        from gcp_live_support.ssh_expiry import remove_test_key

        remove_test_key(self.config, self.manifest, entry)

    def delete(self, entry: Document) -> None:
        """Recheck ownership immediately and persist one bounded delete request."""
        gate(self.project)
        if entry.get("preserve") is True:
            raise PiccoloError("Existing policy targets cannot be deleted")
        kind, name, zone = (text(entry, k) for k in ("kind", "name", "zone"))
        observed = self.get(kind, name, zone)
        if observed is None:
            return
        # get may have captured an ID after an accepted response was lost.
        entry = self.manifest.lookup(kind, name, zone) or entry
        if not self.owns(entry, observed):
            raise PiccoloError("Resource changed before deletion")
        if kind == "disk" and observed.get("users"):
            raise PiccoloError("Disk still has users")
        previous = [
            a
            for a in self.manifest.entries("actions")
            if text(a, "kind") == f"{kind}.delete"
            and text(a, "name") == name
            and text(a, "zone") == zone
        ]
        if previous:
            if not all(a.get("settled") is True for a in previous):
                raise PiccoloError("Previous deletion remains uncertain")
            if not text(previous[-1], "error"):
                if kind == "account" and self.settle(previous[-1]):
                    return
                raise PiccoloError(
                    "Completed deletion still has a resource; inspect it"
                )
        if kind in {"instance", "disk", "snapshot"}:
            import uuid

            request = str(uuid.uuid4())
            self.submit(f"{kind}.delete", name, zone, {}, request)
            action = next(
                a for a in self.manifest.entries("actions") if text(a, "key") == request
            )
        else:
            action = self.manifest.intent(f"{kind}.delete", name, zone)
            if kind == "firewall":
                operation = self.perform(
                    action,
                    lambda: self.clients.firewalls.delete(
                        request=compute_v1.DeleteFirewallRequest(
                            project=self.project,
                            firewall=name,
                            request_id=text(action, "key"),
                        ),
                        retry=None,
                        timeout=30,
                    ),
                )
                action["operation"] = str(operation.name)
                self.manifest.put("actions", action)
            elif kind == "secret":
                self.perform(
                    action,
                    lambda: self.clients.secrets.delete_secret(
                        name=f"projects/{self.project}/secrets/{name}",
                        retry=None,
                        timeout=30,
                    ),
                )
            elif kind == "account":
                self.perform(
                    action,
                    lambda: self.clients.iam.delete_service_account(
                        name=f"projects/{self.project}/serviceAccounts/{name}",
                        retry=None,
                        timeout=30,
                    ),
                )
        if not self.settle(action):
            raise PiccoloError("Deletion remains uncertain; manifest retained")
        if text(action, "error"):
            raise PiccoloError(text(action, "error"))

    def policy(self, kind: str, resource: str) -> policy_pb2.Policy:
        """Read a fresh version-three policy with its current etag."""
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=resource,
            options=options_pb2.GetPolicyOptions(requested_policy_version=3),
        )
        if kind == "project":
            if resource != f"projects/{self.project}":
                raise PiccoloError("Project policy target is outside approval")
            return self.clients.projects.get_iam_policy(
                request=request, retry=READ_RETRY, timeout=30
            )
        if kind == "account":
            return self.clients.iam.get_iam_policy(
                request=request, retry=READ_RETRY, timeout=30
            )
        return self.clients.secrets.get_iam_policy(
            request=request, retry=READ_RETRY, timeout=30
        )

    def set_policy(self, kind: str, resource: str, policy: policy_pb2.Policy) -> None:
        """Set with the just-read etag, never restore a baseline policy wholesale."""
        gate(self.project)
        scope = "serviceAccounts" if kind == "account" else "secrets"
        name = resource.rsplit("/", 1)[-1]
        entry = self.manifest.lookup(kind, name)
        observed = self.get(kind, name)
        expected_resource = (
            f"projects/{self.project}"
            if kind == "project"
            else f"projects/{self.project}/{scope}/{name}"
        )
        if (
            resource != expected_resource
            or entry is None
            or observed is None
            or not self.owns(entry, observed)
        ):
            raise PiccoloError("Refusing IAM write outside this run")
        if not policy.etag:
            raise PiccoloError("Refusing IAM write without an etag")
        request = iam_policy_pb2.SetIamPolicyRequest(resource=resource, policy=policy)
        if kind == "project":
            self.clients.projects.set_iam_policy(
                request=request, retry=None, timeout=30
            )
        elif kind == "account":
            self.clients.iam.set_iam_policy(request=request, retry=None, timeout=30)
        else:
            self.clients.secrets.set_iam_policy(request=request, retry=None, timeout=30)

    def binding(self, kind: str, name: str, role: str, member: str) -> None:
        """Re-read and merge grants after definitively rejected IAM conflicts."""
        deadline = time.monotonic() + 60
        conflicts = 0
        while True:
            try:
                self._binding_once(kind, name, role, member)
                return
            except (exceptions.Aborted, exceptions.Conflict):
                conflicts += 1
                if conflicts == 3:
                    raise
                time.sleep(timeout(2 ** (conflicts - 1)))
            except exceptions.InvalidArgument as exc:
                if time.monotonic() >= deadline or not LiveAccess(
                    self
                ).account_propagating(exc):
                    raise
                time.sleep(timeout(min(2, max(0, deadline - time.monotonic()))))

    def _binding_once(self, kind: str, name: str, role: str, member: str) -> None:
        """Record only a missing grant on a proven fixture-owned policy target."""
        gate(self.project)
        if kind == "project":
            self.check_project_binding(name, role, member)
            self.preserve_external(kind, name)
        entry = self.manifest.lookup(kind, name)
        observed = self.get(kind, name)
        if entry is None or observed is None or not self.owns(entry, observed):
            raise PiccoloError("IAM mutation target is not run-owned")
        resource = (
            f"projects/{self.project}"
            if kind == "project"
            else (
                f"projects/{self.project}/serviceAccounts/{name}"
                if kind == "account"
                else f"projects/{self.project}/secrets/{name}"
            )
        )
        policy = self.policy(kind, resource)
        guest_id = ""
        if kind == "project":
            guest = self.get("account", self.config.gcp.service_account)
            if guest is None or not text(guest, "id"):
                raise PiccoloError("Project grant guest identity is unavailable")
            guest_id = text(guest, "id")
        if any(
            b.role == role and member in b.members and b.HasField("condition")
            for b in policy.bindings
        ) and not any(
            b.role == role and member in b.members and not b.HasField("condition")
            for b in policy.bindings
        ):
            raise PiccoloError("Conditional-only IAM access; refusing to widen it")
        if not add_binding(policy, role, member):
            return
        binding: Document = {
            "key": f"{resource}:{role}:{member}",
            "kind": kind,
            "name": name,
            "resource": resource,
            "role": role,
            "member": member,
            "target_id": text(observed, "id"),
            "absent_before": True,
            "guest_id": guest_id,
        }
        previous = next(
            (
                item
                for item in self.manifest.entries("bindings")
                if text(item, "key") == text(binding, "key")
            ),
            None,
        )
        if previous is not None and (
            text(previous, "target_id") != text(binding, "target_id")
            or text(previous, "guest_id") != guest_id
        ):
            raise PiccoloError("IAM grant identity changed during reconciliation")
        self.manifest.put("bindings", binding)
        self.set_policy(kind, resource, policy)

    def check_project_binding(self, name: str, role: str, member: str) -> None:
        """Limit project grants to approved roles and the exact guest identity."""
        gate(self.project)
        if (
            name != self.project
            or role not in self.config.gcp.project_roles
            or member != f"serviceAccount:{self.config.gcp.service_account}"
        ):
            raise PiccoloError("Project IAM grant is outside the approved guest roles")

    def remove_binding(self, entry: Document) -> None:
        """Remove only a recorded absent-before member; retain unrelated conditions."""
        kind, name = text(entry, "kind"), text(entry, "name")
        if kind == "project":
            self.check_project_binding(name, text(entry, "role"), text(entry, "member"))
            current = self.policy(kind, f"projects/{self.project}")
            if not any(
                b.role == text(entry, "role")
                and text(entry, "member") in b.members
                and not b.HasField("condition")
                for b in current.bindings
            ):
                return
            guest = self.get("account", self.config.gcp.service_account)
            if (
                guest is None
                or not text(entry, "guest_id")
                or text(guest, "id") != text(entry, "guest_id")
            ):
                raise PiccoloError("Project grant guest identity changed")
        observed = self.get(kind, name)
        if observed is None:
            return
        resource_entry = self.manifest.lookup(kind, name)
        if (
            resource_entry is None
            or not self.owns(resource_entry, observed)
            or entry.get("absent_before") is not True
            or text(entry, "target_id") != text(observed, "id")
        ):
            raise PiccoloError("IAM target identity changed; preserving policy")
        resource = text(entry, "resource")
        expected_resource = (
            f"projects/{self.project}"
            if kind == "project"
            else (
                f"projects/{self.project}/serviceAccounts/{name}"
                if kind == "account"
                else f"projects/{self.project}/secrets/{name}"
            )
        )
        if resource != expected_resource:
            raise PiccoloError("IAM resource is outside the recorded target")
        for attempt in range(3):
            policy = self.policy(kind, resource)
            changed = False
            for binding in list(policy.bindings):
                if (
                    binding.role == text(entry, "role")
                    and not binding.HasField("condition")
                    and text(entry, "member") in binding.members
                ):
                    binding.members.remove(text(entry, "member"))
                    if not binding.members:
                        policy.bindings.remove(binding)
                    changed = True
            if not changed:
                return
            try:
                entry["cleanup_status"] = "intent"
                self.manifest.put("bindings", entry)
                self.set_policy(kind, resource, policy)
                verified = self.policy(kind, resource)
                if any(
                    b.role == text(entry, "role")
                    and text(entry, "member") in b.members
                    and not b.HasField("condition")
                    for b in verified.bindings
                ):
                    raise PiccoloError("IAM grant removal was not verified")
                entry["cleanup_status"] = "removed"
                self.manifest.put("bindings", entry)
                return
            except (exceptions.Aborted, exceptions.Conflict):
                if attempt == 2:
                    raise

    def create_secret(self, name: str) -> None:
        """Create an empty dummy secret; no credential or payload is uploaded."""
        run = text(self.manifest.data, "run")
        self.prepare("secret", name, "", {"labels": {"piccolo-live-run": run}})
        action = self.manifest.intent("secret.create", name, "")
        self.perform(
            action,
            lambda: self.clients.secrets.create_secret(
                parent=f"projects/{self.project}",
                secret_id=name,
                secret=secretmanager_v1.Secret(
                    labels={"piccolo-live-run": run},
                    replication=secretmanager_v1.Replication(
                        automatic=secretmanager_v1.Replication.Automatic()
                    ),
                ),
                retry=None,
                timeout=30,
            ),
        )
        if not self.settle(action):
            raise PiccoloError("Dummy secret creation cannot be verified")

    @override
    def access(self) -> None:
        """Use manifest-aware access reconciliation, preserving enabled APIs."""
        LiveAccess(self).ensure()


class LiveProvider(GCPProvider):
    """Verify the actual fixture settings on creation and every recovery path."""

    @override
    def created(self, kind: str, name: str, zone: str, resource: Document) -> Document:
        """Include approved test login metadata in the expected instance settings."""
        if not isinstance(self.cloud, LiveCloud):
            raise PiccoloError("Live provider requires the manifest-backed adapter")
        initial_zone = os.environ.get("PICCOLO_GCP_LIVE_INIT_ZONE", "")
        if (
            initial_zone
            and self.journal.operation.get("kind") == "init"
            and kind in {"disk", "instance"}
            and zone != initial_zone
        ):
            raise PiccoloError(
                "Initial creation outside the approved initial zone is blocked"
            )
        if kind == "instance":
            resource = self.cloud.instance_settings(resource)
        try:
            return super().created(kind, name, zone, resource)
        except PiccoloError as exc:
            if "settings differ from the request" in str(exc):
                observed = self.cloud.get(kind, name, zone)
                self.cloud.manifest.put(
                    "verification",
                    {
                        "key": f"{kind}:{zone}:{name}",
                        "expected": resource,
                        "observed": observed,
                        "error": str(exc),
                    },
                )
            raise


class LiveAccess(Access):
    """Exercise Piccolo account creation while tracking access cleanup intent."""

    def __init__(self, cloud: LiveCloud) -> None:
        """Use the same provisioner clients and persisted run identity."""
        super().__init__(cloud.config, cloud.clients)
        self.cloud = cloud

    @override
    def account_propagating(self, error: exceptions.InvalidArgument) -> bool:
        """Prove this run created the exact principal rejected by Resource Manager."""
        name = self.gcp.service_account
        if (
            not self.gcp.create_service_account
            or f"service account {name} does not exist" not in str(error).lower()
        ):
            return False
        entry = self.cloud.manifest.lookup("account", name)
        observed = self.cloud.get("account", name)
        return (
            entry is not None
            and entry.get("absent_before") is True
            and observed is not None
            and observed.get("disabled") is not True
            and bool(text(entry, "id"))
            and self.cloud.owns(entry, observed)
        )

    @override
    def mutation(
        self,
        key: str,
        submit: Callable[[], str],
        observe: Callable[[], str],
        *,
        recover: Callable[[Document], str] | None = None,
    ) -> None:
        """Use the fixture manifest's enclosing account intent for test writes."""
        del recover
        if observe():
            return
        if (
            key != f"service-account:{self.gcp.service_account}"
            or not self.cloud.manifest.lookup("account", self.gcp.service_account)
        ):
            raise PiccoloError("Live access mutation lacks an enclosing fixture intent")
        submit()

    @override
    def service_account(self) -> None:
        """Create once through Piccolo, then grant temporary attachment rights."""
        name = self.gcp.service_account
        observed = self.cloud.get("account", name)
        if observed is None and self.gcp.create_service_account:
            self.cloud.prepare(
                "account",
                name,
                "",
                {"displayName": f"Piccolo {self.config.environment}"},
            )
            action = self.cloud.manifest.intent("account.create", name, "")
            gate(self.gcp.project_id)
            self.cloud.perform(action, super().service_account)
            if not self.cloud.settle(action):
                raise PiccoloError("VM account creation remains uncertain")
        elif self.cloud.manifest.lookup("account", name):
            entry = self.cloud.manifest.lookup("account", name)
            if (
                entry is None
                or observed is None
                or not self.cloud.owns(entry, observed)
            ):
                raise PiccoloError("Recorded account outcome is uncertain")
        else:
            # Existing accounts are inspected and never receive fixture IAM writes.
            super().service_account()
        if self.cloud.manifest.lookup("account", name):
            for member in (
                f"serviceAccount:{self.cloud.provisioner}",
                f"user:{self.gcp.connection_account}",
            ):
                self.cloud.binding(
                    "account", name, "roles/iam.serviceAccountUser", member
                )
        deadline = time.monotonic() + self.gcp.readiness_timeout
        while True:
            permissions = self.clients.iam.test_iam_permissions(
                request=iam_policy_pb2.TestIamPermissionsRequest(
                    resource=f"projects/{self.gcp.project_id}/serviceAccounts/{name}",
                    permissions=["iam.serviceAccounts.actAs"],
                ),
                retry=READ_RETRY,
                timeout=30,
            )
            if "iam.serviceAccounts.actAs" in permissions.permissions:
                break
            if (
                not self.cloud.manifest.lookup("account", name)
                or time.monotonic() >= deadline
            ):
                raise PiccoloError(
                    "Provisioner lacks actAs on VM account; no VM was created"
                )
            # IAM propagation is a read-only wait; account creation is never retried.
            time.sleep(2)

    @override
    def grant(self, resource: str, role: str, *, secret: bool) -> None:
        """Track approved project and dummy-secret grants for exact restoration."""
        if not secret:
            if resource != f"projects/{self.gcp.project_id}":
                raise PiccoloError("Project IAM target is outside approval")
            self.cloud.binding(
                "project",
                self.gcp.project_id,
                role,
                f"serviceAccount:{self.gcp.service_account}",
            )
            return
        self.cloud.binding(
            "secret",
            resource.rsplit("/", 1)[-1],
            role,
            f"serviceAccount:{self.gcp.service_account}",
        )

    @override
    def firewall(self) -> None:
        """Create the canonical Piccolo rule once with a persisted request ID."""
        name = self.gcp.firewall_name
        existing = self.cloud.get("firewall", name)
        entry = self.cloud.manifest.lookup("firewall", name)
        if existing:
            if entry is None or not self.cloud.owns(entry, existing):
                raise PiccoloError("Preserving pre-existing or replaced firewall")
            parsed = compute_v1.Firewall.from_json(json.dumps(existing))
            if not isinstance(parsed, compute_v1.Firewall):
                raise PiccoloError("Unexpected firewall SDK representation")
            if not self.firewall_matches(parsed):
                raise PiccoloError("Run firewall drifted; inspect it")
            return
        expected = self.firewall_spec()
        self.cloud.prepare("firewall", name, "", {"description": expected.description})
        action = self.cloud.manifest.intent("firewall.insert", name, "")
        operation = self.cloud.perform(
            action,
            lambda: self.clients.firewalls.insert(
                request=compute_v1.InsertFirewallRequest(
                    project=self.gcp.project_id,
                    firewall_resource=expected,
                    request_id=text(action, "key"),
                ),
                retry=None,
                timeout=30,
            ),
        )
        action["operation"] = str(operation.name)
        self.cloud.manifest.put("actions", action)
        if not self.cloud.settle(action) or text(action, "error"):
            raise PiccoloError("Firewall creation failed or remains uncertain")
