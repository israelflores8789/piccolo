# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""provider.py — GCP lifecycle orchestration with journaled init and relocation."""

import uuid
from collections.abc import Callable

from piccolo.bootstrap import execution, staging
from piccolo.config.models import Config
from piccolo.data import Document, Value, document, objects, text
from piccolo.errors import CapacityError, PiccoloError
from piccolo.providers.base import Connection
from piccolo.providers.gcp.auth import credentials
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.connection import GCloudConnection
from piccolo.providers.gcp.operations import Cloud, Operations, failure
from piccolo.providers.gcp.provision import (
    boot_disk,
    differences,
    instance_resource,
    labels,
    owned,
    reject_startup,
    validate_source,
    zone_of,
)
from piccolo.providers.gcp.resources import SDKCloud
from piccolo.state.journal import Journal


class GCPProvider:
    """Implement infrastructure operations independently of the CLI and SDK types."""

    capabilities = frozenset(
        {
            "init",
            "start",
            "stop",
            "move",
            "resume",
            "cleanup",
            "bootstrap",
            "connect",
            "tunnel",
        }
    )

    def __init__(
        self,
        config: Config,
        cloud: Cloud | None = None,
        connection: Connection | None = None,
        notify: Callable[[str], None] = print,
    ) -> None:
        """Accept injected adapters so lifecycle tests never contact GCP."""
        self.config = config
        self.gcp = config.gcp
        self.cloud = (
            cloud
            if cloud is not None
            else SDKCloud(config, Clients(credentials(config.gcp)))
        )
        self.connection = (
            connection if connection is not None else GCloudConnection(config.gcp)
        )
        self.journal = Journal(config)
        self.notify = notify
        self.operations = Operations(
            self.cloud, self.journal, self.gcp.operation_timeout, notify
        )

    def instances(self) -> list[Document]:
        """Discover all instances with the configured name across every zone."""
        return [
            item
            for item in self.cloud.list("instance")
            if text(item, "name") == self.gcp.name
        ]

    def active(self) -> Document:
        """Reject unresolved operations and accidental same-name duplicates."""
        if self.journal.operation:
            raise PiccoloError(
                "An unresolved operation exists; run resume before daily commands"
            )
        instances = self.instances()
        if len(instances) != 1:
            raise PiccoloError(
                f"Expected one {self.gcp.name} instance; found "
                f"{len(instances)}. Run init if absent, or "
                f"inspect duplicates"
            )
        selected = instances[0]
        self.check_owner(selected)
        recorded = text(self.journal.data, "active_instance_id")
        if recorded and text(selected, "id") != recorded:
            raise PiccoloError(
                "Instance identity changed outside Piccolo; "
                "inspect state before continuing"
            )
        if not recorded and not owned(self.config, selected):
            raise PiccoloError("Unrecorded legacy VM; review it and run init --adopt")
        return selected

    def check_owner(self, instance: Document) -> None:
        """Reject positive foreign ownership even when a local ID matches."""
        actual = document(instance.get("labels", {}))
        owner = text(actual, "piccolo-environment")
        if (owner and owner != text(labels(self.config), "piccolo-environment")) or (
            actual.get("managed-by") == "piccolo" and not owner
        ):
            raise PiccoloError("VM has foreign or incomplete Piccolo ownership")

    def disk(self, instance: Document) -> Document:
        """Inspect the disk identified by the attached boot flag."""
        attached = boot_disk(instance)
        name = text(attached, "source").split("/")[-1]
        disk = self.cloud.get("disk", name, zone_of(instance))
        if disk is None:
            raise PiccoloError("The boot disk is missing or cannot be inspected")
        return disk

    def inspect(self) -> Document:
        """Report all locations and operation state without changing anything."""
        return {
            "config": str(self.config.path),
            "project": self.gcp.project_id,
            "environment": self.config.environment,
            "instances": [document(item) for item in self.instances()],
            "operation": self.journal.operation,
            "bootstrap": document(
                self.journal.data.get("bootstrap", {"status": "unknown"})
            ),
        }

    def plan(self) -> Document:
        """Inspect VM drift and describe additive reconciliation without mutations."""
        instances = self.instances()
        drift: list[Value] = []
        if len(instances) > 1:
            drift.append(
                "Multiple same-name instances; inspect "
                "operation journal before proceeding"
            )
        if len(instances) == 1:
            drift.extend(
                differences(self.config, instances[0], self.disk(instances[0]))
            )
            if text(self.journal.data, "image", self.gcp.image) != self.gcp.image:
                drift.append("gcp.disk.image differs from the recorded image")
        return {
            "config": str(self.config.path),
            "project": self.gcp.project_id,
            "environment": self.config.environment,
            "action": "reconcile existing infrastructure"
            if instances
            else "provision a fresh VM",
            "zones": list(self.gcp.zones),
            "differences": drift,
            "access": self.cloud.access_plan(),
            "bootstrap": "stage on fresh provisioning only; never execute",
            "operation": self.journal.operation,
        }

    def safe_start(self, instance: Document) -> None:
        """Check ownership and both metadata scopes before lifecycle mutations."""
        self.check_owner(instance)
        reject_startup(document(instance.get("metadata", {})))
        reject_startup(self.cloud.project_metadata())

    def init(self, *, adopt: bool = False) -> None:
        """Reconcile an existing VM or journal fresh provisioning and script staging."""
        if self.journal.operation:
            raise PiccoloError("An unresolved operation exists; use resume")
        instances = self.instances()
        if len(instances) > 1:
            raise PiccoloError("Multiple same-name VMs exist; provisioning is blocked")
        if not instances and text(self.journal.data, "active_instance_id"):
            raise PiccoloError(
                "The previously recorded VM is missing; inspect retained disks "
                "and state before provisioning a different environment"
            )
        if instances:
            instance = instances[0]
            self.check_owner(instance)
            recorded_id = text(self.journal.data, "active_instance_id")
            if not owned(self.config, instance) and not recorded_id and not adopt:
                raise PiccoloError(
                    "Unrecorded legacy VM; review it and run init --adopt"
                )
            if recorded_id and text(instance, "id") != recorded_id:
                raise PiccoloError("Existing VM identity changed; inspect state")
            drift = differences(self.config, instance, self.disk(instance))
            if text(self.journal.data, "image", self.gcp.image) != self.gcp.image:
                drift.append("gcp.disk.image differs from the recorded image")
            if drift:
                raise PiccoloError(
                    "Existing VM differs; init will not rebuild it: " + "; ".join(drift)
                )
            self.safe_start(instance)
            self.journal.data["active_instance_id"] = text(instance, "id")
            self.journal.data["active_zone"] = zone_of(instance)
            self.journal.begin(
                {
                    "kind": "access",
                    "id": uuid.uuid4().hex,
                    "stage": "access",
                    "instance_id": text(instance, "id"),
                    "zone": zone_of(instance),
                    "adopted": adopt and not owned(self.config, instance),
                }
            )
            self.cloud.access()
            self.journal.finish()
            self.notify(
                "Existing infrastructure verified; bootstrap was not staged or executed"
            )
            return
        if adopt:
            raise PiccoloError("init --adopt requires an existing VM")
        reject_startup(self.cloud.project_metadata())
        self.journal.begin(
            {
                "kind": "init",
                "id": uuid.uuid4().hex,
                "stage": "access",
                "zones": list(self.gcp.zones),
            }
        )
        self.continue_init()

    def access(self) -> None:
        """Persist access intent and repeat additive reconciliation safely."""
        for instance in self.instances():
            self.check_owner(instance)
        operation = self.journal.operation
        operation["stage"] = "access"
        self.journal.update(operation)
        self.cloud.access()

    def created(self, kind: str, name: str, zone: str, resource: Document) -> Document:
        """Submit a creation once and verify both ownership and observed readiness."""
        operation = self.journal.operation
        existing = self.cloud.get(kind, name, zone)
        if existing and not owned(self.config, existing, text(operation, "id")):
            raise PiccoloError(f"{kind} {name} already exists with different ownership")
        recorded = next(
            (
                item
                for item in objects(operation, "artifacts")
                if item.get("kind") == kind
                and item.get("name") == name
                and item.get("zone") == zone
            ),
            None,
        )
        if recorded is not None and (
            existing is None or text(existing, "id") != text(recorded, "id")
        ):
            raise PiccoloError("Created artifact identity changed; retained")
        self.operations.run(
            f"{kind}.insert:{zone}:{name}", f"{kind}.insert", name, zone, resource
        )
        operation = self.journal.operation
        observed = self.cloud.get(kind, name, zone)
        if observed is None or not owned(self.config, observed, text(operation, "id")):
            raise PiccoloError(
                f"Created {kind} cannot be verified; preserve "
                f"the operation and run resume"
            )
        expected = "RUNNING" if kind == "instance" else "READY"
        if text(observed, "status") != expected:
            raise PiccoloError(
                f"{kind} {name} is not {expected}; run resume after inspection"
            )
        if kind in {"disk", "snapshot", "instance"}:
            artifacts = objects(operation, "artifacts")
            entry: Document = {
                "kind": kind,
                "name": name,
                "zone": zone,
                "id": text(observed, "id"),
                "operation_id": text(operation, "id"),
            }
            previous = next(
                (
                    item
                    for item in artifacts
                    if item["kind"] == kind
                    and item["name"] == name
                    and item["zone"] == zone
                ),
                None,
            )
            if previous is not None and previous != entry:
                raise PiccoloError("Created artifact identity changed; retained")
            if previous is None:
                artifacts.append(entry)
                operation["artifacts"] = [item for item in artifacts]
                self.journal.update(operation)
        return observed

    def candidate(
        self, zone: str, snapshot: str = "", source: Document | None = None
    ) -> Document:
        """Create a labelled zonal disk, then the VM, retaining failed-attempt disks."""
        operation = self.journal.operation
        operation_id = text(operation, "id")
        disk_name = f"{self.gcp.name[:44]}-{operation_id[:12]}-boot"
        subnet = self.cloud.subnet(zone)
        disk_resource: Document = {
            "name": disk_name,
            "size_gb": self.gcp.size_gb,
            "type_": f"zones/{zone}/diskTypes/{self.gcp.disk_type}",
            "labels": labels(self.config, operation_id),
        }
        if snapshot:
            disk_resource["source_snapshot"] = (
                f"projects/{self.gcp.project_id}/global/snapshots/{snapshot}"
            )
            original_disk = document(operation["source_disk"])
            disk_resource["size_gb"] = original_disk["size_gb"]
        else:
            disk_resource["source_image"] = self.gcp.image
        disk = self.created("disk", disk_name, zone, disk_resource)
        link = text(
            disk,
            "self_link",
            f"projects/{self.gcp.project_id}/zones/{zone}/disks/{disk_name}",
        )
        return self.created(
            "instance",
            self.gcp.name,
            zone,
            instance_resource(self.config, zone, link, subnet, operation_id, source),
        )

    def choose(self, source: Document | None = None) -> Document:
        """Try only confirmed capacity failures and block ambiguous duplicate."""
        operation = self.journal.operation
        zones = operation.get("zones")
        if not isinstance(zones, list):
            raise PiccoloError("Invalid journal zone policy")
        source_zone = zone_of(source) if source else ""
        for candidate_zone in zones:
            operation = self.journal.operation
            if not isinstance(candidate_zone, str):
                raise PiccoloError("Invalid journal candidate zone")
            failed = any(
                text(action, "zone") == candidate_zone
                and text(action, "kind") in {"disk.insert", "instance.insert"}
                and text(action, "status") == "failed"
                and action.get("capacity") is True
                for action in objects(operation, "actions")
            )
            if failed:
                if (
                    self.cloud.get("instance", self.gcp.name, candidate_zone)
                    is not None
                ):
                    raise PiccoloError("Capacity failure left a VM resource; inspect")
                continue
            operation["candidate_zone"] = candidate_zone
            self.journal.update(operation)
            self.notify(f"Trying {candidate_zone}")
            current = self.instances()
            if any(
                zone_of(item) not in {source_zone, candidate_zone} for item in current
            ):
                raise PiccoloError(
                    "Another same-name VM exists; no additional creation is safe"
                )
            if source and any(
                zone_of(item) == source_zone and text(item, "status") != "TERMINATED"
                for item in current
            ):
                raise PiccoloError(
                    "Source is no longer stopped; destination creation is blocked"
                )
            try:
                return self.candidate(
                    candidate_zone, text(operation, "snapshot"), source
                )
            except CapacityError:
                if (
                    self.cloud.get("instance", self.gcp.name, candidate_zone)
                    is not None
                ):
                    raise PiccoloError(
                        "Capacity failure left a VM resource; inspect "
                        "before trying another zone"
                    ) from None
                self.notify(f"Confirmed capacity exhaustion in {candidate_zone}")
        raise CapacityError(
            "No configured destination has capacity; "
            "resources and recovery artifacts retained. "
            "For a move, resume --rollback can restart the "
            "source only after confirmed failure"
        )

    def continue_init(self) -> None:
        """Resume initial creation with the original request IDs and."""
        self.access()
        reject_startup(self.cloud.project_metadata())
        replacement = self.choose()
        disk = self.disk(replacement)
        self.journal.data["active_instance_id"] = text(replacement, "id")
        self.journal.data["active_zone"] = zone_of(replacement)
        self.journal.data["fresh_disk_id"] = text(disk, "id")
        self.journal.data["image"] = self.gcp.image
        operation = self.journal.operation
        operation["stage"] = "stage-bootstrap"
        self.journal.update(operation)
        staging.stage(
            self.config,
            self.journal,
            self.connection,
            zone_of(replacement),
            text(disk, "id"),
        )
        self.journal.finish()
        self.notify("Infrastructure ready; bootstrap execution remains explicit")

    def start(self) -> str:
        """Start an existing VM, recording uncertain start operations for resume."""
        instance = self.active()
        self.safe_start(instance)
        zone = zone_of(instance)
        if text(instance, "status") == "RUNNING":
            return zone
        if text(instance, "status") != "TERMINATED":
            raise PiccoloError(
                "VM must be RUNNING or TERMINATED; inspect its transition"
            )
        self.journal.begin(
            {
                "kind": "start",
                "id": uuid.uuid4().hex,
                "zone": zone,
                "instance_id": text(instance, "id"),
            }
        )
        self.continue_power()
        return zone

    def stop(self) -> None:
        """Stop an existing VM without touching its disk or setup."""
        instance = self.active()
        self.safe_start(instance)
        if text(instance, "status") == "TERMINATED":
            return
        if text(instance, "status") != "RUNNING":
            raise PiccoloError(
                "VM must be RUNNING or TERMINATED; inspect its transition"
            )
        self.journal.begin(
            {
                "kind": "stop",
                "id": uuid.uuid4().hex,
                "zone": zone_of(instance),
                "instance_id": text(instance, "id"),
            }
        )
        self.continue_power()

    def continue_power(self) -> None:
        """Verify instance identity and await a start or stop operation."""
        operation = self.journal.operation
        kind, zone = text(operation, "kind"), text(operation, "zone")
        instance = self.cloud.get("instance", self.gcp.name, zone)
        if instance is None or text(instance, "id") != text(operation, "instance_id"):
            raise PiccoloError("Power-operation target identity changed")
        self.safe_start(instance)
        self.operations.run(kind, f"instance.{kind}", self.gcp.name, zone)
        observed = self.cloud.get("instance", self.gcp.name, zone)
        expected = "RUNNING" if kind == "start" else "TERMINATED"
        if observed is None or text(observed, "status") != expected:
            raise PiccoloError(f"VM did not reach {expected}; inspect and resume")
        self.journal.finish()

    def move(self, destination: str | None) -> None:
        """Inspect and journal the source before protecting or stopping."""
        source = self.active()
        setup = document(self.journal.data.get("bootstrap", {}))
        if text(setup, "status") in {"started", "uncertain"}:
            raise PiccoloError(
                "Bootstrap may still be running; inspect bootstrap --status "
                "before moving the VM"
            )
        if text(source, "status") not in {"RUNNING", "TERMINATED"}:
            raise PiccoloError("Source must be RUNNING or TERMINATED")
        disk = self.disk(source)
        validate_source(self.config, source, disk)
        self.safe_start(source)
        zones = (
            [destination]
            if destination
            else [zone for zone in self.gcp.zones if zone != zone_of(source)]
        )
        if not zones or any(zone == zone_of(source) for zone in zones):
            raise PiccoloError("Move requires at least one distinct destination zone")
        if destination:
            from piccolo.config.loader import named

            named(destination, "--to", r"[a-z]+-[a-z]+[0-9]+-[a-z]")
        for zone in zones:
            self.cloud.subnet(zone)
        operation_id = uuid.uuid4().hex
        self.journal.begin(
            {
                "kind": "move",
                "id": operation_id,
                "stage": "inspect",
                "source": source,
                "source_disk": disk,
                "zones": [zone for zone in zones],
                "snapshot": f"{self.gcp.name[:40]}-move-{operation_id[:12]}",
            }
        )
        self.continue_move()

    def source(self) -> Document | None:
        """Re-inspect a journaled source and reject resource replacement by name."""
        recorded = document(self.journal.operation["source"])
        source = self.cloud.get("instance", self.gcp.name, zone_of(recorded))
        if source is not None and text(source, "id") != text(recorded, "id"):
            raise PiccoloError(
                "Source instance identity changed; move recovery is blocked"
            )
        if source is not None:
            self.check_owner(source)
        return source

    def continue_move(self) -> None:
        """Protect, stop, snapshot, replace, verify SSH, commit, and clean up."""
        operation = self.journal.operation
        self.journal.check_fingerprint()
        if operation.get("committed") is True:
            self.commit_cleanup()
            return
        recorded = document(operation["source"])
        zone = zone_of(recorded)
        source = self.source()
        if source is None:
            raise PiccoloError(
                "Source disappeared before commit; preserve recovery artifacts"
            )
        self.safe_start(source)
        original_disk = document(operation["source_disk"])
        disk = self.disk(source)
        if text(disk, "id") != text(original_disk, "id"):
            raise PiccoloError("Source boot disk identity changed")
        validate_source(self.config, source, disk)
        self.operations.run(
            "protect-source",
            "instance.protect",
            self.gcp.name,
            zone,
            {"device_name": text(boot_disk(source), "device_name")},
        )
        if (
            text(recorded, "status") == "RUNNING"
            or text(source, "status") != "TERMINATED"
        ):
            self.operations.run("stop-source", "instance.stop", self.gcp.name, zone)
        stopped = self.source()
        if stopped is None or text(stopped, "status") != "TERMINATED":
            raise PiccoloError(
                "Source is not confirmed stopped; snapshot/creation blocked"
            )
        snapshot_name = text(operation, "snapshot")
        self.created(
            "snapshot",
            snapshot_name,
            "",
            {
                "name": snapshot_name,
                "source_disk": text(boot_disk(stopped), "source"),
                "storage_locations": [self.gcp.snapshot_location],
                "labels": labels(self.config, text(operation, "id")),
            },
        )
        replacement = self.choose(recorded)
        operation = self.journal.operation
        operation["replacement_zone"] = zone_of(replacement)
        operation["replacement_id"] = text(replacement, "id")
        operation["stage"] = "readiness"
        self.journal.update(operation)
        self.connection.ready(zone_of(replacement))
        source = self.source()
        if source is None or text(source, "status") != "TERMINATED":
            raise PiccoloError(
                "Source changed during readiness verification; commit blocked"
            )
        verified = self.cloud.get("instance", self.gcp.name, zone_of(replacement))
        if (
            verified is None
            or text(verified, "id") != text(replacement, "id")
            or text(verified, "status") != "RUNNING"
        ):
            raise PiccoloError("Replacement changed during readiness verification")
        self.check_owner(verified)
        operation["committed"] = True
        operation["stage"] = "committed"
        self.journal.data["active_instance_id"] = text(replacement, "id")
        self.journal.data["active_zone"] = zone_of(replacement)
        self.journal.update(operation)
        self.commit_cleanup()

    def commit_cleanup(self) -> None:
        """Delete only verified retired resources after a durable replacement commit."""
        operation = self.journal.operation
        replacement = self.cloud.get(
            "instance", self.gcp.name, text(operation, "replacement_zone")
        )
        if (
            replacement is None
            or text(replacement, "id") != text(operation, "replacement_id")
            or text(replacement, "status") != "RUNNING"
        ):
            raise PiccoloError(
                "Committed replacement is missing or stopped; "
                "recovery resources retained"
            )
        self.check_owner(replacement)
        source = self.source()
        source_record = document(operation["source"])
        zone = zone_of(source_record)
        if source:
            self.safe_start(source)
            if (
                text(source, "status") != "TERMINATED"
                or boot_disk(source).get("auto_delete") is not False
            ):
                raise PiccoloError(
                    "Retired source is not stopped with a protected boot disk"
                )
            self.operations.run("delete-source", "instance.delete", self.gcp.name, zone)
        disk_record = document(operation["source_disk"])
        disk_name = text(disk_record, "name")
        disk = self.cloud.get("disk", disk_name, zone)
        if disk and owned(self.config, disk):
            if text(disk, "id") != text(disk_record, "id") or disk.get("users"):
                raise PiccoloError("Retired boot disk changed or is attached; retained")
            self.operations.run("delete-source-disk", "disk.delete", disk_name, zone)
        elif disk:
            self.notify(
                "Retained original boot disk because it was not created by Piccolo"
            )
        snapshot = self.cloud.get("snapshot", text(operation, "snapshot"))
        if snapshot:
            if not owned(self.config, snapshot, text(operation, "id")):
                raise PiccoloError("Recovery snapshot ownership changed; retained")
            self.operations.run(
                "delete-snapshot", "snapshot.delete", text(operation, "snapshot")
            )
        self.journal.finish()
        self.notify(
            "Move complete; disk contents preserved and bootstrap was not executed"
        )

    def resume(self) -> None:
        """Recover using recorded requests, resource identities, and original config."""
        self.journal.check_fingerprint()
        match text(self.journal.operation, "kind"):
            case "init":
                self.continue_init()
            case "move":
                if self.journal.operation.get("rollback_requested") is True:
                    self.rollback()
                else:
                    self.continue_move()
            case "start" | "stop":
                self.continue_power()
            case "access":
                target = self.cloud.get(
                    "instance", self.gcp.name, text(self.journal.operation, "zone")
                )
                if target is None or text(target, "id") != text(
                    self.journal.operation, "instance_id"
                ):
                    raise PiccoloError("Access target identity changed; retained")
                self.safe_start(target)
                self.cloud.access()
                self.journal.finish()
            case "cleanup":
                self.continue_cleanup()
            case "":
                self.notify("No unresolved infrastructure operation")
            case _:
                raise PiccoloError("Unsupported journal operation; inspect state")

    def rollback(self) -> None:
        """Restart a move source only when all replacement requests are settled."""
        operation = self.journal.operation
        self.journal.check_fingerprint()
        if text(operation, "kind") != "move" or operation.get("committed"):
            raise PiccoloError("Rollback requires an uncommitted move")
        source = self.source()
        if source is None:
            raise PiccoloError("Rollback source is missing")
        for action in objects(operation, "actions"):
            if text(action, "key") == "rollback-start":
                continue
            if text(action, "status") not in {"done", "failed"}:
                raise PiccoloError(
                    "A request is unresolved; reconcile it with resume before rollback"
                )
        if any(zone_of(item) != zone_of(source) for item in self.instances()):
            raise PiccoloError("A replacement exists; restarting the source is unsafe")
        self.safe_start(source)
        operation["rollback_requested"] = True
        self.journal.update(operation)
        self.operations.run(
            "rollback-start", "instance.start", self.gcp.name, zone_of(source)
        )
        observed = self.source()
        if observed is None or text(observed, "status") != "RUNNING":
            raise PiccoloError(
                "Source restart could not be verified; retain all recovery data"
            )
        self.journal.data["active_instance_id"] = text(source, "id")
        self.journal.data["active_zone"] = zone_of(source)
        self.journal.finish()
        self.notify(
            "Source restarted; inspect retained snapshots and disks with cleanup"
        )

    def cleanup(self, apply: bool) -> Document:
        """Require completed local manifests before making artifacts eligible."""
        resources = [*self.cloud.list("disk"), *self.cloud.list("snapshot")]
        eligible: list[Value] = []
        protected: list[Value] = []
        for item in resources:
            if not owned(self.config, item) or not text(
                document(item.get("labels", {})), "piccolo-operation"
            ):
                continue
            kind = "disk" if item.get("zone") else "snapshot"
            entry: Document = {
                "kind": kind,
                "name": text(item, "name"),
                "zone": zone_of(item) if kind == "disk" else "",
                "id": text(item, "id"),
                "operation_id": text(document(item["labels"]), "piccolo-operation"),
            }
            if (
                item.get("users")
                or self.journal.operation
                or not self.cleanup_authorized(entry)
            ):
                protected.append(entry)
            else:
                eligible.append(entry)
        result: Document = {
            "eligible": eligible,
            "protected": protected,
            "apply": apply,
        }
        if apply:
            if self.journal.operation:
                raise PiccoloError(
                    "Cleanup cannot apply during an unresolved operation"
                )
            self.journal.begin(
                {"kind": "cleanup", "id": uuid.uuid4().hex, "resources": eligible}
            )
            self.continue_cleanup()
        return result

    def cleanup_authorized(self, entry: Document) -> bool:
        """Verify exact history, settled cloud requests, and environment topology."""
        if not text(entry, "id") or not text(entry, "operation_id"):
            return False
        origin = next(
            (
                item
                for item in objects(self.journal.data, "history")
                if text(item, "id") == text(entry, "operation_id")
            ),
            None,
        )
        if (
            origin is None
            or text(origin, "stage") != "complete"
            or text(origin, "kind") not in {"init", "move"}
            or entry not in objects(origin, "artifacts")
        ):
            return False
        current = self.instances()
        if len(current) != 1 or text(current[0], "id") != text(
            self.journal.data, "active_instance_id"
        ):
            return False
        self.check_owner(current[0])
        for instance in self.cloud.list("instance"):
            for disk in objects(instance, "disks"):
                source = text(disk, "source")
                if text(entry, "kind") == "disk" and source.endswith(
                    f"/zones/{text(entry, 'zone')}/disks/{text(entry, 'name')}"
                ):
                    return False
        actions = objects(origin, "actions")
        if not actions:
            return False
        for action in actions:
            status, operation_id = text(action, "status"), text(action, "operation_id")
            if status not in {"done", "failed"} or not operation_id:
                return False
            result = self.cloud.poll(operation_id, text(action, "zone"))
            if text(result, "status") != "DONE":
                return False
            if (failure(result) is None) != (status == "done"):
                return False
        return True

    def continue_cleanup(self) -> None:
        """Recheck ownership, immutable ID, and attachments before deletion."""
        operation = self.journal.operation
        for entry in objects(operation, "resources"):
            kind, name, zone = (
                text(entry, "kind"),
                text(entry, "name"),
                text(entry, "zone"),
            )
            actual = self.cloud.get(kind, name, zone)
            if actual is None:
                continue
            if (
                not owned(self.config, actual, text(entry, "operation_id"))
                or text(actual, "id") != text(entry, "id")
                or actual.get("users")
                or not self.cleanup_authorized(entry)
            ):
                raise PiccoloError(
                    f"Cleanup target {name} changed or is attached; retained"
                )
            self.operations.run(
                f"delete:{kind}:{zone}:{name}", f"{kind}.delete", name, zone
            )
        self.journal.finish()

    def bootstrap(self, dry_run: bool, status: bool) -> Document:
        """Invoke the shared opaque bootstrap policy on the observed."""
        instance = self.active()
        return execution.execute(
            self.config,
            self.journal,
            self.connection,
            zone_of(instance),
            text(self.disk(instance), "id"),
            dry_run=dry_run,
            status=status,
        )
