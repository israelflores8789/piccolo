# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""manifest.py — Durable live-test intent and conservative independent cleanup.

Set PICCOLO_GCP_LIVE_PROJECT to the approved project before live use.
"""

import os
import re
import uuid
from pathlib import Path
from typing import Protocol

from gcp_live_support.deadline import check_work, phase
from piccolo.data import Document, objects, text
from piccolo.errors import PiccoloError
from piccolo.privacy import sanitize_text
from piccolo.state.journal import Journal
from piccolo.state.storage import private_directory, private_file

PROJECT_ID_PATTERN = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
RESOURCE_KINDS = ("instance", "disk", "snapshot", "firewall", "secret", "account")


def approved_project() -> str:
    """Read an explicit approved project ID without a default or normalization."""
    project = os.environ.get("PICCOLO_GCP_LIVE_PROJECT", "")
    if re.fullmatch(PROJECT_ID_PATTERN, project) is None:
        raise PiccoloError("Set PICCOLO_GCP_LIVE_PROJECT to a valid exact project ID")
    return project


def gate(project: str) -> None:
    """Require opt-in and exact approval of the recorded or configured project."""
    if os.environ.get("PICCOLO_GCP_LIVE") != "1" or project != approved_project():
        raise PiccoloError(
            "Live GCP requires PICCOLO_GCP_LIVE=1 and "
            "PICCOLO_GCP_LIVE_PROJECT set to the exact project "
            "in the configuration/manifest"
        )


def resource_key(kind: str, name: str, zone: str = "") -> str:
    """Return an exact manifest identity independent of list order."""
    return f"{kind}:{zone}:{name}"


def resource_url(project: str, kind: str, name: str, zone: str = "") -> str:
    """Return a sanitized API URL for a resource requiring manual recovery."""
    project = f"projects/{project}"
    if kind == "account":
        return f"https://iam.googleapis.com/v1/{project}/serviceAccounts/{name}"
    if kind == "secret":
        return f"https://secretmanager.googleapis.com/v1/{project}/secrets/{name}"
    scope = f"zones/{zone}" if zone else "global"
    return f"https://www.googleapis.com/compute/v1/{project}/{scope}/{kind}s/{name}"


class Manifest(Journal):
    """Reuse durable atomic journal writes for a separate run resource manifest."""

    @classmethod
    def create(
        cls, path: Path, config_path: Path, run: str, *, project: str
    ) -> "Manifest":
        """Persist run identity before constructing any mutating cloud adapter."""
        if path.exists():
            raise PiccoloError("Refusing to overwrite an existing run manifest")
        gate(project)
        result = cls.__new__(cls)
        result.path = path.absolute()
        result.directory = result.path.parent
        result.data = {
            "schema_version": 1,
            "project": project,
            "run": run,
            "config": str(config_path.resolve()),
            "resources": [],
            "actions": [],
            "bindings": [],
            "complete": False,
        }
        result.validate()
        result.save()
        return result

    @classmethod
    def open(cls, path: Path) -> "Manifest":
        """Read a retained manifest without needing the original test process."""
        from piccolo.data import decode

        result = cls.__new__(cls)
        result.path = path.absolute()
        result.directory = result.path.parent
        private_directory(result.directory.parent, create=False)
        private_directory(result.directory, create=False)
        with os.fdopen(private_file(result.path)) as stream:
            result.data = decode(stream.read())
        result.validate()
        return result

    def validate(self) -> None:
        """Reject unsupported versions, projects, and non-random run prefixes."""
        if (
            self.data.get("schema_version") != 1
            or re.fullmatch(PROJECT_ID_PATTERN, text(self.data, "project")) is None
            or re.fullmatch(r"plive-[0-9a-f]{16}", text(self.data, "run")) is None
        ):
            raise PiccoloError("Invalid live-test manifest project/run/version")

    def entries(self, section: str) -> list[Document]:
        """Read checked records; callers persist changes using put."""
        return objects(self.data, section)

    def put(self, section: str, entry: Document) -> None:
        """Flush an intent or observation before the caller proceeds."""
        records = self.entries(section)
        key = text(entry, "key")
        self.data[section] = [item for item in records if text(item, "key") != key]
        records_value = self.data[section]
        if not isinstance(records_value, list):
            raise PiccoloError("Invalid manifest section")
        records_value.append(entry)
        self.data["complete"] = False
        self.save()

    def lookup(self, kind: str, name: str, zone: str = "") -> Document | None:
        """Find only an exactly registered resource."""
        key = resource_key(kind, name, zone)
        return next(
            (
                r
                for r in self.entries("resources") + self.entries("external_resources")
                if text(r, "key") == key
            ),
            None,
        )

    def register(self, kind: str, name: str, zone: str, proof: Document) -> Document:
        """Record verified absence and ownership proof before creating a resource."""
        run = text(self.data, "run")
        if kind not in RESOURCE_KINDS or not name.startswith(f"{run}-"):
            raise PiccoloError("Resource name is outside this run")
        previous = self.lookup(kind, name, zone)
        if previous is not None:
            return previous
        entry: Document = {
            "key": resource_key(kind, name, zone),
            "kind": kind,
            "name": name,
            "zone": zone,
            "absent_before": True,
            "proof": proof,
            "id": "",
            "url": resource_url(text(self.data, "project"), kind, name, zone),
        }
        self.put("resources", entry)
        return entry

    def intent(self, kind: str, name: str, zone: str, request: str = "") -> Document:
        """Persist a unique request before submission, including janitor deletes."""
        check_work()
        request = request or str(uuid.uuid4())
        previous = next(
            (a for a in self.entries("actions") if text(a, "key") == request), None
        )
        if previous:
            raise PiccoloError("Refusing to resubmit a recorded cloud mutation")
        action: Document = {
            "key": request,
            "kind": kind,
            "name": name,
            "zone": zone,
            "operation": "",
            "settled": False,
        }
        self.put("actions", action)
        return action


class CleanupBackend(Protocol):
    """Inject cloud operations so recovery failures can be tested offline."""

    def get(self, kind: str, name: str, zone: str = "") -> Document | None:
        """Inspect a resource; only confirmed NotFound returns None."""
        ...

    def inventory(self, kind: str) -> list[Document]:
        """Enumerate all pages, failing on incomplete discovery."""
        ...

    def settle(self, action: Document) -> bool:
        """Reconcile a persisted submission; never retry an uncertain create."""
        ...

    def owns(self, entry: Document, observed: Document) -> bool:
        """Check the manifest proof and immutable ID against current state."""
        ...

    def delete(self, entry: Document) -> None:
        """Persist and submit a scoped deletion after safety checks."""
        ...

    def remove_binding(self, entry: Document) -> None:
        """Remove only this run's added member from a freshly read IAM policy."""
        ...

    def remove_ssh_key(self, entry: Document) -> None:
        """Remove only an independently recorded disposable connection key."""
        ...


def cleanup_actions(
    manifest: Manifest, backend: CleanupBackend, *, apply: bool = False
) -> list[str]:
    """Reconcile first, delete in dependency order, and retain every failure."""
    manifest.validate()
    if apply:
        gate(text(manifest.data, "project"))
    failures: list[str] = []
    # A late accepted creation must finish before any dependent resource is deleted.
    for action in manifest.entries("actions"):
        if action.get("settled") is True:
            continue
        try:
            check_work()
            if not backend.settle(action):
                failures.append(f"Unresolved request {text(action, 'key')}")
        except Exception as exc:
            failures.append(f"Cannot settle {text(action, 'key')}: {exc}")
    if failures or not apply:
        if failures:
            manifest.data["cleanup_failures"] = [message for message in failures]
            manifest.data["complete"] = False
            manifest.save()
        return failures
    for kind in RESOURCE_KINDS:
        # Keep accounts, secrets, and their policies until all compute is gone.
        if failures:
            break
        if kind == "secret":
            for binding in manifest.entries("bindings"):
                try:
                    check_work()
                    backend.remove_binding(binding)
                except Exception as exc:
                    failures.append(f"IAM {text(binding, 'key')}: {exc}")
            if failures:
                break
        for entry in manifest.entries("resources"):
            if text(entry, "kind") != kind:
                continue
            label = text(entry, "url", text(entry, "key"))
            try:
                check_work()
                observed = backend.get(kind, text(entry, "name"), text(entry, "zone"))
                if observed is None:
                    continue
                if not backend.owns(entry, observed):
                    raise PiccoloError("Ownership or immutable identity changed")
                if kind == "disk" and observed.get("users"):
                    raise PiccoloError("Disk remains attached; preserve it")
                if kind == "instance":
                    for disk in objects(observed, "disks"):
                        source = text(disk, "source")
                        owned_disk = manifest.lookup(
                            "disk", source.rsplit("/", 1)[-1], text(entry, "zone")
                        )
                        if owned_disk is None or disk.get("auto_delete") is True:
                            raise PiccoloError(
                                "Untracked or auto-delete disk; preserve VM"
                            )
                        observed_disk = backend.get(
                            "disk", text(owned_disk, "name"), text(owned_disk, "zone")
                        )
                        if observed_disk is None or not backend.owns(
                            owned_disk, observed_disk
                        ):
                            raise PiccoloError(
                                "Attached disk identity changed; preserve VM"
                            )
                check_work()
                backend.delete(entry)
                if backend.get(kind, text(entry, "name"), text(entry, "zone")):
                    raise PiccoloError("Deletion not verified")
            except Exception as exc:
                failures.append(f"{label}: {exc}")
    if not failures:
        for entry in manifest.entries("ssh_keys"):
            try:
                check_work()
                backend.remove_ssh_key(entry)
            except Exception as exc:
                failures.append(f"SSH key {text(entry, 'key')}: {exc}")
    return failures


def residual_report(
    manifest: Manifest, backend: CleanupBackend, failures: list[str]
) -> list[str]:
    """Inventory even after cleanup failures, distinguishing leftovers/unknowns."""
    run = text(manifest.data, "run")
    leftovers: list[Document] = []
    unknown: list[str] = []
    with phase("inventory"):
        for kind in RESOURCE_KINDS:
            try:
                check_work()
                observed_resources = backend.inventory(kind)
            except Exception as exc:
                message = f"Incomplete {kind} inventory: {exc}"
                failures.append(message)
                unknown.append(kind)
                continue
            for observed in observed_resources:
                name = text(observed, "name").rsplit("/", 1)[-1]
                if kind == "account":
                    name = text(observed, "email", name)
                if name.startswith(f"{run}-"):
                    zone = text(observed, "zone").rsplit("/", 1)[-1]
                    url = resource_url(text(manifest.data, "project"), kind, name, zone)
                    failures.append(f"Leftover {kind}: {url}")
                    leftovers.append(
                        {
                            "kind": kind,
                            "name": name,
                            "zone": zone,
                            "id": text(
                                observed,
                                "id",
                                text(
                                    observed, "uniqueId", text(observed, "createTime")
                                ),
                            ),
                            "status": text(observed, "status"),
                            "url": url,
                        }
                    )
    failures = [sanitize_text(message) for message in failures]
    manifest.data["residual_cost_exposure"] = {
        "dollar_limit_enforced": False,
        "remaining_resources": [entry for entry in leftovers],
        "unverified_inventory": [kind for kind in unknown],
        "unverified_resources": [
            {
                "kind": text(entry, "kind"),
                "name": text(entry, "name"),
                "zone": text(entry, "zone"),
                "last_recorded_id": text(entry, "id"),
                "url": text(entry, "url"),
                "verification": "final inventory unavailable",
            }
            for entry in manifest.entries("resources")
            if text(entry, "kind") in unknown
        ],
        "unverified_cleanup": [
            message for message in failures if not message.startswith("Leftover ")
        ],
        "operator_responsibility": (
            "Resources may continue billing; no maximum bill is guaranteed"
        ),
    }
    manifest.data["cleanup_failures"] = [message for message in failures]
    manifest.data["complete"] = not failures
    manifest.save()
    return failures


def cleanup(
    manifest: Manifest, backend: CleanupBackend, *, apply: bool = False
) -> list[str]:
    """Reserve cleanup time and always report final exposure after apply attempts."""
    manifest.validate()
    if apply:
        gate(text(manifest.data, "project"))
    failures: list[str] = []
    try:
        with phase("cleanup"):
            failures = cleanup_actions(manifest, backend, apply=apply)
    except BaseException as exc:
        failures.append(
            f"Cleanup interrupted or could not be verified: {type(exc).__name__}"
        )
        if apply:
            residual_report(manifest, backend, failures)
        raise
    return residual_report(manifest, backend, failures) if apply else failures
