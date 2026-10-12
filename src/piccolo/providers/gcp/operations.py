# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""operations.py — Persist Compute requests and reconcile uncertain submissions."""

import time
import uuid
from collections.abc import Callable
from typing import Protocol

from piccolo.data import Document, Value, document, objects, text
from piccolo.errors import CapacityError, PiccoloError, UncertainError
from piccolo.state.journal import Journal

CAPACITY_CODES = frozenset(
    {"ZONE_RESOURCE_POOL_EXHAUSTED", "ZONE_RESOURCE_POOL_EXHAUSTED_WITH_DETAILS"}
)


class Cloud(Protocol):
    """Represent SDK infrastructure using typed JSON resource documents."""

    def get(self, kind: str, name: str, zone: str = "") -> Document | None:
        """Inspect a resource; return None only for confirmed NotFound."""
        ...

    def list(self, kind: str) -> list[Document]:
        """Enumerate resources completely, including all pages."""
        ...

    def submit(
        self, kind: str, name: str, zone: str, resource: Document, request_id: str
    ) -> str:
        """Submit one mutation with automatic mutation retries disabled."""
        ...

    def poll(self, name: str, zone: str) -> Document:
        """Read a Compute operation with bounded transient retries."""
        ...

    def recover(self, request_id: str, zone: str) -> str:
        """Find a submitted operation by its persisted client request ID."""
        ...

    def access(self) -> None:
        """Reconcile APIs, service account, IAM grants, and IAP firewall."""
        ...

    def access_plan(self) -> Document:
        """Inspect API state and access-resource reconciliation without writes."""
        ...

    def subnet(self, zone: str) -> str:
        """Resolve and validate a regional subnet for a candidate zone."""
        ...

    def move_policy(self, instance: Document, disk: Document) -> None:
        """Reject separately attached policies and tags that cannot be preserved."""
        ...

    def connection_policy(self, instance: Document) -> None:
        """Inspect effective ingress before permitting a connection."""
        ...

    def host_keys(self, zone: str) -> Document:
        """Read host public keys through the authenticated Compute API."""
        ...

    def permission_denied(self, kind: str, detail: str = "") -> PiccoloError:
        """Return IAM binding guidance for the acting provisioner and action."""
        ...

    def project_metadata(self) -> Document:
        """Inspect inherited startup metadata."""
        ...


def failure(operation: Document) -> PiccoloError | None:
    """Classify only structured, terminal Compute errors as capacity failures."""
    errors = objects(document(operation.get("error", {})), "errors")
    if not errors:
        if operation.get("http_error_status_code"):
            return PiccoloError(
                f"Compute operation failed with HTTP "
                f"{operation['http_error_status_code']}: "
                f"{text(operation, 'http_error_message')}"
            )
        return None
    codes = {text(item, "code") for item in errors}
    detail = "; ".join(
        f"{text(item, 'code')}: {text(item, 'message')}" for item in errors
    )
    if codes and codes <= CAPACITY_CODES:
        return CapacityError(detail)
    return PiccoloError(f"Compute operation failed: {detail}")


class Operations:
    """Submit once, poll to completion, and leave uncertain outcomes unresolved."""

    def __init__(
        self,
        cloud: Cloud,
        journal: Journal,
        timeout: int,
        notify: Callable[[str], None],
    ) -> None:
        """Configure the adapter, persistence, deadline, and warning reporter."""
        self.cloud = cloud
        self.journal = journal
        self.timeout = timeout
        self.notify = notify

    def run(
        self,
        key: str,
        kind: str,
        name: str,
        zone: str = "",
        resource: Document | None = None,
    ) -> None:
        """Record intent before submission and reconcile persisted requests on."""
        operation = self.journal.operation
        actions = objects(operation, "actions")
        shared_actions: list[Value] = [item for item in actions]
        operation["actions"] = shared_actions
        existing = next((item for item in actions if text(item, "key") == key), None)
        if (
            existing is not None
            and text(existing, "status") == "failed"
            and kind
            in {
                "instance.start",
                "instance.stop",
                "instance.protect",
                "instance.delete",
                "disk.delete",
                "snapshot.delete",
            }
        ):
            existing["key"] = f"{key}:failed:{text(existing, 'request_id')}"
            self.journal.update(operation)
            existing = None
        if existing is None:
            action: Document = {
                "key": key,
                "kind": kind,
                "name": name,
                "zone": zone,
                "request_id": str(uuid.uuid4()),
                "status": "intent",
            }
            actions.append(action)
            shared_actions.append(action)
            self.journal.update(operation)
            try:
                action["operation_id"] = self.cloud.submit(
                    kind, name, zone, resource or {}, text(action, "request_id")
                )
            except UncertainError:
                raise
            except PiccoloError as exc:
                action["status"] = "failed"
                action["error"] = str(exc)
                action["capacity"] = isinstance(exc, CapacityError)
                self.journal.update(operation)
                raise
            action["status"] = "submitted"
            self.journal.update(operation)
        else:
            action = existing
        status = text(action, "status")
        if status == "done":
            return
        if status == "failed":
            error_type = (
                CapacityError if action.get("capacity") is True else PiccoloError
            )
            raise error_type(text(action, "error"))
        operation_id = text(action, "operation_id")
        if not operation_id:
            operation_id = self.cloud.recover(text(action, "request_id"), zone)
            if not operation_id:
                raise UncertainError(
                    f"Submission outcome unknown for {key}; no "
                    f"matching operation is visible. Keep resources "
                    f"and inspect the journal; no alternate zone "
                    f"will be tried"
                )
            action["operation_id"] = operation_id
            self.journal.update(operation)
        deadline = time.monotonic() + self.timeout
        while True:
            result = self.cloud.poll(operation_id, zone)
            if text(result, "status") == "DONE":
                for warning in objects(result, "warnings"):
                    self.notify(
                        f"Compute warning: {text(warning, 'code')}: "
                        f"{text(warning, 'message')}"
                    )
                error = failure(result)
                if error and (
                    result.get("http_error_status_code") == 403
                    or any(
                        text(item, "code")
                        in {"PERMISSIONS_ERROR", "PERMISSION_DENIED", "FORBIDDEN"}
                        for item in objects(document(result.get("error", {})), "errors")
                    )
                ):
                    error = self.cloud.permission_denied(kind, str(error))
                action["target_id"] = str(result.get("target_id", ""))
                action["status"] = "failed" if error else "done"
                if error:
                    action["error"] = str(error)
                    action["capacity"] = isinstance(error, CapacityError)
                self.journal.update(operation)
                if error:
                    raise error
                return
            if time.monotonic() >= deadline:
                raise UncertainError(
                    f"Operation {operation_id} timed out; run piccolo resume"
                )
            time.sleep(min(2, max(0, deadline - time.monotonic())))
