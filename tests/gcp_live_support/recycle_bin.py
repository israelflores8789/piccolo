# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""recycle_bin.py — Permanently purge only manifest-proven recoverable snapshots."""

import re
import time
import uuid
from urllib.parse import urlencode

from google.auth.credentials import Credentials
from google.auth.transport.requests import AuthorizedSession
from requests import Response

from gcp_live_support.deadline import check_work, timeout
from gcp_live_support.manifest import Manifest, gate
from piccolo.data import Document, decode, document, objects, text
from piccolo.errors import PiccoloError, UncertainError


class RecycleBin:
    """Use the beta API absent from the pinned stable Compute SDK."""

    def __init__(self, project: str, credentials: Credentials) -> None:
        """Bind requests to one approved project and disable authenticated replay."""
        gate(project)
        self.project = project
        self.session = AuthorizedSession(
            credentials, max_refresh_attempts=0, refresh_timeout=30
        )

    def request(self, method: str, path: str) -> Document | None:
        """Send one bounded request without redirects or mutation retries."""
        gate(self.project)
        check_work()
        url = (
            "https://compute.googleapis.com/compute/beta/projects/"
            f"{self.project}/global/{path}"
        )
        response: Response = self.session.request(
            method,
            url,
            timeout=timeout(),
            max_allowed_time=timeout(),
            allow_redirects=False,
        )
        if method == "GET" and response.status_code == 404:
            return None
        if not 200 <= response.status_code < 300:
            raise PiccoloError(
                f"Recycle-bin {method} failed with HTTP {response.status_code}; "
                f"provisioner needs recoverable snapshot access on {self.project}"
            )
        return decode(response.text)

    def inventory(self) -> list[Document]:
        """Read all pages, rejecting incomplete or cyclic pagination."""
        result: list[Document] = []
        token = ""
        seen: set[str] = set()
        while True:
            suffix = "?" + urlencode({"pageToken": token}) if token else ""
            page = self.request("GET", "recoverableSnapshots" + suffix)
            if page is None:
                raise PiccoloError("Recycle-bin inventory is unavailable")
            warning = document(page.get("warning", {}))
            if warning and text(warning, "code") != "NO_RESULTS_ON_PAGE":
                raise PiccoloError("Recycle-bin inventory is incomplete")
            result.extend(objects(page, "items"))
            token = text(page, "nextPageToken")
            if not token:
                return result
            if token in seen:
                raise PiccoloError("Recycle-bin pagination repeated a token")
            seen.add(token)

    def wait(self, operation: str) -> None:
        """Observe the recorded beta global operation before verifying absence."""
        self.checked_name(operation)
        deadline = time.monotonic() + timeout(120)
        while time.monotonic() < deadline:
            observed = self.request("GET", f"operations/{operation}")
            if observed is None:
                raise UncertainError("Recycle-bin operation is unavailable")
            if observed.get("error"):
                raise PiccoloError(
                    "Recycle-bin purge operation failed; retain manifest"
                )
            if observed.get("status") == "DONE":
                return
            time.sleep(timeout(1))
        raise UncertainError("Recycle-bin purge operation timed out; retain manifest")

    @staticmethod
    def checked_name(name: str) -> None:
        """Reject paths or untrusted API resource names before constructing a URL."""
        if re.fullmatch(r"[a-z][a-z0-9-]{0,200}", name) is None:
            raise PiccoloError("Invalid recycle-bin resource or operation name")

    def purge(self, manifest: Manifest) -> None:
        """Match original snapshot IDs and journal every permanent deletion."""
        if self.project != text(manifest.data, "project"):
            raise PiccoloError("Recycle-bin manifest project differs from approval")
        run = text(manifest.data, "run")
        for item in self.inventory():
            original = document(item.get("originalResource", {}))
            original_name = text(original, "name")
            if not original_name.startswith(run + "-"):
                continue
            proof = manifest.lookup("snapshot", original_name)
            if (
                proof is None
                or proof.get("absent_before") is not True
                or not text(proof, "id")
                or text(proof, "id") != text(original, "id")
                or not text(item, "id")
            ):
                raise PiccoloError("Recycle-bin snapshot ownership is unproven")
            name = text(item, "name")
            self.checked_name(name)
            key = f"recoverable:{name}"
            previous = next(
                (r for r in manifest.entries("recycle_bin") if text(r, "key") == key),
                None,
            )
            record: Document = previous or {
                "key": key,
                "name": name,
                "id": text(item, "id"),
                "original_name": original_name,
                "original_id": text(original, "id"),
                "storage_bytes": original.get("storageBytes", "0"),
                "request_id": str(uuid.uuid4()),
                "operation": "",
                "outcome": "intent",
            }
            if text(record, "id") != text(item, "id"):
                raise PiccoloError("Recoverable snapshot identity changed")
            if previous is not None:
                operation = text(record, "operation")
                if not operation:
                    raise UncertainError("Previous recycle-bin purge remains uncertain")
                self.wait(operation)
            else:
                current = self.request("GET", f"recoverableSnapshots/{name}")
                if current is None:
                    continue
                if text(current, "id") != text(item, "id") or text(
                    document(current.get("originalResource", {})), "id"
                ) != text(original, "id"):
                    raise PiccoloError("Recoverable snapshot changed before deletion")
                manifest.put("recycle_bin", record)
                query = urlencode({"requestId": text(record, "request_id")})
                result = self.request("DELETE", f"recoverableSnapshots/{name}?{query}")
                if result is None or not text(result, "name"):
                    raise UncertainError("Recycle-bin purge returned no operation")
                record["operation"] = text(result, "name")
                manifest.put("recycle_bin", record)
                self.wait(text(result, "name"))
            if self.request("GET", f"recoverableSnapshots/{name}") is not None:
                raise UncertainError("Recycle-bin deletion was not verified")
            record["outcome"] = "purged"
            manifest.put("recycle_bin", record)
        for record in manifest.entries("recycle_bin"):
            if record.get("outcome") == "purged":
                continue
            operation = text(record, "operation")
            if not operation:
                raise UncertainError("Previous recycle-bin purge remains uncertain")
            self.wait(operation)
            name = text(record, "name")
            self.checked_name(name)
            if self.request("GET", f"recoverableSnapshots/{name}") is not None:
                raise UncertainError("Recycle-bin deletion was not verified")
            record["outcome"] = "purged"
            manifest.put("recycle_bin", record)
