# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""ssh_auth.py — Expiring SSH authorization using the selected gcloud identity."""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from piccolo.config.models import GCP
from piccolo.data import Document, Value, decode, document, objects, text
from piccolo.errors import PiccoloError
from piccolo.privacy import remember_secrets


class SSHHost(Protocol):
    """Supply configuration, inspected gcloud execution, and authenticated targets."""

    config: GCP
    windows: bool
    deadline: float | None
    user_home: Path
    key_file: Path
    empty_config: Path
    known_hosts: Path
    host_files: dict[str, tuple[str, Path]]
    target: Callable[[str], Document] | None
    host_keys: Callable[[str], Document] | None

    def run(
        self, arguments: list[str], *, timeout: int | None = 60, capture: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Launch gcloud under the validated connection identity."""
        ...

    def environment(self) -> dict[str, str]:
        """Return an inspected connection environment."""
        ...

    def check_identity(self) -> None:
        """Verify the configured connection account."""
        ...

    def before_ssh(self, zone: str) -> None:
        """Perform connection and test-approval checks before SSH preparation."""
        ...

    def host_options(self, zone: str, flag: str) -> list[str]:
        """Enroll provider-authenticated host keys."""
        ...

    def ssh_arguments(self, zone: str, command: str | None = None) -> list[str]:
        """Build POSIX gcloud transport arguments."""
        ...

    def launcher(self) -> list[str]:
        """Return an argument-list SDK launcher."""
        ...

    def flags(self) -> list[str]:
        """Select the project, account, and explicit impersonation identity."""
        ...


def duration(value: str) -> int:
    """Convert the already validated finite configuration duration to seconds."""
    return int(value[:-1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[value[-1]]


def metadata_values(metadata: Document) -> dict[str, str]:
    """Reject ambiguous metadata before deciding the SSH authorization mode."""
    result: dict[str, str] = {}
    for item in objects(metadata, "items"):
        key, value = text(item, "key"), text(item, "value")
        if key in result:
            raise PiccoloError(f"Ambiguous duplicate SSH metadata key: {key}")
        result[key] = value
    return result


class KeyAuthorization:
    """Keep registration credentials separate from infrastructure provisioner ADC."""

    def __init__(self, connection: SSHHost) -> None:
        """Use only the inspected, explicitly selected gcloud connection facade."""
        self.connection = connection

    def request(self, path: str, body: Document | None = None) -> Document:
        """Call fixed Google Compute endpoints with a connection-identity token."""
        result = self.connection.run(["auth", "print-access-token"], timeout=30)
        token = result.stdout.strip()
        if result.returncode or not token or any(c.isspace() for c in token):
            raise PiccoloError(
                "Cannot obtain the selected gcloud connection access token"
            )
        remember_secrets({"access_token": token})
        request = Request(
            "https://compute.googleapis.com/compute/v1/" + path,
            data=None if body is None else json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method="GET" if body is None else "POST",
        )
        try:
            timeout = 30.0
            if self.connection.deadline is not None:
                timeout = min(timeout, self.connection.deadline - time.monotonic())
                if timeout <= 0:
                    raise PiccoloError("SSH key authorization timed out")
            with urlopen(request, timeout=timeout) as response:
                return decode(response.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code in (409, 412):
                raise
            raise PiccoloError(
                f"SSH key authorization API failed (HTTP {exc.code}); "
                "check the connection identity's Compute permissions"
            ) from exc
        except (URLError, OSError, ValueError) as exc:
            raise PiccoloError(
                "Cannot complete SSH key authorization; "
                "inspect the selected instance metadata before retrying"
            ) from exc

    def prefix(self, zone: str) -> str:
        """Build a fixed project/zone scope without trusting remote self-links."""
        project = quote(self.connection.config.project_id, safe="")
        return f"projects/{project}/zones/{quote(zone, safe='')}"

    def instance(self, zone: str, identity: str) -> Document:
        """Recheck the exact provider-selected instance before every key mutation."""
        instance = self.request(
            self.prefix(zone)
            + "/instances/"
            + quote(self.connection.config.name, safe="")
        )
        if text(instance, "id") != identity:
            raise PiccoloError("Instance changed during SSH key authorization")
        return instance

    def policy(self, zone: str, instance: Document) -> dict[str, str]:
        """Combine documented project, zonal, and instance metadata precedence."""
        project = self.request(
            "projects/" + quote(self.connection.config.project_id, safe="")
        )
        values = metadata_values(document(project.get("commonInstanceMetadata", {})))
        # Zonal metadata participates in the effective SSH policy when present.
        zonal = self.request(self.prefix(zone) + "/instanceSettings")
        raw = document(zonal.get("metadata", {}))
        nested = raw.get("items", {})
        if isinstance(nested, dict):
            for key, value in nested.items():
                if not isinstance(value, str):
                    raise PiccoloError("Invalid zonal SSH metadata")
                values[key] = value
        values.update(metadata_values(document(instance.get("metadata", {}))))
        return values

    def authorize(self, zone: str, identity: str, public_key: str) -> None:
        """Renew one key with a finite TTL and preserve every unrelated entry."""
        instance = self.instance(zone, identity)
        values = self.policy(zone, instance)
        oslogin = values.get("enable-oslogin", "false").lower() == "true"
        if values.get("enable-oslogin-certificates", "false").lower() == "true":
            raise PiccoloError(
                "Native Windows SSH does not support OS Login certificate mode"
            )
        if oslogin:
            if values.get("enable-oslogin-2fa", "false").lower() == "true":
                raise PiccoloError(
                    "Native Windows SSH does not support OS Login two-factor challenges"
                )
            self.oslogin(zone, identity, public_key)
            return
        for attempt in range(3):
            instance = self.instance(zone, identity)
            metadata = document(instance.get("metadata", {}))
            values = metadata_values(metadata)
            if values.get("enable-oslogin", "false").lower() == "true":
                raise PiccoloError(
                    "SSH authentication policy changed during registration; reconnect"
                )
            fingerprint = text(metadata, "fingerprint")
            if not fingerprint:
                raise PiccoloError("SSH metadata update requires a current fingerprint")
            if "sshKeys" in values:
                raise PiccoloError(
                    "Legacy sshKeys metadata is unsupported on native Windows; "
                    "migrate it to ssh-keys deliberately"
                )
            user = self.connection.config.ssh_user
            seconds = duration(self.connection.config.expire_after)
            material = " ".join(public_key.split()[:2])
            own_prefix = f"{user}:{material}"
            lines = values.get("ssh-keys", "").splitlines()
            matching = [
                line
                for line in lines
                if line.startswith(own_prefix + " ") or line == own_prefix
            ]
            valid: list[float] = []
            for line in matching:
                _, separator, stamp = line.partition(" google-ssh ")
                if separator:
                    try:
                        expiry = datetime.fromisoformat(text(decode(stamp), "expireOn"))
                        if expiry.tzinfo is not None:
                            valid.append(expiry.timestamp())
                    except ValueError:
                        pass
            if (
                len(matching) == 1
                and valid
                and time.time() + min(60, seconds / 2)
                < max(valid)
                <= time.time() + seconds + 1
            ):
                return
            expires = datetime.fromtimestamp(time.time() + seconds, UTC).strftime(
                "%Y-%m-%dT%H:%M:%S%z"
            )
            line = (
                own_prefix
                + " google-ssh "
                + json.dumps(
                    {"userName": user, "expireOn": expires}, separators=(",", ":")
                )
            )
            retained = [entry for entry in lines if entry not in matching]
            retained.append(line)
            items = [
                item
                for item in objects(metadata, "items")
                if text(item, "key") != "ssh-keys"
            ]
            items.append({"key": "ssh-keys", "value": "\n".join(retained)})
            try:
                operation = self.request(
                    self.prefix(zone)
                    + "/instances/"
                    + quote(self.connection.config.name, safe="")
                    + "/setMetadata?requestId="
                    + str(uuid.uuid4()),
                    {"fingerprint": fingerprint, "items": list[Value](items)},
                )
                self.wait(zone, operation, identity)
                self.instance(zone, identity)
                return
            except HTTPError:
                if attempt == 2:
                    raise PiccoloError(
                        "SSH metadata kept changing; "
                        "retry after coordinating other metadata writers"
                    ) from None
        raise PiccoloError("SSH key registration did not complete")

    def wait(self, zone: str, operation: Document, identity: str) -> None:
        """Bound metadata propagation without replaying an uncertain accepted write."""
        name = text(operation, "name")
        if not name or text(operation, "targetId") not in ("", identity):
            raise PiccoloError("Cannot verify the SSH metadata operation target")
        deadline = time.monotonic() + 60
        while text(operation, "status") != "DONE":
            if time.monotonic() >= deadline:
                raise PiccoloError(
                    "SSH metadata operation timed out; "
                    "inspect instance metadata before retrying"
                )
            time.sleep(0.2)
            operation = self.request(
                self.prefix(zone) + "/operations/" + quote(name, safe="")
            )
        if operation.get("error"):
            raise PiccoloError(
                "SSH metadata operation failed; "
                "inspect connection permissions and metadata policy"
            )

    def oslogin(self, zone: str, identity: str, public_key: str) -> None:
        """Check the effective POSIX account before importing an expiring key."""
        result = self.connection.run(
            ["compute", "os-login", "describe-profile", "--format=json"]
        )
        if result.returncode:
            raise PiccoloError(
                "Cannot inspect the selected connection's OS Login profile"
            )
        profile = decode(result.stdout)
        accounts = [
            entry
            for entry in objects(profile, "posixAccounts")
            if entry.get("primary") is True
            and entry.get("operatingSystemType", "LINUX") == "LINUX"
        ]
        if (
            len(accounts) != 1
            or text(accounts[0], "username") != self.connection.config.ssh_user
        ):
            raise PiccoloError(
                "OS Login user mismatch; set gcp.ssh.user to the connection "
                "identity's primary POSIX username"
            )
        self.instance(zone, identity)
        result = self.connection.run(
            [
                "compute",
                "os-login",
                "ssh-keys",
                "add",
                f"--key={public_key}",
                f"--ttl={self.connection.config.expire_after}",
                "--format=json",
            ]
        )
        if result.returncode:
            raise PiccoloError(
                "Cannot import an expiring OS Login key "
                "for the selected connection identity"
            )
        self.instance(zone, identity)
