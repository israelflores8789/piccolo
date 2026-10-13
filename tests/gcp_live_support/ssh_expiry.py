# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""ssh_expiry.py — Disposable SSH keys and observed expiration/reconnect evidence."""

import hashlib
import os
import shlex
import subprocess
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, override

from gcp_live_support.deadline import timeout
from gcp_live_support.manifest import Manifest, gate
from piccolo.config import Config
from piccolo.data import Document, decode, document, objects, text
from piccolo.errors import PiccoloError
from piccolo.process import run_command
from piccolo.providers.gcp.connection import GCloudConnection
from piccolo.providers.gcp.provision import zone_of
from piccolo.state.storage import private_directory, private_file

INITIAL_TTL = "45s"
RENEWED_TTL = "5m"


def key_material(public_key: str) -> str:
    """Identify a public key independently of its optional trailing comment."""
    fields = public_key.split()
    if len(fields) < 2:
        raise PiccoloError("Malformed test public key")
    return " ".join(fields[:2])


def profile_key(profile: Document, public_key: str) -> tuple[str, float] | None:
    """Read only the exact test key and its finite OS Login expiration."""
    matches: list[tuple[str, float]] = []
    for fingerprint, raw in document(profile.get("sshPublicKeys", {})).items():
        entry = document(raw)
        if key_material(text(entry, "key")) != key_material(public_key):
            continue
        expiration = str(entry.get("expirationTimeUsec", ""))
        if not expiration.isdecimal() or int(expiration) <= 0:
            raise PiccoloError("Test OS Login key has no finite expiration")
        matches.append((fingerprint, int(expiration) / 1_000_000))
    if len(matches) > 1:
        raise PiccoloError("Multiple OS Login entries match the test key")
    return matches[0] if matches else None


def metadata_key(
    metadata: Document, public_key: str, user: str
) -> tuple[str, float] | None:
    """Observe an instance-scoped expiring key without accepting another user."""
    expirations: list[float] = []
    for item in objects(metadata, "items"):
        if text(item, "key") not in {"ssh-keys", "sshKeys"}:
            continue
        for line in text(item, "value").splitlines():
            username, separator, body = line.partition(":")
            if not separator or username != user:
                continue
            if key_material(body) != key_material(public_key):
                continue
            _, separator, expiration = body.partition(" google-ssh ")
            if not separator:
                raise PiccoloError("Test metadata key has a non-expiring authorization")
            try:
                stamp = datetime.fromisoformat(text(decode(expiration), "expireOn"))
                if stamp.tzinfo is None:
                    raise ValueError("Missing expiration timezone")
                expirations.append(stamp.timestamp())
            except ValueError as exc:
                raise PiccoloError("Malformed metadata key expiration") from exc
    if not expirations:
        return None
    fingerprint = hashlib.sha256(key_material(public_key).encode()).hexdigest()
    return fingerprint, max(expirations)


def read_profile(connection: GCloudConnection) -> Document:
    """Inspect the configured connector's profile without changing its keys."""
    result = connection.run(
        ["compute", "os-login", "describe-profile", "--format=json"], timeout=30
    )
    if result.returncode:
        raise PiccoloError(f"Cannot inspect test OS Login profile: {result.stderr}")
    return decode(result.stdout)


def validate_key_record(config: Config, manifest: Manifest, entry: Document) -> Path:
    """Authorize cleanup only for this run's newly created, unchanged public key."""
    manifest.validate()
    gate(config.gcp.project_id)
    run = text(manifest.data, "run")
    mode, transport = text(entry, "mode"), text(entry, "transport")
    if (
        config.gcp.project_id != text(manifest.data, "project")
        or config.environment != run
        or mode not in {"oslogin", "metadata"}
        or transport not in {"ssh", "scp"}
        or entry.get("absent_before") is not True
        or text(entry, "key") != f"ssh-key:{run}:{mode}:{transport}"
        or text(entry, "account") != config.gcp.connection_account
        or not config.gcp.connection_account
        or config.gcp.connection_impersonate
    ):
        raise PiccoloError("SSH test-key cleanup identity or ownership is unproven")
    expected = manifest.directory / f"ssh-expiry-{mode}-{transport}" / "key.pub"
    path = Path(text(entry, "public_key_path"))
    if path != expected or path.resolve() != expected or path.is_symlink():
        raise PiccoloError("SSH test-key path is outside its recorded run")
    public = text(entry, "public_key")
    fields = public.split()
    comment = f"piccolo-live-{run}-{mode}-{transport}"
    if len(fields) != 3 or fields[0] != "ssh-ed25519" or fields[2] != comment:
        raise PiccoloError("SSH test key lacks the exact run marker")
    if path.read_text().strip() != public or path.stat().st_nlink != 1:
        raise PiccoloError("SSH test public key changed; preserve it for inspection")
    private = path.with_suffix("")
    if private.is_symlink():
        raise PiccoloError("SSH test private key was replaced with a symlink")
    if private.exists():
        identity = private.stat()
        if (
            identity.st_nlink != 1
            or identity.st_ino != entry.get("private_inode")
            or identity.st_dev != entry.get("private_device")
        ):
            raise PiccoloError("SSH test private key identity changed; preserve it")
    return path


def remove_test_key(config: Config, manifest: Manifest, entry: Document) -> None:
    """Remove exactly the disposable profile key and retain failures for the janitor."""
    if entry.get("status") == "removed":
        return
    path = validate_key_record(config, manifest, entry)
    if text(entry, "mode") == "oslogin":
        connection = GCloudConnection(config.gcp)
        observed = profile_key(read_profile(connection), text(entry, "public_key"))
        if observed is not None:
            entry["status"] = "removal-intent"
            manifest.put("ssh_keys", entry)
            gate(config.gcp.project_id)
            result = connection.run(
                ["compute", "os-login", "ssh-keys", "remove", f"--key-file={path}"],
                timeout=30,
            )
            if result.returncode:
                raise PiccoloError(f"Cannot remove disposable SSH key: {result.stderr}")
            if profile_key(read_profile(connection), text(entry, "public_key")):
                raise PiccoloError("Disposable SSH key removal could not be verified")
    # Metadata authorization disappears with the run-owned VM, removed first.
    path.with_suffix("").unlink(missing_ok=True)
    entry["status"] = "removed"
    manifest.put("ssh_keys", entry)


class ExpiryConnection(GCloudConnection):
    """Exercise Piccolo's transport with a journaled disposable key."""

    def __init__(self, provider: "GCPProvider", entry: Document) -> None:
        """Keep production flags and host trust, substituting only the test key/TTL."""
        from gcp_live_support.gcp_sdk import LiveCloud

        if not isinstance(provider.cloud, LiveCloud):
            raise PiccoloError(
                "SSH expiration requires the manifest-backed live adapter"
            )
        self.provider = provider
        self.cloud = provider.cloud
        self.entry = entry
        self.manifest = self.cloud.manifest
        super().__init__(
            replace(provider.gcp, expire_after=INITIAL_TTL, require_passphrase=False),
            self.checked_target,
            self.cloud.host_keys,
        )
        self.key_file = Path(text(entry, "public_key_path")).with_suffix("")

    @override
    def before_ssh(self, zone: str) -> None:
        """Journal native registration against the disposable key before any write."""
        self.checked_target(zone)
        validate_key_record(self.provider.config, self.manifest, self.entry)
        self.entry["status"] = "publishing"
        self.manifest.put("ssh_keys", self.entry)
        super().before_ssh(zone)

    def checked_target(self, zone: str) -> Document:
        """Reject replaced or foreign VMs before any test-key publication or probe."""
        gate(self.config.project_id)
        instance = self.provider.connection_target(zone)
        resource = self.manifest.lookup("instance", self.config.name, zone)
        if (
            resource is None
            or not self.cloud.owns(resource, instance)
            or text(instance, "id") != text(self.entry, "instance_id")
            or zone != text(self.entry, "zone")
        ):
            raise PiccoloError("SSH expiry target is not the exact run-owned VM")
        return instance

    @override
    def host_options(self, zone: str, flag: str) -> list[str]:
        """Retain production host checking and select the newly generated test key."""
        options = super().host_options(zone, flag)
        public = validate_key_record(self.provider.config, self.manifest, self.entry)
        return [item for item in options if not item.startswith("--ssh-key-file=")] + [
            f"--ssh-key-file={public.with_suffix('')}"
        ]

    @override
    def run(
        self, arguments: list[str], *, timeout: int | None = 60, capture: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Journal potential gcloud publication before SSH/SCP can mutate key access."""
        gate(self.config.project_id)
        if arguments[:2] in (["compute", "ssh"], ["compute", "scp"]):
            self.checked_target(text(self.entry, "zone"))
            validate_key_record(self.provider.config, self.manifest, self.entry)
            self.entry["status"] = "publishing"
            self.manifest.put("ssh_keys", self.entry)
        return super().run(arguments, timeout=timeout, capture=capture)


class SSHExpiryProbe:
    """Observe key rejection, then reconnect through the actual Piccolo transport."""

    def __init__(self, provider: "GCPProvider", mode: str, transport: str) -> None:
        """Create one private, run-scoped key without reading the user's normal keys."""
        from gcp_live_support.gcp_sdk import LiveCloud

        if mode not in {"oslogin", "metadata"} or transport not in {"ssh", "scp"}:
            raise PiccoloError("Unsupported SSH expiration test case")
        if not isinstance(provider.cloud, LiveCloud):
            raise PiccoloError("SSH expiration requires a live run manifest")
        gate(provider.gcp.project_id)
        self.provider = provider
        self.cloud = provider.cloud
        self.manifest = self.cloud.manifest
        instance = provider.active()
        self.zone = zone_of(instance)
        run = text(self.manifest.data, "run")
        directory = self.manifest.directory / f"ssh-expiry-{mode}-{transport}"
        private_directory(directory)
        key = directory / "key"
        keygen = (
            provider.connection.ssh.client.executable("ssh-keygen")
            if isinstance(provider.connection, GCloudConnection)
            and provider.connection.windows
            else "ssh-keygen"
        )
        result = subprocess.run(
            [
                keygen,
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(key),
                "-C",
                f"piccolo-live-{run}-{mode}-{transport}",
            ],
            shell=False,
            text=True,
            capture_output=True,
            timeout=timeout(),
            check=False,
        )
        if result.returncode:
            raise PiccoloError(
                f"Cannot create disposable SSH test key: {result.stderr}"
            )
        public = key.with_suffix(".pub")
        os.close(private_file(public))
        os.close(private_file(key))
        self.entry: Document = {
            "key": f"ssh-key:{run}:{mode}:{transport}",
            "mode": mode,
            "transport": transport,
            "account": provider.gcp.connection_account,
            "public_key_path": str(public),
            "public_key": public.read_text().strip(),
            "instance_id": text(instance, "id"),
            "zone": self.zone,
            "absent_before": True,
            "status": "reserved",
            "private_inode": key.stat().st_ino,
            "private_device": key.stat().st_dev,
        }
        self.connection = ExpiryConnection(provider, self.entry)
        if self.authorization() is not None:
            raise PiccoloError("Disposable key unexpectedly preexists in cloud access")
        self.manifest.put("ssh_keys", self.entry)
        metadata = document(instance.get("metadata", {}))
        items = [
            item
            for item in objects(metadata, "items")
            if text(item, "key") not in {"enable-oslogin", "block-project-ssh-keys"}
        ]
        items.extend(
            [
                {
                    "key": "enable-oslogin",
                    "value": "TRUE" if mode == "oslogin" else "FALSE",
                },
                {"key": "block-project-ssh-keys", "value": "TRUE"},
            ]
        )
        self.cloud.set_metadata(self.zone, text(instance, "id"), items)
        self.remote_path = f"piccolo-key-expiry-{run}-{mode}-{transport}.txt"

    def authorization(self) -> tuple[str, float] | None:
        """Read actual published authorization without renewing it."""
        instance = self.connection.checked_target(self.zone)
        public = text(self.entry, "public_key")
        if self.entry["mode"] == "oslogin":
            return profile_key(read_profile(self.connection), public)
        return metadata_key(
            document(instance.get("metadata", {})), public, self.provider.gcp.ssh_user
        )

    def native_arguments(self, command: str) -> list[str]:
        """Construct a direct SSH probe that cannot publish or renew a key."""
        self.connection.checked_target(self.zone)
        self.connection.environment()
        proxy = shlex.join(
            [
                *self.connection.launcher(),
                "compute",
                "start-iap-tunnel",
                self.provider.gcp.name,
                "22",
                "--listen-on-stdin",
                f"--zone={self.zone}",
                *self.connection.flags(),
            ]
        )
        if self.connection.windows:
            proxy = self.connection.ssh.proxy_command(self.zone)
        return [
            self.connection.ssh.client.executable("ssh")
            if self.connection.windows
            else "ssh",
            "-F",
            str(self.connection.empty_config)
            if self.connection.windows
            else "/dev/null",
            "-i",
            str(Path(text(self.entry, "public_key_path")).with_suffix("")),
            "-oBatchMode=yes",
            "-oIdentitiesOnly=yes",
            "-oIdentityAgent=none",
            "-oPreferredAuthentications=publickey",
            "-oPasswordAuthentication=no",
            "-oKbdInteractiveAuthentication=no",
            "-oStrictHostKeyChecking=yes",
            (
                f'-oGlobalKnownHostsFile="{self.connection.empty_config.as_posix()}"'
                if self.connection.windows
                else "-oGlobalKnownHostsFile=/dev/null"
            ),
            "-oKnownHostsCommand=none",
            "-oVerifyHostKeyDNS=no",
            "-oCheckHostIP=no",
            "-oConnectTimeout=10",
            "-oConnectionAttempts=1",
            f'-oUserKnownHostsFile="{self.connection.known_hosts.as_posix()}"',
            f"-oHostKeyAlias=compute.{text(self.entry, 'instance_id')}",
            f"-oProxyCommand={proxy}",
            f"{self.provider.gcp.ssh_user}@compute.{text(self.entry, 'instance_id')}",
            command,
        ]

    def native(self, command: str) -> subprocess.CompletedProcess[str]:
        """Authenticate only with the disposable key and enrolled host trust."""
        if self.connection.windows:
            return run_command(
                self.native_arguments(command),
                self.connection.environment(),
                timeout=timeout(),
            )
        return subprocess.run(
            self.native_arguments(command),
            shell=False,
            text=True,
            capture_output=True,
            timeout=timeout(),
            env=self.connection.environment(),
            check=False,
        )

    def establish(self) -> tuple[str, float]:
        """Prove successful SSH and finite authorization before waiting for expiry."""
        self.connection.ready(self.zone)
        ready = self.connection.execute(self.zone, "printf authorized")
        if ready != "authorized":
            raise PiccoloError("Initial Piccolo SSH did not return its expected marker")
        authorization = self.authorization()
        if authorization is None or authorization[1] <= time.time():
            raise PiccoloError("Initial key authorization is absent or already expired")
        probe = self.native("printf authorized")
        if probe.returncode or probe.stdout != "authorized":
            raise PiccoloError("Disposable key did not authenticate before expiration")
        self.entry["first_expiration"] = authorization[1]
        self.entry["fingerprint"] = authorization[0]
        self.entry["status"] = "authorized"
        self.manifest.put("ssh_keys", self.entry)
        return authorization

    def wait_until_rejected(self, first_expiration: float, timeout: int = 180) -> None:
        """Require actual expiry and key rejection, distinguishing network failures."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            observed = self.authorization()
            if observed is not None and observed[1] > first_expiration:
                raise PiccoloError(
                    "Key authorization was renewed before the expiry probe"
                )
            if time.time() >= first_expiration and (
                observed is None or observed[1] <= time.time()
            ):
                probe = self.native("printf authorized")
                if probe.returncode == 255:
                    diagnostic = probe.stderr.lower()
                    if (
                        "permission denied" not in diagnostic
                        or "publickey" not in diagnostic
                    ):
                        raise PiccoloError(
                            "Expiry probe failed for a reason other than key rejection"
                        )
                    self.entry["status"] = "expired-and-rejected"
                    self.manifest.put("ssh_keys", self.entry)
                    return
                if probe.returncode:
                    raise PiccoloError(
                        "Expiry probe returned an unexpected SSH failure"
                    )
            time.sleep(2)
        raise PiccoloError("Expired key remained usable or rejection was not observed")

    def reconnect(self, initial: tuple[str, float]) -> None:
        """Verify SSH/SCP renews the same key without an intervening readiness call."""
        if self.entry.get("status") != "expired-and-rejected":
            raise PiccoloError(
                "Expiration and rejection must be observed before reconnect"
            )
        self.connection.config = replace(
            self.connection.config, expire_after=RENEWED_TTL
        )
        if self.entry["transport"] == "ssh":
            if (
                self.connection.execute(self.zone, "printf reconnected")
                != "reconnected"
            ):
                raise PiccoloError("Piccolo SSH failed to reconnect after expiration")
        else:
            source = Path(text(self.entry, "public_key_path")).parent / "probe.txt"
            source.write_text("piccolo expiry transfer\n", newline="\n")
            source.chmod(0o600)
            self.connection.copy(self.zone, source, self.remote_path)
            verify = self.native(f"cat ~/{self.remote_path}")
            if verify.returncode or verify.stdout != source.read_text():
                raise PiccoloError("SCP did not preserve the transferred probe bytes")
        authorization = self.authorization()
        if (
            authorization is None
            or authorization[0] != initial[0]
            or authorization[1] <= max(initial[1], time.time())
        ):
            raise PiccoloError("Reconnect did not renew the same published public key")
        validate_key_record(self.provider.config, self.manifest, self.entry)
        self.entry["renewed_expiration"] = authorization[1]
        self.entry["status"] = "reconnected"
        self.manifest.put("ssh_keys", self.entry)


if TYPE_CHECKING:
    from piccolo.providers.gcp.provider import GCPProvider
