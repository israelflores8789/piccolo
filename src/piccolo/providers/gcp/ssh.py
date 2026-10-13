# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""ssh.py — GCP session preparation and platform transport dispatch."""

from __future__ import annotations

import base64
import binascii
import re
import shlex
import subprocess
import sys
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from piccolo.data import document, objects, text
from piccolo.errors import PiccoloError
from piccolo.logger import log
from piccolo.openssh import OpenSSH, SSHSession, write_host_keys
from piccolo.providers.gcp.ssh_auth import KeyAuthorization, SSHHost


class SSHTransport:
    """Keep SSH consumers independent of platform-specific transport choices."""

    def __init__(self, connection: SSHHost) -> None:
        """Keep the gcloud identity facade and provider-bound authenticated reads."""
        self.connection = connection
        self.client = OpenSSH(
            lambda: self.connection.environment(),
            lambda: self.connection.deadline,
            windows=True,
        )
        self.authorization = KeyAuthorization(connection)

    @contextmanager
    def bounded(self, seconds: int | None) -> Generator[None]:
        """Share one deadline across key preparation, authorization, and execution."""
        previous = self.connection.deadline
        if seconds is not None:
            deadline = time.monotonic() + seconds
            self.connection.deadline = (
                deadline if previous is None else min(previous, deadline)
            )
        try:
            yield
        finally:
            self.connection.deadline = previous

    def native_session(self, zone: str) -> SSHSession:
        """Resolve GCP authorization, authenticated trust, address, and IAP policy."""
        self.client.check_terminal(self.connection.config.require_passphrase)
        self.connection.environment()
        self.connection.before_ssh(zone)
        if self.connection.target is None:
            raise PiccoloError("SSH requires a provider-bound instance identity")
        selected = self.connection.target(zone)
        identity = text(selected, "id")
        if not identity.isdecimal():
            raise PiccoloError("Cannot verify SSH instance identity")
        public = self.client.prepare_key(
            self.connection.key_file,
            self.connection.config.ssh_user,
            self.connection.config.require_passphrase,
        )
        self.authorization.authorize(zone, identity, public)
        alias, known_hosts = self.host_trust(zone)
        proxy = None
        address = self.connection.config.name
        if self.connection.config.via_iap:
            proxy = self.proxy_command(zone)
        else:
            interfaces = objects(selected, "network_interfaces") or objects(
                selected, "networkInterfaces"
            )
            if not interfaces:
                raise PiccoloError("Selected instance has no network interface")
            if self.connection.config.internal_ip:
                address = text(interfaces[0], "network_i_p") or text(
                    interfaces[0], "networkIP"
                )
            else:
                access = objects(interfaces[0], "access_configs") or objects(
                    interfaces[0], "accessConfigs"
                )
                address = (
                    (text(access[0], "nat_i_p") or text(access[0], "natIP"))
                    if access
                    else ""
                )
            import ipaddress

            try:
                ipaddress.IPv4Address(address)
            except ipaddress.AddressValueError as exc:
                raise PiccoloError(
                    "Selected instance has no usable configured SSH IP address"
                ) from exc
        if text(self.connection.target(zone), "id") != identity:
            raise PiccoloError("Instance changed before native SSH execution")
        return SSHSession(
            address=address,
            username=self.connection.config.ssh_user,
            key_file=self.connection.key_file,
            known_hosts=known_hosts,
            host_alias=alias,
            empty_config=self.connection.empty_config,
            require_passphrase=self.connection.config.require_passphrase,
            proxy_command=proxy,
        )

    def proxy_command(self, zone: str) -> str:
        """Encode the inspected SDK argv across OpenSSH's proxy parsing boundary."""
        import json

        proxy = [
            *self.connection.launcher(),
            "compute",
            "start-iap-tunnel",
            self.connection.config.name,
            "22",
            f"--zone={zone}",
            "--listen-on-stdin",
            "--verbosity=warning",
            "--quiet",
            *self.connection.flags(),
        ]
        encoded = base64.urlsafe_b64encode(json.dumps(proxy).encode("utf-8")).decode(
            "ascii"
        )
        command = subprocess.list2cmdline(
            [sys.executable, "-m", "piccolo.providers.gcp.iap", encoded]
        )
        return command.replace("%", "%%")

    def native_result(
        self,
        zone: str,
        command: str | None,
        *,
        timeout: int | None = 60,
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Apply one deadline to the whole native SSH command."""
        with self.bounded(timeout):
            return self.native_command(zone, command, timeout=timeout, capture=capture)

    def native_command(
        self, zone: str, command: str | None, *, timeout: int | None, capture: bool
    ) -> subprocess.CompletedProcess[str]:
        """Resolve GCP policy before executing a guarded native SSH operation."""
        session = self.native_session(zone)
        user = shlex.quote(self.connection.config.ssh_user)
        guard = (
            f'if test "$(id -un)" != {user}; then '
            "printf 'Piccolo SSH user mismatch; review gcp.ssh.user\\n' >&2; "
            "exit 65; fi; "
        )
        remote = guard + (
            command if command is not None else 'exec "${SHELL:-/bin/bash}" -l'
        )
        return self.client.command(session, remote, timeout=timeout, capture=capture)

    def native_copy(self, zone: str, source: Path, destination: str) -> None:
        """Apply one deadline to the whole native bootstrap transfer."""
        with self.bounded(120):
            self.native_transfer(zone, source, destination)

    def native_transfer(self, zone: str, source: Path, destination: str) -> None:
        """Resolve GCP policy before delegating a bounded native transfer."""
        self.client.check_terminal(self.connection.config.require_passphrase)
        self.client.check_destination(destination)
        self.client.transfer(self.native_session(zone), source, destination)

    def host_trust(self, zone: str) -> tuple[str, Path]:
        """Enroll host keys through authenticated GCP reads bound to the selected ID."""
        if self.connection.target is None:
            raise PiccoloError("SSH requires a provider-bound instance identity")
        selected = self.connection.target(zone)
        identity = text(selected, "id")
        if not identity.isdecimal():
            raise PiccoloError("Cannot verify SSH instance identity")
        alias = f"compute.{identity}"
        enrolled = self.connection.host_files.get(zone)
        if enrolled is None or enrolled[0] != identity:
            if self.connection.host_keys is None:
                raise PiccoloError("SSH requires authenticated Compute host-key reads")
            entries = objects(
                document(self.connection.host_keys(zone).get("query_value", {})),
                "items",
            )
            lines: list[str] = []
            for entry in entries:
                algorithm, value = text(entry, "key"), text(entry, "value")
                if text(entry, "namespace") != "hostkeys" or algorithm not in {
                    "ssh-ed25519",
                    "ssh-rsa",
                    "ecdsa-sha2-nistp256",
                    "ecdsa-sha2-nistp384",
                    "ecdsa-sha2-nistp521",
                }:
                    continue
                if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
                    raise PiccoloError("Malformed GCP host key")
                try:
                    decoded = base64.b64decode(value, validate=True)
                    length = int.from_bytes(decoded[:4], "big")
                    if decoded[4 : 4 + length] != algorithm.encode():
                        raise ValueError("SSH key algorithm mismatch")
                    load_ssh_public_key(f"{algorithm} {value}".encode("ascii"))
                except (ValueError, binascii.Error, UnsupportedAlgorithm) as exc:
                    raise PiccoloError("Malformed GCP host key") from exc
                lines.append(f"{alias} {algorithm} {value}\n")
            if not lines:
                raise PiccoloError(
                    "No trusted GCP host keys are published. Enable "
                    "enable-guest-attributes and have the Google guest agent publish "
                    "hostkeys before connecting; unknown SSH host keys are refused."
                )
            if text(self.connection.target(zone), "id") != identity:
                raise PiccoloError("Instance changed during host-key enrollment")
            path = self.connection.known_hosts
            write_host_keys(path, lines)
            self.connection.host_files[zone] = (identity, path)
        path = self.connection.host_files[zone][1]
        return alias, path

    def host_options(self, zone: str, flag: str) -> list[str]:
        """Render authenticated host trust as provider-specific gcloud arguments."""
        alias, path = self.host_trust(zone)
        return [
            "--strict-host-key-checking=yes",
            f"--ssh-key-expire-after={self.connection.config.expire_after}",
            f"--ssh-key-file={self.connection.key_file}",
            f"--{flag}=-oHostKeyAlias={alias}",
            f'--{flag}=-oUserKnownHostsFile="{path.as_posix()}"',
            f'--{flag}=-oGlobalKnownHostsFile="{self.connection.empty_config.as_posix()}"',
            f"--{flag}=-oKnownHostsCommand=none",
            f"--{flag}=-oVerifyHostKeyDNS=no",
            f"--{flag}=-oUpdateHostKeys=no",
            f"--{flag}=-Fnone",
            f"--{flag}=-oCheckHostIP=no",
        ]

    def ssh_arguments(self, zone: str, command: str | None = None) -> list[str]:
        """Build a gcloud SSH command for the configured development user."""
        args = [
            "compute",
            "ssh",
            f"{self.connection.config.ssh_user}@{self.connection.config.name}",
            f"--zone={zone}",
        ]
        args.extend(self.connection.host_options(zone, "ssh-flag"))
        if self.connection.config.via_iap:
            args.append("--tunnel-through-iap")
        elif self.connection.config.internal_ip:
            args.append("--internal-ip")
        if command is not None:
            user = shlex.quote(self.connection.config.ssh_user)
            command = (
                f'if test "$(id -un)" != {user}; then '
                "printf 'Piccolo SSH user mismatch; review gcp.ssh.user\\n' >&2; "
                f"exit 65; fi; {command}"
            )
            args.extend(
                [
                    f"--command={command}",
                    "--ssh-flag=-oBatchMode=yes",
                    "--ssh-flag=-oConnectTimeout=10",
                    "--ssh-flag=-oConnectionAttempts=1",
                ]
            )
        return args

    def ready(self, zone: str) -> None:
        """Retry actual SSH boot failures until a bounded readiness deadline."""
        self.connection.check_identity()
        deadline = time.monotonic() + self.connection.config.readiness_timeout
        diagnostic = "SSH not ready"
        key_rejections = 0
        while time.monotonic() < deadline:
            remaining = max(1, int(deadline - time.monotonic()))
            try:
                result = (
                    self.native_result(zone, "true", timeout=min(25, remaining))
                    if self.connection.windows
                    else self.connection.run(
                        self.connection.ssh_arguments(zone, "true"),
                        timeout=min(25, remaining),
                    )
                )
                if result.returncode == 0:
                    if self.connection.config.readiness_command:
                        self.execute(
                            zone,
                            self.connection.config.readiness_command,
                            timeout=max(1, int(deadline - time.monotonic())),
                        )
                    return
                diagnostic = result.stderr.strip()
                if result.returncode == 65:
                    raise PiccoloError("SSH user mismatch; review gcp.ssh.user")
                propagating = (
                    self.connection.windows
                    and result.returncode == 255
                    and "permission denied (publickey)" in diagnostic.lower()
                    and key_rejections < 3
                )
                if propagating:
                    key_rejections += 1
                if not propagating and any(
                    marker in diagnostic.lower()
                    for marker in (
                        "permission denied",
                        "forbidden",
                        "not authorized",
                        "does not have permission",
                        "invalid choice",
                        "not found",
                        "does not support ssh",
                    )
                ):
                    raise PiccoloError(
                        f"SSH configuration or permission failure: {diagnostic}"
                    )
            except PiccoloError as exc:
                if "timed out" not in str(
                    exc
                ) and "No trusted GCP host keys" not in str(exc):
                    raise
                diagnostic = str(exc)
            log(f"Waiting for SSH in {zone}...")
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise PiccoloError(f"SSH readiness timed out: {diagnostic}")

    def execute(self, zone: str, command: str, timeout: int = 60) -> str:
        """Execute a project-owned remote command with a deadline."""
        result = (
            self.native_result(zone, command, timeout=timeout)
            if self.connection.windows
            else self.connection.run(
                self.connection.ssh_arguments(zone, command), timeout=timeout
            )
        )
        if result.returncode:
            raise PiccoloError(
                f"Remote command failed ({result.returncode}): {result.stderr.strip()}"
            )
        return result.stdout.strip()

    def copy(self, zone: str, source: Path, destination: str) -> None:
        """Copy a relative path, allowing bounded renewed-key propagation."""
        if self.connection.windows:
            self.native_copy(zone, source, destination)
            return
        args = [
            "compute",
            "scp",
            str(source),
            f"{self.connection.config.ssh_user}@{self.connection.config.name}:~/{destination}",
            f"--zone={zone}",
        ]
        args.extend(self.connection.host_options(zone, "scp-flag"))
        args.append("--scp-flag=-oBatchMode=yes")
        if self.connection.config.via_iap:
            args.append("--tunnel-through-iap")
        elif self.connection.config.internal_ip:
            args.append("--internal-ip")
        deadline = time.monotonic() + 120
        for attempt in range(4):
            result = self.connection.run(
                args,
                timeout=max(1, int(deadline - time.monotonic())),
                capture=not self.connection.config.require_passphrase,
            )
            if not result.returncode:
                return
            diagnostic = (result.stderr or "").strip()
            if (
                result.returncode != 255
                or "permission denied (publickey)" not in diagnostic.lower()
                or attempt == 3
                or deadline - time.monotonic() <= 2
            ):
                raise PiccoloError(
                    f"Bootstrap transfer failed ({result.returncode}): {diagnostic}"
                )
            # Public-key rejection happens before the file transfer begins.
            time.sleep(2)

    def shell(self, zone: str) -> None:
        """Open SSH in the foreground with terminal input and output intact."""
        result = (
            self.native_result(zone, None, timeout=None, capture=False)
            if self.connection.windows
            else self.connection.run(
                self.connection.ssh_arguments(zone), timeout=None, capture=False
            )
        )
        if result.returncode:
            raise PiccoloError(f"SSH session exited with status {result.returncode}")
