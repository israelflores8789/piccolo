# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""ssh.py — Unified GCP SSH enrollment and native Windows OpenSSH transport."""

from __future__ import annotations

import base64
import binascii
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from platformdirs import user_state_path

from piccolo.data import document, objects, text
from piccolo.errors import PiccoloError
from piccolo.logger import log
from piccolo.process import run_command
from piccolo.providers.gcp.ssh_auth import KeyAuthorization, SSHHost
from piccolo.state.lock import file_lock
from piccolo.state.storage import private_directory, private_file, temporary_directory


class SSHTransport:
    """Keep SSH consumers independent of platform-specific transport choices."""

    def __init__(self, connection: SSHHost) -> None:
        """Keep the gcloud identity facade and provider-bound authenticated reads."""
        self.connection = connection
        self._executables: dict[str, str] = {}
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

    def remaining(self, seconds: float) -> float:
        """Bound a native subprocess by the complete operation's remaining time."""
        if self.connection.deadline is None:
            return seconds
        remaining = self.connection.deadline - time.monotonic()
        if remaining <= 0:
            raise PiccoloError("Native SSH connection preparation timed out")
        return min(seconds, remaining)

    def executable(self, name: str) -> str:
        """Select Windows OpenSSH 9.0+ explicitly, independently of PATH."""
        if name in self._executables:
            return self._executables[name]
        root = os.environ.get("SYSTEMROOT")
        if not root:
            raise PiccoloError(
                "SystemRoot is required to locate native Windows OpenSSH"
            )
        system = "Sysnative" if os.environ.get("PROCESSOR_ARCHITEW6432") else "System32"
        directory = Path(root) / system / "OpenSSH"
        for program in ("ssh", "scp", "ssh-keygen"):
            if not (directory / f"{program}.exe").is_file():
                raise PiccoloError(
                    "Install the Windows OpenSSH Client optional feature; "
                    "native ssh.exe, scp.exe and ssh-keygen.exe are required"
                )
        try:
            result = run_command(
                [str(directory / "ssh.exe"), "-V"],
                os.environ.copy(),
                timeout=self.remaining(10),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PiccoloError(
                "Cannot check the native Windows OpenSSH client version"
            ) from exc
        match = re.search(
            r"OpenSSH_for_Windows_(\d+)\.(\d+)", result.stderr + result.stdout
        )
        if (
            result.returncode
            or match is None
            or tuple(map(int, match.groups())) < (9, 0)
        ):
            raise PiccoloError(
                "Update the Windows OpenSSH Client to version 9.0 or newer"
            )
        self._executables = {
            program: str(directory / f"{program}.exe")
            for program in ("ssh", "scp", "ssh-keygen")
        }
        return self._executables[name]

    def key_command(
        self, arguments: list[str], *, prompts: bool = False, capture: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Run only the native key utility, with bounded local prompt handling."""
        try:
            return run_command(
                [self.executable("ssh-keygen"), *arguments],
                self.connection.environment(),
                timeout=self.remaining(120),
                capture=capture,
                prompts=prompts,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PiccoloError(
                "Native SSH key preparation failed or timed out"
            ) from exc

    def prepare_key(self) -> str:
        """Reuse an owned key pair, recovering only a missing public half safely."""
        key = self.connection.key_file
        public = key.with_name(key.name + ".pub")
        self.executable("ssh-keygen")
        lock_root = (
            user_state_path("piccolo", appauthor=False, ensure_exists=False)
            / "ssh-locks"
        )
        import hashlib

        lock_name = hashlib.sha256(str(key.absolute()).casefold().encode()).hexdigest()
        with file_lock(lock_root / f"{lock_name}.lock"):
            if not key.parent.exists():
                private_directory(key.parent)
            exists = key.exists() or key.is_symlink()
            if not exists and (public.exists() or public.is_symlink()):
                raise PiccoloError(
                    "SSH private key is missing but its public key exists; "
                    "restore the original pair deliberately"
                )
            if not exists:
                with temporary_directory("piccolo-keygen-") as directory:
                    staged = directory / "key"
                    arguments = [
                        "-t",
                        "rsa",
                        "-b",
                        "3072",
                        "-f",
                        str(staged),
                        "-C",
                        self.connection.config.ssh_user,
                    ]
                    if not self.connection.config.require_passphrase:
                        arguments.extend(["-N", ""])
                    result = self.key_command(
                        arguments,
                        prompts=self.connection.config.require_passphrase,
                        capture=not self.connection.config.require_passphrase,
                    )
                    if result.returncode:
                        raise PiccoloError(
                            "Cannot generate a native OpenSSH key; "
                            "the original key was not replaced"
                        )
                    with os.fdopen(private_file(staged), "rb") as stream:
                        contents = stream.read()
                    with os.fdopen(
                        private_file(key, create=True, exclusive=True), "wb"
                    ) as stream:
                        stream.write(contents)
            with os.fdopen(private_file(key), "rb") as stream:
                contents = stream.read()
            # A private-only copy prevents ssh-keygen from trusting an unrelated .pub
            # sidecar while it inspects the private file's embedded public identity.
            with temporary_directory("piccolo-key-check-") as directory:
                isolated = directory / "key"
                with os.fdopen(
                    private_file(isolated, create=True, exclusive=True), "wb"
                ) as stream:
                    stream.write(contents)
                fingerprint = self.key_command(
                    ["-l", "-E", "sha256", "-f", str(isolated)]
                )
                fields = fingerprint.stdout.split()
                if fingerprint.returncode or len(fields) < 2:
                    raise PiccoloError(
                        "Invalid or unsupported existing SSH private key; "
                        "restore it deliberately"
                    )
                if self.connection.config.require_passphrase:
                    unencrypted = self.key_command(
                        ["-y", "-P", "", "-f", str(isolated)]
                    )
                    if unencrypted.returncode == 0:
                        raise PiccoloError(
                            "gcp.ssh.require_passphrase requires an encrypted key; "
                            "encrypt the existing key deliberately"
                        )
                if not (public.exists() or public.is_symlink()):
                    recovered = self.key_command(
                        [
                            "-y",
                            "-f",
                            str(isolated),
                            *(
                                []
                                if self.connection.config.require_passphrase
                                else ["-P", ""]
                            ),
                        ],
                        prompts=self.connection.config.require_passphrase,
                    )
                    if recovered.returncode:
                        raise PiccoloError(
                            "Cannot recover the missing SSH public key; "
                            "use native ssh-keygen -y with the key's passphrase, "
                            "retaining the private key"
                        )
                    with os.fdopen(
                        private_file(public, create=True, exclusive=True),
                        "w",
                        encoding="utf-8",
                        newline="\n",
                    ) as stream:
                        stream.write(recovered.stdout.strip() + "\n")
                with os.fdopen(private_file(public), encoding="utf-8") as stream:
                    material = stream.read().strip()
                public_identity = self.key_command(
                    ["-l", "-E", "sha256", "-f", str(public)]
                )
                public_fields = public_identity.stdout.split()
                if (
                    public_identity.returncode
                    or len(public_fields) < 2
                    or public_fields[1] != fields[1]
                    or "\n" in material
                    or "\r" in material
                ):
                    raise PiccoloError(
                        "Existing SSH public/private keys do not match; "
                        "restore the pair deliberately"
                    )
                return material

    def native_options(self, zone: str) -> tuple[list[str], str]:
        """Authorize one key and build isolated strict native SSH/SCP options."""
        self.connection.environment()
        self.connection.before_ssh(zone)
        if self.connection.target is None:
            raise PiccoloError("SSH requires a provider-bound instance identity")
        selected = self.connection.target(zone)
        identity = text(selected, "id")
        if not identity.isdecimal():
            raise PiccoloError("Cannot verify SSH instance identity")
        public = self.prepare_key()
        self.authorization.authorize(zone, identity, public)
        enrolled = self.connection.host_options(zone, "ssh-flag")
        options = [
            "-F",
            str(self.connection.empty_config),
            "-i",
            str(self.connection.key_file),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "BatchMode="
            + ("no" if self.connection.config.require_passphrase else "yes"),
        ]
        for option in enrolled:
            if option.startswith("--ssh-flag=-o"):
                options.extend(["-o", option.removeprefix("--ssh-flag=-o")])
        address = self.connection.config.name
        if self.connection.config.via_iap:
            options.extend(["-o", "ProxyCommand=" + self.proxy_command(zone)])
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
        return options, address

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
        """Run native OpenSSH with foreground PTY or bounded remote command capture."""
        if self.connection.config.require_passphrase and not (
            sys.stdin.isatty() and sys.stderr.isatty()
        ):
            raise PiccoloError("Passphrase prompts require an interactive terminal")
        options, address = self.native_options(zone)
        user = shlex.quote(self.connection.config.ssh_user)
        guard = (
            f'if test "$(id -un)" != {user}; then '
            "printf 'Piccolo SSH user mismatch; review gcp.ssh.user\\n' >&2; "
            "exit 65; fi; "
        )
        remote = guard + (
            command if command is not None else 'exec "${SHELL:-/bin/bash}" -l'
        )
        marker = "piccolo-output-" + uuid.uuid4().hex
        prompts = self.connection.config.require_passphrase
        if prompts and capture:
            remote = (
                f"printf '{marker}\\n'; ({remote}); rc=$?; "
                f"printf '{marker}\\n'; exit \"$rc\""
            )
        arguments = [
            self.executable("ssh"),
            *options,
            "-T" if capture else "-tt",
            f"{self.connection.config.ssh_user}@{address}",
            remote,
        ]
        try:
            result = run_command(
                arguments,
                self.connection.environment(),
                timeout=None if timeout is None else self.remaining(timeout),
                capture=capture,
                prompts=prompts,
            )
        except subprocess.TimeoutExpired as exc:
            raise PiccoloError(
                f"Native SSH command timed out after {timeout}s"
            ) from exc
        except OSError as exc:
            raise PiccoloError("Cannot launch native Windows OpenSSH") from exc
        if prompts and capture:
            pieces = result.stdout.replace("\r\n", "\n").split(marker + "\n")
            result.stdout = pieces[1] if len(pieces) >= 3 else ""
        return result

    def native_copy(self, zone: str, source: Path, destination: str) -> None:
        """Apply one deadline to the whole native bootstrap transfer."""
        with self.bounded(120):
            self.native_transfer(zone, source, destination)

    def native_transfer(self, zone: str, source: Path, destination: str) -> None:
        """Use native SFTP-backed SCP with bounded authorization retries."""
        if self.connection.config.require_passphrase and not (
            sys.stdin.isatty() and sys.stderr.isatty()
        ):
            raise PiccoloError("Passphrase prompts require an interactive terminal")
        path = PurePosixPath(destination)
        if (
            not destination
            or path.is_absolute()
            or ".." in path.parts
            or any(c in destination for c in "\n\r\0")
        ):
            raise PiccoloError("SCP destination must be a safe home-relative path")
        options, address = self.native_options(zone)
        command = [
            self.executable("scp"),
            *options,
            str(source.absolute()),
            f"{self.connection.config.ssh_user}@{address}:~/{destination}",
        ]
        deadline = time.monotonic() + 120
        for attempt in range(4):
            try:
                result = run_command(
                    command,
                    self.connection.environment(),
                    timeout=self.remaining(max(1, deadline - time.monotonic())),
                    capture=not self.connection.config.require_passphrase,
                    prompts=self.connection.config.require_passphrase,
                )
            except subprocess.TimeoutExpired as exc:
                raise PiccoloError("Native bootstrap transfer timed out") from exc
            if not result.returncode:
                return
            diagnostic = result.stderr.strip()
            if (
                result.returncode != 255
                or "permission denied (publickey)" not in diagnostic.lower()
                or attempt == 3
                or deadline - time.monotonic() <= 2
            ):
                raise PiccoloError(
                    f"Bootstrap transfer failed ({result.returncode}): {diagnostic}"
                )
            time.sleep(2)

    def host_options(self, zone: str, flag: str) -> list[str]:
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
            with os.fdopen(
                private_file(path, create=True), "a", encoding="utf-8", newline="\n"
            ) as stream:
                stream.write("".join(lines))
            self.connection.host_files[zone] = (identity, path)
        path = self.connection.host_files[zone][1]
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
