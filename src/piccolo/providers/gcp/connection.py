# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""connection.py — gcloud transport for SSH, opaque file transfer, and IAP."""

import base64
import binascii
import codecs
import os
import re
import selectors
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from piccolo.config.models import GCP
from piccolo.data import Document, decode, document, objects, text
from piccolo.errors import PiccoloError
from piccolo.logger import log

AUTH_OVERRIDES = (
    "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
    "CLOUDSDK_AUTH_DISABLE_CREDENTIALS",
)


class GCloudConnection:
    """Keep SDK authentication distinct from an explicit gcloud login identity."""

    def __init__(
        self,
        config: GCP,
        target: Callable[[str], Document] | None = None,
        host_keys: Callable[[str], Document] | None = None,
    ) -> None:
        """Record configuration without requiring gcloud for SDK-only commands."""
        self.config = config
        self.windows = os.name == "nt"
        self.selected_account = config.connection_account
        self.identity_checked = False
        self.target = target
        self.host_keys = host_keys
        self.host_directory = tempfile.TemporaryDirectory(prefix="piccolo-host-trust-")
        self.host_files: dict[str, tuple[str, Path]] = {}
        self.user_home = Path.home()
        self.known_hosts = (
            Path(self.host_directory.name) / ".ssh" / "google_compute_known_hosts"
        )
        self.known_hosts.parent.mkdir(mode=0o700)

    def executable(self) -> str:
        """Resolve gcloud, including Windows command shims."""
        found = shutil.which("gcloud") or shutil.which("gcloud.cmd")
        if found is None:
            raise PiccoloError(
                "gcloud is required for SSH, bootstrap transfer, and IAP tunnels"
            )
        return found

    def flags(self) -> list[str]:
        """Specify connection identity and avoid credential-file inheritance."""
        result = [f"--project={self.config.project_id}"]
        if not self.config.require_passphrase:
            result.append("--quiet")
        if self.selected_account:
            result.append(f"--account={self.selected_account}")
        if self.config.connection_impersonate:
            result.append(
                f"--impersonate-service-account={self.config.connection_impersonate}"
            )
        return result

    def launcher(self) -> list[str]:
        """Use the SDK Python entry point on Windows to avoid batch interpolation."""
        executable = self.executable()
        if self.windows and executable.lower().endswith((".cmd", ".bat")):
            entry = Path(executable).parent.parent / "lib" / "gcloud.py"
            if not entry.is_file():
                raise PiccoloError(
                    "Cannot locate the Windows SDK Python entry point; "
                    "install the full Google Cloud CLI"
                )
            return [os.environ.get("CLOUDSDK_PYTHON", sys.executable), str(entry)]
        return [executable]

    def run(
        self, arguments: list[str], *, timeout: int | None = 60, capture: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Validate credential policy on every command, including receipt reads."""
        environment = self.environment()
        if arguments[:1] == ["compute"] and not self.identity_checked:
            self.check_identity()
        if arguments[:2] in (["compute", "ssh"], ["compute", "scp"]):
            environment["CLOUDSDK_CONFIG"] = environment.get(
                "CLOUDSDK_CONFIG", str(self.user_home / ".config" / "gcloud")
            )
            environment["HOME"] = self.host_directory.name
        return self.invoke(arguments, environment, timeout=timeout, capture=capture)

    def environment(self) -> dict[str, str]:
        """Reject inherited credentials before inspecting the local CLI config."""
        environment = os.environ.copy()
        for variable in AUTH_OVERRIDES:
            if environment.get(variable):
                raise PiccoloError(f"Unset {variable} before gcloud connections")
        if self.config.require_passphrase and environment.get(
            "CLOUDSDK_CORE_DISABLE_PROMPTS", "false"
        ).lower() not in {"false", "0", ""}:
            raise PiccoloError(
                "Unset CLOUDSDK_CORE_DISABLE_PROMPTS for passphrase prompts"
            )
        result = self.invoke(
            ["config", "list", "--format=json"], environment, use_flags=False
        )
        if result.returncode:
            raise PiccoloError("Cannot inspect gcloud authentication configuration")
        try:
            configuration = decode(result.stdout)
            auth = document(configuration.get("auth", {}))
        except ValueError as exc:
            raise PiccoloError("Invalid gcloud configuration response") from exc
        for key in (
            "access_token_file",
            "credential_file_override",
            "impersonate_service_account",
        ):
            if auth.get(key) not in (None, "", "(unset)"):
                raise PiccoloError(f"Unset gcloud auth/{key} before connections")
        if str(auth.get("disable_credentials", "false")).lower() not in {
            "false",
            "none",
            "",
            "(unset)",
        }:
            raise PiccoloError(
                "Unset gcloud auth/disable_credentials before connections"
            )
        core = document(configuration.get("core", {}))
        if self.config.require_passphrase and str(
            core.get("disable_prompts", "false")
        ).lower() not in {"false", "none", "", "(unset)"}:
            raise PiccoloError(
                "Unset gcloud core/disable_prompts for passphrase prompts"
            )
        return environment

    def invoke(
        self,
        arguments: list[str],
        environment: dict[str, str],
        *,
        timeout: int | None = 60,
        capture: bool = True,
        use_flags: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Launch gcloud using an already inspected environment snapshot."""
        interactive = self.config.require_passphrase and arguments[:2] in (
            ["compute", "ssh"],
            ["compute", "scp"],
        )
        if interactive and not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise PiccoloError("Passphrase prompts require an interactive terminal")
        try:
            if interactive and capture:
                return self.interactive_invoke(arguments, environment, timeout=timeout)
            return subprocess.run(
                [*self.launcher(), *arguments, *(self.flags() if use_flags else [])],
                shell=False,
                text=True,
                capture_output=capture,
                timeout=timeout,
                env=environment,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PiccoloError(
                f"gcloud connection command timed out after {timeout}s"
            ) from exc
        except OSError as exc:
            raise PiccoloError(f"Cannot launch gcloud: {exc}") from exc

    def interactive_invoke(
        self,
        arguments: list[str],
        environment: dict[str, str],
        *,
        timeout: float | None,
    ) -> subprocess.CompletedProcess[str]:
        """Forward terminal prompts and retain framed remote output."""
        marker = "piccolo-output-" + uuid.uuid4().hex
        framed = list(arguments)
        for index, argument in enumerate(framed):
            if argument.startswith("--command="):
                remote = argument.removeprefix("--command=")
                framed[index] = (
                    f"--command=printf '{marker}\\n'; ({remote}); rc=$?; "
                    f"printf '{marker}\\n'; exit \"$rc\""
                )
        command = [*self.launcher(), *framed, *self.flags()]
        output: list[str] = []
        with subprocess.Popen(
            command, shell=False, text=True, stdout=subprocess.PIPE, env=environment
        ) as process:
            stream = process.stdout
            if stream is None:
                raise PiccoloError("Interactive gcloud stdout is unavailable")

            deadline = None if timeout is None else time.monotonic() + timeout
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            os.set_blocking(stream.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(stream, selectors.EVENT_READ)
                while True:
                    if (
                        timeout is not None
                        and deadline is not None
                        and time.monotonic() >= deadline
                    ):
                        process.kill()
                        process.wait()
                        raise subprocess.TimeoutExpired(command, timeout)
                    events = selector.select(timeout=0.1)
                    if not events and process.poll() is not None:
                        break
                    if events:
                        try:
                            chunk = os.read(stream.fileno(), 4096)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            break
                        rendered = decoder.decode(chunk)
                        output.append(rendered)
                        sys.stdout.write(rendered)
                        sys.stdout.flush()
                rendered = decoder.decode(b"", final=True)
                output.append(rendered)
                sys.stdout.write(rendered)
                sys.stdout.flush()
            remaining = (
                None if deadline is None else max(0, deadline - time.monotonic())
            )
            try:
                code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise
        captured = "".join(output)
        pieces = captured.split(marker + "\n")
        remote_output = pieces[1] if len(pieces) >= 3 else ""
        return subprocess.CompletedProcess(command, code, remote_output, "")

    def check_identity(self) -> None:
        """Report the connection identity and enforce explicit credential separation."""
        if (
            self.config.auth.credential_file
            or self.config.auth.impersonate_service_account
        ) and not (
            self.config.connection_account or self.config.connection_impersonate
        ):
            raise PiccoloError(
                "SDK file/impersonation authentication is "
                "configured; explicitly set gcp.ssh.account or "
                "gcp.ssh.impersonate_service_account for "
                "connections"
            )
        result = self.run(
            ["auth", "list", "--filter=status:ACTIVE", "--format=value(account)"],
            timeout=30,
        )
        selected = self.config.connection_account or result.stdout.strip()
        if result.returncode or not selected:
            raise PiccoloError(
                "No usable gcloud connection identity; run gcloud auth login"
            )
        if self.config.connection_account:
            available = self.run(
                ["auth", "list", "--format=value(account)"], timeout=30
            )
            if available.returncode or selected not in available.stdout.splitlines():
                raise PiccoloError(f"gcloud account {selected} is not logged in")
        self.selected_account = selected
        self.identity_checked = True
        log(
            f"Connection account: {selected}; "
            f"impersonation: "
            f"{self.config.connection_impersonate or 'none'} "
            f"(separate from SDK credentials)"
        )

    def host_options(self, zone: str, flag: str) -> list[str]:
        """Enroll host keys through authenticated GCP reads bound to the selected ID."""
        if self.windows:
            raise PiccoloError(
                "Verified SSH host enrollment currently requires OpenSSH on Linux/macOS"
            )
        if self.target is None:
            raise PiccoloError("SSH requires a provider-bound instance identity")
        selected = self.target(zone)
        identity = text(selected, "id")
        if not identity.isdecimal():
            raise PiccoloError("Cannot verify SSH instance identity")
        alias = f"compute.{identity}"
        enrolled = self.host_files.get(zone)
        if enrolled is None or enrolled[0] != identity:
            if self.host_keys is None:
                raise PiccoloError("SSH requires authenticated Compute host-key reads")
            entries = objects(
                document(self.host_keys(zone).get("query_value", {})), "items"
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
                except (ValueError, binascii.Error) as exc:
                    raise PiccoloError("Malformed GCP host key") from exc
                lines.append(f"{alias} {algorithm} {value}\n")
            if not lines:
                raise PiccoloError(
                    "No trusted GCP host keys are published. Enable "
                    "enable-guest-attributes and have the Google guest agent publish "
                    "hostkeys before connecting; unknown SSH host keys are refused."
                )
            if text(self.target(zone), "id") != identity:
                raise PiccoloError("Instance changed during host-key enrollment")
            path = self.known_hosts
            with path.open("a") as stream:
                stream.write("".join(lines))
            path.chmod(0o600)
            self.host_files[zone] = (identity, path)
        path = self.host_files[zone][1]
        return [
            "--strict-host-key-checking=yes",
            f"--ssh-key-expire-after={self.config.expire_after}",
            f"--ssh-key-file={self.user_home / '.ssh' / 'google_compute_engine'}",
            f"--{flag}=-oHostKeyAlias={alias}",
            f"--{flag}=-oUserKnownHostsFile={path}",
            f"--{flag}=-oGlobalKnownHostsFile=/dev/null",
            f"--{flag}=-oKnownHostsCommand=none",
            f"--{flag}=-oVerifyHostKeyDNS=no",
            f"--{flag}=-oUpdateHostKeys=no",
            f"--{flag}=-F/dev/null",
            f"--{flag}=-oCheckHostIP=no",
        ]

    def ssh_arguments(self, zone: str, command: str | None = None) -> list[str]:
        """Build a gcloud SSH command for the configured development user."""
        args = [
            "compute",
            "ssh",
            f"{self.config.ssh_user}@{self.config.name}",
            f"--zone={zone}",
        ]
        args.extend(self.host_options(zone, "ssh-flag"))
        if self.config.via_iap:
            args.append("--tunnel-through-iap")
        elif self.config.internal_ip:
            args.append("--internal-ip")
        if command is not None:
            user = shlex.quote(self.config.ssh_user)
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
        self.check_identity()
        deadline = time.monotonic() + self.config.readiness_timeout
        diagnostic = "SSH not ready"
        while time.monotonic() < deadline:
            remaining = max(1, int(deadline - time.monotonic()))
            try:
                result = self.run(
                    self.ssh_arguments(zone, "true"), timeout=min(25, remaining)
                )
                if result.returncode == 0:
                    if self.config.readiness_command:
                        self.execute(
                            zone, self.config.readiness_command, timeout=remaining
                        )
                    return
                diagnostic = result.stderr.strip()
                if result.returncode == 65:
                    raise PiccoloError("SSH user mismatch; review gcp.ssh.user")
                if any(
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
        result = self.run(self.ssh_arguments(zone, command), timeout=timeout)
        if result.returncode:
            raise PiccoloError(
                f"Remote command failed ({result.returncode}): {result.stderr.strip()}"
            )
        return result.stdout.strip()

    def copy(self, zone: str, source: Path, destination: str) -> None:
        """Copy a relative path, allowing bounded renewed-key propagation."""
        args = [
            "compute",
            "scp",
            str(source),
            f"{self.config.ssh_user}@{self.config.name}:~/{destination}",
            f"--zone={zone}",
        ]
        args.extend(self.host_options(zone, "scp-flag"))
        args.append("--scp-flag=-oBatchMode=yes")
        if self.config.via_iap:
            args.append("--tunnel-through-iap")
        elif self.config.internal_ip:
            args.append("--internal-ip")
        deadline = time.monotonic() + 120
        for attempt in range(4):
            result = self.run(
                args,
                timeout=max(1, int(deadline - time.monotonic())),
                capture=not self.config.require_passphrase,
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
        result = self.run(self.ssh_arguments(zone), timeout=None, capture=False)
        if result.returncode:
            raise PiccoloError(f"SSH session exited with status {result.returncode}")

    def tunnel(self, zone: str) -> None:
        """Forward the configured port to localhost until interrupted."""
        self.check_identity()
        result = self.run(
            [
                "compute",
                "start-iap-tunnel",
                self.config.name,
                str(self.config.remote_port),
                f"--zone={zone}",
                f"--local-host-port=localhost:{self.config.local_port}",
            ],
            timeout=None,
            capture=False,
        )
        if result.returncode:
            raise PiccoloError(f"IAP tunnel exited with status {result.returncode}")
