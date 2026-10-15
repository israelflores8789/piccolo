# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""connection.py — gcloud identity facade and platform-independent SSH/IAP dispatch."""

import os
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from piccolo.config.models import GCP
from piccolo.data import Document, decode, document
from piccolo.errors import PiccoloError
from piccolo.logger import log
from piccolo.process import run_command
from piccolo.providers.gcp.paths import cloud_sdk_directory
from piccolo.providers.gcp.ssh import SSHTransport
from piccolo.state.storage import (
    PrivateTemporaryDirectory,
    private_directory,
    private_file,
)

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
        self.deadline: float | None = None
        self.target = target
        self.host_keys = host_keys
        self.host_directory = PrivateTemporaryDirectory("piccolo-host-trust-")
        self.host_files: dict[str, tuple[str, Path]] = {}
        self.user_home = Path.home()
        self.key_file = self.user_home / ".ssh" / "google_compute_engine"
        self.known_hosts = (
            Path(self.host_directory.name) / ".ssh" / "google_compute_known_hosts"
        )
        private_directory(self.known_hosts.parent)
        self.empty_config = self.known_hosts.parent / "empty"
        os.close(private_file(self.empty_config, create=True, exclusive=True))
        self.sdk_directory = cloud_sdk_directory()
        self.ssh = SSHTransport(self)

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
            bundled = entry.parent.parent / "platform" / "bundledpython" / "python.exe"
            interpreter = os.environ.get("CLOUDSDK_PYTHON") or (
                str(bundled) if bundled.is_file() else sys.executable
            )
            return [interpreter, str(entry)]
        return [executable]

    def run(
        self, arguments: list[str], *, timeout: int | None = 60, capture: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Validate credential policy on every command, including receipt reads."""
        environment = self.environment()
        if arguments[:1] == ["compute"] and not self.identity_checked:
            self.check_identity()
        if arguments[:2] in (["compute", "ssh"], ["compute", "scp"]):
            environment["CLOUDSDK_CONFIG"] = str(self.sdk_directory)
            environment["HOME"] = self.host_directory.name
        return self.invoke(arguments, environment, timeout=timeout, capture=capture)

    def environment(self) -> dict[str, str]:
        """Reject inherited credentials before inspecting the local CLI config."""
        environment = os.environ.copy()
        environment["CLOUDSDK_CONFIG"] = str(self.sdk_directory)
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
        bounded: float | None = timeout
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise PiccoloError("SSH connection preparation timed out")
            bounded = remaining if timeout is None else min(timeout, remaining)
        interactive = self.config.require_passphrase and arguments[:2] in (
            ["compute", "ssh"],
            ["compute", "scp"],
        )
        if interactive and not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise PiccoloError("Passphrase prompts require an interactive terminal")
        try:
            if interactive and capture:
                return self.interactive_invoke(arguments, environment, timeout=bounded)
            if self.windows:
                return run_command(
                    [
                        *self.launcher(),
                        *arguments,
                        *(self.flags() if use_flags else []),
                    ],
                    environment,
                    timeout=bounded,
                    capture=capture,
                )
            return subprocess.run(
                [*self.launcher(), *arguments, *(self.flags() if use_flags else [])],
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=capture,
                timeout=bounded,
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
        result = run_command(command, environment, timeout=timeout, prompts=True)
        pieces = result.stdout.replace("\r\n", "\n").split(marker + "\n")
        remote_output = pieces[1] if len(pieces) >= 3 else ""
        return subprocess.CompletedProcess(
            command, result.returncode, remote_output, ""
        )

    def check_identity(self) -> None:
        """Report the connection identity and enforce explicit credential separation."""
        if (
            self.config.auth.credentials_file
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
        """Enroll authenticated host keys through the shared SSH component."""
        return self.ssh.host_options(zone, flag)

    def ssh_arguments(self, zone: str, command: str | None = None) -> list[str]:
        """Retain the gcloud argument contract for the POSIX transport."""
        return self.ssh.ssh_arguments(zone, command)

    def ready(self, zone: str) -> None:
        """Wait for authenticated SSH with a bounded readiness deadline."""
        self.ssh.ready(zone)

    def execute(self, zone: str, command: str, timeout: int = 60) -> str:
        """Execute through the platform-selected SSH component."""
        return self.ssh.execute(zone, command, timeout)

    def copy(self, zone: str, source: Path, destination: str) -> None:
        """Transfer through the platform-selected SSH component."""
        self.ssh.copy(zone, source, destination)

    def shell(self, zone: str) -> None:
        """Open a foreground SSH session with terminal IO intact."""
        self.ssh.shell(zone)

    def before_ssh(self, zone: str) -> None:
        """Validate connection identity before preparing or authorizing a key."""
        del zone
        self.check_identity()

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
