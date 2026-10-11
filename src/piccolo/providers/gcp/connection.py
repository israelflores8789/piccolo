# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""connection.py — gcloud transport for SSH, opaque file transfer, and IAP."""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from piccolo.config.models import GCP
from piccolo.errors import PiccoloError


class GCloudConnection:
    """Keep SDK authentication distinct from an explicit gcloud login identity."""

    def __init__(self, config: GCP) -> None:
        """Record configuration without requiring gcloud for SDK-only commands."""
        self.config = config
        self.windows = os.name == "nt"
        self.selected_account = config.connection_account

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
        result = [f"--project={self.config.project_id}", "--quiet"]
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
        """Run an argument array with terminal passthrough when interactive."""
        environment = os.environ.copy()
        environment.pop("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", None)
        try:
            return subprocess.run(
                [*self.launcher(), *arguments, *self.flags()],
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
            if selected not in available.stdout.splitlines():
                raise PiccoloError(f"gcloud account {selected} is not logged in")
        self.selected_account = selected
        print(
            f"Connection account: {selected}; "
            f"impersonation: "
            f"{self.config.connection_impersonate or 'none'} "
            f"(separate from SDK credentials)"
        )

    def ssh_arguments(self, zone: str, command: str | None = None) -> list[str]:
        """Build a gcloud SSH command for the configured development user."""
        args = [
            "compute",
            "ssh",
            f"{self.config.ssh_user}@{self.config.name}",
            f"--zone={zone}",
        ]
        if self.config.via_iap:
            args.append("--tunnel-through-iap")
        if command is not None:
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
                if "timed out" not in str(exc):
                    raise
                diagnostic = str(exc)
            print(f"Waiting for SSH in {zone}...")
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
        """Copy to a validated relative path using gcloud compute scp."""
        args = [
            "compute",
            "scp",
            str(source),
            f"{self.config.ssh_user}@{self.config.name}:~/{destination}",
            f"--zone={zone}",
        ]
        if self.config.via_iap:
            args.append("--tunnel-through-iap")
        result = self.run(args, timeout=120)
        if result.returncode:
            raise PiccoloError(f"Bootstrap transfer failed: {result.stderr.strip()}")

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
