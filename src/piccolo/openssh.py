# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""openssh.py — Provider-neutral key preparation and strict OpenSSH execution."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from platformdirs import user_state_path

from piccolo.errors import PiccoloError
from piccolo.process import run_command
from piccolo.state.lock import file_lock
from piccolo.state.storage import private_directory, private_file, temporary_directory


@dataclass(frozen=True)
class SSHSession:
    """Resolved transport inputs, including authenticated host trust and proxy."""

    address: str
    username: str
    key_file: Path
    known_hosts: Path
    host_alias: str
    empty_config: Path
    require_passphrase: bool = False
    proxy_command: str | None = None


def write_host_keys(path: Path, entries: list[str]) -> None:
    """Append provider-authenticated host entries to a private trust file."""
    with os.fdopen(
        private_file(path, create=True), "a", encoding="utf-8", newline="\n"
    ) as stream:
        stream.write("".join(entries))


class OpenSSH:
    """Execute resolved sessions with inspected environments and shared deadlines."""

    def __init__(
        self,
        environment: Callable[[], dict[str, str]],
        deadline: Callable[[], float | None],
        *,
        windows: bool = sys.platform == "win32",
    ) -> None:
        """Retain runtime suppliers without assuming provider identity or policy."""
        self.windows = windows
        self.environment = environment
        self.deadline = deadline
        self._executables: dict[str, str] = {}

    def remaining(self, seconds: float) -> float:
        """Bound a native subprocess by the complete operation's remaining time."""
        deadline = self.deadline()
        if deadline is None:
            return seconds
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PiccoloError("Native SSH connection preparation timed out")
        return min(seconds, remaining)

    def executable(self, name: str) -> str:
        """Select native Windows OpenSSH 9.0+, or the platform OpenSSH client."""
        if name in self._executables:
            return self._executables[name]
        if not self.windows:
            executable = shutil.which(name)
            if executable is None:
                raise PiccoloError(f"Install OpenSSH; {name} is required")
            self._executables[name] = executable
            return executable
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
                self.environment(),
                timeout=self.remaining(120),
                capture=capture,
                prompts=prompts,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PiccoloError(
                "Native SSH key preparation failed or timed out"
            ) from exc

    def prepare_key(self, key: Path, username: str, require_passphrase: bool) -> str:
        """Reuse an owned key pair, recovering only a missing public half safely."""
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
                        username,
                    ]
                    if not require_passphrase:
                        arguments.extend(["-N", ""])
                    result = self.key_command(
                        arguments,
                        prompts=require_passphrase,
                        capture=not require_passphrase,
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
                if require_passphrase:
                    unencrypted = self.key_command(
                        ["-y", "-P", "", "-f", str(isolated)]
                    )
                    if unencrypted.returncode == 0:
                        raise PiccoloError(
                            "SSH passphrase policy requires an encrypted key; "
                            "encrypt the existing key deliberately"
                        )
                if not (public.exists() or public.is_symlink()):
                    recovered = self.key_command(
                        [
                            "-y",
                            "-f",
                            str(isolated),
                            *([] if require_passphrase else ["-P", ""]),
                        ],
                        prompts=require_passphrase,
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

    def options(self, session: SSHSession) -> list[str]:
        """Isolate configuration and require the provider's enrolled host identity."""
        options = [
            "-F",
            str(session.empty_config),
            "-i",
            str(session.key_file),
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
            "BatchMode=" + ("no" if session.require_passphrase else "yes"),
        ]
        for option in (
            f"HostKeyAlias={session.host_alias}",
            f'UserKnownHostsFile="{session.known_hosts.as_posix()}"',
            f'GlobalKnownHostsFile="{session.empty_config.as_posix()}"',
            "KnownHostsCommand=none",
            "VerifyHostKeyDNS=no",
            "UpdateHostKeys=no",
            "CheckHostIP=no",
        ):
            options.extend(["-o", option])
        if session.proxy_command is not None:
            options.extend(["-o", "ProxyCommand=" + session.proxy_command])
        return options

    @staticmethod
    def check_terminal(require_passphrase: bool) -> None:
        """Require a real terminal before preparing a prompted operation."""
        if require_passphrase and not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise PiccoloError("Passphrase prompts require an interactive terminal")

    def command(
        self, session: SSHSession, remote: str, *, timeout: int | None, capture: bool
    ) -> subprocess.CompletedProcess[str]:
        """Run native OpenSSH with foreground PTY or bounded remote command capture."""
        self.check_terminal(session.require_passphrase)
        options = self.options(session)
        marker = "piccolo-output-" + uuid.uuid4().hex
        prompts = session.require_passphrase
        if prompts and capture:
            remote = (
                f"printf '{marker}\\n'; ({remote}); rc=$?; "
                f"printf '{marker}\\n'; exit \"$rc\""
            )
        arguments = [
            self.executable("ssh"),
            *options,
            "-T" if capture else "-tt",
            f"{session.username}@{session.address}",
            remote,
        ]
        try:
            result = run_command(
                arguments,
                self.environment(),
                timeout=None if timeout is None else self.remaining(timeout),
                capture=capture,
                prompts=prompts,
            )
        except subprocess.TimeoutExpired as exc:
            raise PiccoloError(
                f"Native SSH command timed out after {timeout}s"
            ) from exc
        except OSError as exc:
            raise PiccoloError("Cannot launch OpenSSH") from exc
        if prompts and capture:
            pieces = result.stdout.replace("\r\n", "\n").split(marker + "\n")
            result.stdout = pieces[1] if len(pieces) >= 3 else ""
        return result

    @staticmethod
    def check_destination(destination: str) -> None:
        """Refuse paths that could escape the remote user's home directory."""
        path = PurePosixPath(destination)
        if (
            not destination
            or path.is_absolute()
            or ".." in path.parts
            or any(c in destination for c in "\n\r\0")
        ):
            raise PiccoloError("SCP destination must be a safe home-relative path")

    def transfer(self, session: SSHSession, source: Path, destination: str) -> None:
        """Use native SFTP-backed SCP with bounded authorization retries."""
        self.check_terminal(session.require_passphrase)
        self.check_destination(destination)
        options = self.options(session)
        command = [
            self.executable("scp"),
            *options,
            str(source.absolute()),
            f"{session.username}@{session.address}:~/{destination}",
        ]
        deadline = time.monotonic() + 120
        for attempt in range(4):
            try:
                result = run_command(
                    command,
                    self.environment(),
                    timeout=self.remaining(max(1, deadline - time.monotonic())),
                    capture=not session.require_passphrase,
                    prompts=session.require_passphrase,
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
