# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_ssh_expiry.py — Offline expiration-oracle and disposable-key safety checks."""

import json
import shutil
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest
from gcp_live_support import ssh_expiry
from gcp_live_support.gcp_sdk import LiveCloud
from gcp_live_support.manifest import Manifest
from google.auth.credentials import AnonymousCredentials

from piccolo.config import Config
from piccolo.data import Document, document, objects, text
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.connection import GCloudConnection
from piccolo.providers.gcp.provider import GCPProvider
from piccolo.providers.gcp.provision import labels

RUN = "plive-0123456789abcdef"
ZONE = "us-west1-a"
PUBLIC = "ssh-ed25519 dGVzdA== fixture"


class Clock:
    """Advance wall and monotonic time without sleeping or contacting a guest."""

    def __init__(self) -> None:
        """Start from a fixed epoch for deterministic metadata timestamps."""
        self.now = 1_000.0

    def time(self) -> float:
        """Return the simulated wall clock."""
        return self.now

    def monotonic(self) -> float:
        """Return the simulated monotonic clock."""
        return self.now

    def sleep(self, seconds: float) -> None:
        """Advance both clocks without delaying the local suite."""
        self.now += seconds


@pytest.fixture
def scenario(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[GCPProvider, Manifest, Document]:
    if shutil.which("ssh-keygen") is None:
        pytest.skip("local disposable-key fixture requires ssh-keygen")
    config = replace(
        config,
        environment=RUN,
        gcp=replace(
            config.gcp, name=f"{RUN}-vm", connection_account="owner@example.com"
        ),
    )
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", config.gcp.project_id)
    manifest = Manifest.create(
        tmp_path / RUN / "manifest.json",
        config.path,
        RUN,
        project=config.gcp.project_id,
    )
    cloud = LiveCloud(config, Clients(AnonymousCredentials()), manifest)
    disk_link = f"projects/{config.gcp.project_id}/zones/{ZONE}/disks/{RUN}-boot"
    instance: Document = {
        "name": config.gcp.name,
        "id": "123",
        "zone": ZONE,
        "status": "RUNNING",
        "labels": labels(config),
        "metadata": {"fingerprint": "original", "items": []},
        "disks": [{"boot": True, "type_": "PERSISTENT", "source": disk_link}],
    }
    disk: Document = {"id": "456", "name": f"{RUN}-boot"}
    entry = manifest.register(
        "instance", config.gcp.name, ZONE, {"labels": labels(config)}
    )
    entry["id"] = "123"
    manifest.put("resources", entry)
    monkeypatch.setattr(cloud, "list", Mock(return_value=[instance]))

    def get(kind: str, name: str, zone: str = "") -> Document | None:
        del name, zone
        return document(instance if kind == "instance" else disk)

    monkeypatch.setattr(cloud, "get", get)
    monkeypatch.setattr(cloud, "connection_policy", lambda _instance: None)

    def set_metadata(zone: str, instance_id: str, items: list[Document]) -> None:
        assert zone == ZONE and instance_id == "123"
        instance["metadata"] = {
            "fingerprint": "updated",
            "items": [item for item in items],
        }

    monkeypatch.setattr(cloud, "set_metadata", set_metadata)
    monkeypatch.setattr(GCloudConnection, "environment", lambda _self: {})
    monkeypatch.setattr(GCloudConnection, "launcher", lambda _self: ["gcloud"])
    monkeypatch.setattr(
        GCloudConnection,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 0, "{}", "")),
    )
    provider = GCPProvider(config, cloud)
    provider.journal.data["active_instance_id"] = "123"
    provider.journal.data["active_disk_id"] = "456"
    return provider, manifest, instance


def test_profile_expiration_matches_only_the_test_key() -> None:
    profile: Document = {
        "sshPublicKeys": {
            "unrelated": {"key": "ssh-rsa dW5yZWxhdGVk", "expirationTimeUsec": "0"},
            "own": {"key": PUBLIC, "expirationTimeUsec": "1200000000"},
        }
    }
    assert ssh_expiry.profile_key(profile, PUBLIC) == ("own", 1200.0)
    assert ssh_expiry.profile_key(profile, "ssh-ed25519 bWlzc2luZw==") is None


@pytest.mark.parametrize("expiration", ["0", "", "invalid"])
def test_profile_without_finite_expiration_cannot_prove_expiry(expiration: str) -> None:
    profile: Document = {
        "sshPublicKeys": {"own": {"key": PUBLIC, "expirationTimeUsec": expiration}}
    }
    with pytest.raises(PiccoloError, match="finite expiration"):
        ssh_expiry.profile_key(profile, PUBLIC)


def test_metadata_expiration_ignores_other_users_and_uses_latest_own_entry() -> None:
    metadata: Document = {
        "items": [
            {
                "key": "ssh-keys",
                "value": (
                    "other:ssh-ed25519 dGVzdA== ordinary\n"
                    "researcher:ssh-ed25519 dGVzdA== google-ssh "
                    '{"expireOn":"1970-01-01T00:20:00+0000"}\n'
                    "researcher:ssh-ed25519 dGVzdA== google-ssh "
                    '{"expireOn":"1970-01-01T00:30:00+0000"}'
                ),
            }
        ]
    }
    observed = ssh_expiry.metadata_key(metadata, PUBLIC, "researcher")
    assert observed is not None and observed[1] == 1800.0
    with pytest.raises(PiccoloError, match="non-expiring"):
        ssh_expiry.metadata_key(metadata, PUBLIC, "other")


@pytest.mark.parametrize("mode", ["oslogin", "metadata"])
@pytest.mark.parametrize("transport", ["ssh", "scp"])
def test_expiration_oracle_and_reconnect_order(
    scenario: tuple[GCPProvider, Manifest, Document],
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    transport: str,
) -> None:
    provider, manifest, instance = scenario
    probe = ssh_expiry.SSHExpiryProbe(provider, mode, transport)
    clock = Clock()
    monkeypatch.setattr(ssh_expiry, "time", clock)
    monkeypatch.setattr("piccolo.providers.gcp.ssh.time", clock)
    profile: Document = {}
    expiry = [0.0]
    commands: list[list[str]] = []
    private_key = Path(text(probe.entry, "public_key_path")).with_suffix("")

    def run(
        _self: GCloudConnection, args: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append(args)
        if args[:2] == ["auth", "list"]:
            return subprocess.CompletedProcess(args, 0, "owner@example.com\n", "")
        if args[:3] == ["compute", "os-login", "describe-profile"]:
            return subprocess.CompletedProcess(args, 0, json.dumps(profile), "")
        assert manifest.entries("ssh_keys")[0]["status"] == "publishing"
        flags = [
            f"--ssh-key-expire-after={_self.config.expire_after}",
            f"--ssh-key-file={private_key}",
        ]
        assert flags[0] in args and flags[1] in args
        expiry[0] = clock.now + (45 if _self.config.expire_after == "45s" else 300)
        public = text(probe.entry, "public_key")
        if mode == "oslogin":
            profile["sshPublicKeys"] = {
                "same-fingerprint": {
                    "key": public,
                    "expirationTimeUsec": str(int(expiry[0] * 1_000_000)),
                }
            }
        else:
            stamp = datetime.fromtimestamp(expiry[0], UTC).isoformat()
            body = (
                f"researcher:{ssh_expiry.key_material(public)} google-ssh "
                + json.dumps({"expireOn": stamp})
            )
            metadata = document(instance["metadata"])
            metadata["items"] = [
                *objects(metadata, "items"),
                {"key": "ssh-keys", "value": body},
            ]
            instance["metadata"] = metadata
        output = (
            "authorized" if not probe.entry.get("first_expiration") else "reconnected"
        )
        return subprocess.CompletedProcess(args, 0, output, "")

    monkeypatch.setattr(GCloudConnection, "run", run)

    def native(command: str) -> subprocess.CompletedProcess[str]:
        if clock.now >= expiry[0]:
            return subprocess.CompletedProcess(
                [], 255, "", "Permission denied (publickey)."
            )
        output = (
            "piccolo expiry transfer\n" if command.startswith("cat ") else "authorized"
        )
        return subprocess.CompletedProcess([], 0, output, "")

    monkeypatch.setattr(probe, "native", native)
    host_reads = [0]

    def host_options(_zone: str, _flag: str) -> list[str]:
        host_reads[0] += 1
        if host_reads[0] == 1:
            raise PiccoloError("No trusted GCP host keys are published")
        return [
            f"--ssh-key-expire-after={probe.connection.config.expire_after}",
            f"--ssh-key-file={private_key}",
        ]

    monkeypatch.setattr(probe.connection, "host_options", host_options)
    initial = probe.establish()
    assert host_reads[0] == 3
    original = Path(text(probe.entry, "public_key_path")).read_bytes()
    probe.wait_until_rejected(initial[1])
    assert len([args for args in commands if args[:2] == ["compute", "ssh"]]) == 2
    assert probe.entry["status"] == "expired-and-rejected"
    probe.reconnect(initial)
    assert manifest.entries("ssh_keys")[0]["status"] == "reconnected"
    assert Path(text(probe.entry, "public_key_path")).read_bytes() == original
    transports = [
        args[1]
        for args in commands
        if args[:2] in (["compute", "ssh"], ["compute", "scp"])
    ]
    assert transports == ["ssh", "ssh", transport]


@pytest.mark.parametrize(
    "error",
    ["Connection timed out", "Host key verification failed", "IAP permission denied"],
)
def test_network_or_host_errors_are_not_counted_as_expired_key_rejection(
    scenario: tuple[GCPProvider, Manifest, Document],
    monkeypatch: pytest.MonkeyPatch,
    error: str,
) -> None:
    provider, _, _ = scenario
    probe = ssh_expiry.SSHExpiryProbe(provider, "oslogin", "ssh")
    monkeypatch.setattr(ssh_expiry, "time", Clock())
    monkeypatch.setattr(probe, "authorization", lambda: ("own", 900.0))
    monkeypatch.setattr(
        probe,
        "native",
        Mock(return_value=subprocess.CompletedProcess([], 255, "", error)),
    )
    with pytest.raises(PiccoloError, match="other than key rejection"):
        probe.wait_until_rejected(900.0)


def test_native_probe_cannot_publish_or_use_another_key(
    scenario: tuple[GCPProvider, Manifest, Document],
) -> None:
    provider, _, _ = scenario
    probe = ssh_expiry.SSHExpiryProbe(provider, "oslogin", "scp")
    args = probe.native_arguments("true")
    assert args[0] == "ssh"
    assert "-oIdentityAgent=none" in args and "-oIdentitiesOnly=yes" in args
    assert "-oStrictHostKeyChecking=yes" in args
    assert args[args.index("-i") + 1] == str(
        Path(text(probe.entry, "public_key_path")).with_suffix("")
    )
    proxy = next(arg for arg in args if arg.startswith("-oProxyCommand="))
    assert "start-iap-tunnel" in proxy and "--listen-on-stdin" in proxy
    assert "compute ssh" not in proxy and "compute scp" not in proxy
    assert not any(arg.startswith("--ssh-key-expire") for arg in args)


@pytest.mark.parametrize(
    "change",
    ["account", "path", "public-key", "private-key", "preexisting", "approval"],
)
def test_changed_key_proof_blocks_cleanup_before_gcloud(
    scenario: tuple[GCPProvider, Manifest, Document],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    provider, manifest, _ = scenario
    probe = ssh_expiry.SSHExpiryProbe(provider, "oslogin", "ssh")
    if change == "account":
        probe.entry["account"] = "another@example.com"
    elif change == "path":
        probe.entry["public_key_path"] = "/outside/key.pub"
    elif change == "public-key":
        Path(text(probe.entry, "public_key_path")).write_text("replaced")
    elif change == "private-key":
        private = Path(text(probe.entry, "public_key_path")).with_suffix("")
        replacement = private.with_name("replacement")
        replacement.write_text("different key")
        replacement.replace(private)
    elif change == "preexisting":
        probe.entry["absent_before"] = False
    else:
        monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", "different-project")
    runner = Mock(side_effect=AssertionError("Unsafe cleanup must not invoke gcloud"))
    monkeypatch.setattr(GCloudConnection, "run", runner)
    with pytest.raises(PiccoloError):
        ssh_expiry.remove_test_key(provider.config, manifest, probe.entry)
    runner.assert_not_called()


def test_profile_cleanup_removes_only_recorded_key_and_private_file(
    scenario: tuple[GCPProvider, Manifest, Document],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, manifest, _ = scenario
    probe = ssh_expiry.SSHExpiryProbe(provider, "oslogin", "ssh")
    profile: Document = {
        "sshPublicKeys": {
            "own": {
                "key": text(probe.entry, "public_key"),
                "expirationTimeUsec": "1200000000",
            },
            "other": {"key": "ssh-rsa b3RoZXI= unrelated", "expirationTimeUsec": "0"},
        }
    }
    commands: list[list[str]] = []

    def run(
        _self: GCloudConnection, args: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append(args)
        if args[:4] == ["compute", "os-login", "ssh-keys", "remove"]:
            assert manifest.entries("ssh_keys")[0]["status"] == "removal-intent"
            assert args[-1] == f"--key-file={text(probe.entry, 'public_key_path')}"
            keys = document(profile["sshPublicKeys"])
            keys.pop("own")
            profile["sshPublicKeys"] = keys
        return subprocess.CompletedProcess(args, 0, json.dumps(profile), "")

    monkeypatch.setattr(GCloudConnection, "run", run)
    ssh_expiry.remove_test_key(provider.config, manifest, probe.entry)
    assert "other" in document(profile["sshPublicKeys"])
    assert len(commands) == 3
    assert manifest.entries("ssh_keys")[0]["status"] == "removed"
    public = Path(text(probe.entry, "public_key_path"))
    assert public.exists() and not public.with_suffix("").exists()


def test_replaced_vm_blocks_key_publication(
    scenario: tuple[GCPProvider, Manifest, Document],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, _, instance = scenario
    probe = ssh_expiry.SSHExpiryProbe(provider, "oslogin", "ssh")
    instance["id"] = "999"
    runner = Mock()
    monkeypatch.setattr(GCloudConnection, "run", runner)
    with pytest.raises(PiccoloError, match=r"identity|run-owned"):
        probe.connection.run(["compute", "ssh", "test"])
    runner.assert_not_called()


def test_unobserved_expiry_blocks_reconnect(
    scenario: tuple[GCPProvider, Manifest, Document],
) -> None:
    provider, _, _ = scenario
    probe = ssh_expiry.SSHExpiryProbe(provider, "oslogin", "ssh")
    with pytest.raises(PiccoloError, match="observed before reconnect"):
        probe.reconnect(("own", 1000.0))


def test_expiry_rejection_wait_is_bounded_when_key_still_authenticates(
    scenario: tuple[GCPProvider, Manifest, Document], monkeypatch: pytest.MonkeyPatch
) -> None:
    provider, _, _ = scenario
    probe = ssh_expiry.SSHExpiryProbe(provider, "oslogin", "ssh")
    clock = Clock()
    monkeypatch.setattr(ssh_expiry, "time", clock)
    monkeypatch.setattr(probe, "authorization", lambda: ("own", 900.0))
    monkeypatch.setattr(
        probe,
        "native",
        Mock(return_value=subprocess.CompletedProcess([], 0, "authorized", "")),
    )
    with pytest.raises(PiccoloError, match="remained usable"):
        probe.wait_until_rejected(900.0, timeout=6)
    assert clock.now == 1006.0
    assert probe.entry["status"] == "reserved"


@pytest.mark.parametrize("observation", [("rotated", 1400.0), ("own", 900.0)])
def test_reconnect_requires_same_key_and_later_expiration(
    scenario: tuple[GCPProvider, Manifest, Document],
    monkeypatch: pytest.MonkeyPatch,
    observation: tuple[str, float],
) -> None:
    provider, manifest, _ = scenario
    probe = ssh_expiry.SSHExpiryProbe(provider, "oslogin", "ssh")
    monkeypatch.setattr(ssh_expiry, "time", Clock())
    probe.entry["status"] = "expired-and-rejected"
    manifest.put("ssh_keys", probe.entry)
    monkeypatch.setattr(
        probe.connection, "execute", lambda _zone, _command: "reconnected"
    )
    monkeypatch.setattr(probe, "authorization", lambda: observation)
    with pytest.raises(PiccoloError, match="renew the same"):
        probe.reconnect(("own", 900.0))
    assert manifest.entries("ssh_keys")[0]["status"] == "expired-and-rejected"
