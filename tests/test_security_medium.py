# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_security_medium.py — Cloud-free regressions for M01 through M08."""

import base64
import json
import os
import subprocess
import sys
import time
import tomllib
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from conftest import FakeCloud, GuestConnection
from google.api_core import exceptions
from google.auth.credentials import AnonymousCredentials
from google.cloud import compute_v1, iam_admin_v1, resourcemanager_v3, service_usage_v1
from google.iam.v1 import policy_pb2

from piccolo.config import Config, load
from piccolo.data import Document, document, objects, text
from piccolo.errors import PiccoloError, UncertainError
from piccolo.providers.gcp import auth
from piccolo.providers.gcp.access import Access
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.connection import GCloudConnection
from piccolo.providers.gcp.provider import GCPProvider
from piccolo.providers.gcp.resources import SDKCloud
from piccolo.state.journal import Journal


@pytest.fixture
def bootstrap_config(config_path: Path) -> Config:
    (config_path.parent / "setup.sh").write_text("#!/bin/bash\nexit 0\n")
    config_path.write_text(
        config_path.read_text()
        + '[bootstrap]\nscript="setup.sh"\nexecution_user="researcher"\ntimeout=5\n'
    )
    return load(config_path)


@pytest.fixture
def access(config: Config, monkeypatch: pytest.MonkeyPatch) -> Access:
    clients = Clients(AnonymousCredentials())
    monkeypatch.setattr(
        clients.projects,
        "get_project",
        Mock(return_value=resourcemanager_v3.Project(name="projects/123")),
    )
    monkeypatch.setattr(
        clients.projects,
        "get_iam_policy",
        Mock(return_value=policy_pb2.Policy(version=3, etag=b"policy")),
    )
    monkeypatch.setattr(
        clients.networks,
        "get_effective_firewalls",
        Mock(return_value=compute_v1.NetworksGetEffectiveFirewallsResponse()),
    )
    monkeypatch.setattr(
        clients.services,
        "get_service",
        Mock(
            return_value=service_usage_v1.Service(state=service_usage_v1.State.ENABLED)
        ),
    )
    monkeypatch.setattr(
        clients.iam,
        "get_service_account",
        Mock(return_value=iam_admin_v1.ServiceAccount(unique_id="1234")),
    )
    journal = Journal(config)
    journal.begin({"kind": "access"})
    return Access(config, clients, journal)


def test_private_defaults_and_finite_ssh_lifetime(config: Config) -> None:
    assert config.gcp.external_ip is False
    assert config.gcp.expire_after == "24h"
    assert config.gcp.require_passphrase is False


def test_move_accepts_output_only_resource_status_without_copying_it(
    config: Config,
) -> None:
    """Allow Compute status observations while preserving strict request validation."""
    from piccolo.providers.gcp.provision import validate_source

    cloud = FakeCloud()
    provider = GCPProvider(config, cloud, GuestConnection(config.path.parent / "guest"))
    provider.init()
    instance = provider.active()
    disk = provider.disk(instance)
    vm_status: Document = {
        "effective_instance_metadata": {"enable_oslogin_metadata_value": True}
    }
    disk_status: Document = {"disk_consistency_status": "CONSISTENT"}
    cloud.resources[("instance", config.gcp.name, "us-west1-a")]["resource_status"] = (
        vm_status
    )
    disk_name = text(disk, "name")
    cloud.resources[("disk", disk_name, "us-west1-a")]["resource_status"] = disk_status
    validate_source(config, provider.active(), provider.disk(provider.active()))
    provider.move("us-east1-b")
    assert "resource_status" not in provider.active()
    assert "resource_status" not in provider.disk(provider.active())


@pytest.mark.parametrize("learned", [False, True])
def test_move_omits_source_integrity_baseline_update_action(
    config: Config, monkeypatch: pytest.MonkeyPatch, learned: bool
) -> None:
    """Preserve Shielded VM settings while a new VM establishes its own baseline."""
    cloud = FakeCloud()
    provider = GCPProvider(config, cloud, GuestConnection(config.path.parent / "guest"))
    provider.init()
    cloud.resources[("instance", config.gcp.name, "us-west1-a")][
        "shielded_instance_integrity_policy"
    ] = {"update_auto_learn_policy": learned}
    source = provider.active()
    submitted: list[Document] = []
    original = cloud.submit

    def submit(
        kind: str, name: str, zone: str, resource: Document, request_id: str
    ) -> str:
        if kind == "instance.insert" and zone == "us-east1-b":
            submitted.append(document(resource))
        return original(kind, name, zone, resource, request_id)

    monkeypatch.setattr(cloud, "submit", submit)
    provider.move("us-east1-b")
    assert len(submitted) == 1
    assert "shielded_instance_integrity_policy" not in submitted[0]
    assert (
        provider.active()["shielded_instance_config"]
        == source["shielded_instance_config"]
    )


def test_unknown_integrity_policy_settings_block_move_before_stop(
    config: Config,
) -> None:
    """Retain strict handling of future nondefault integrity policy configuration."""
    cloud = FakeCloud()
    provider = GCPProvider(config, cloud, GuestConnection(config.path.parent / "guest"))
    provider.init()
    cloud.resources[("instance", config.gcp.name, "us-west1-a")][
        "shielded_instance_integrity_policy"
    ] = {"future_policy": True}
    cloud.calls.clear()
    with pytest.raises(PiccoloError, match="shielded integrity policy"):
        provider.move("us-east1-b")
    assert not cloud.calls


@pytest.mark.parametrize("source", ["0.0.0.0/0", "10.0.0.0/8", "::/0"])
def test_iap_source_ranges_cannot_widen(config_path: Path, source: str) -> None:
    config_path.write_text(
        config_path.read_text() + f'[gcp.iap]\nsource_ranges=["{source}"]\n'
    )
    with pytest.raises(PiccoloError, match="IAP source ranges"):
        load(config_path)


@pytest.mark.parametrize(
    "snippet",
    [
        "via_iap=false\n",
        "internal_ip=true\n",
        'expire-after="0h"\n',
        'expire-after="never"\n',
    ],
)
def test_invalid_transport_policy(config_path: Path, snippet: str) -> None:
    config_path.write_text(config_path.read_text() + snippet)
    with pytest.raises(PiccoloError, match=r"gcp\.ssh"):
        load(config_path)


def test_internal_transport_is_explicit(config_path: Path) -> None:
    config_path.write_text(
        config_path.read_text() + "via_iap=false\ninternal_ip=true\n"
        'expire-after="12h"\nrequire_passphrase=true\n'
    )
    gcp = load(config_path).gcp
    assert gcp.internal_ip and gcp.require_passphrase
    assert gcp.expire_after == "12h"


@pytest.mark.parametrize("hierarchical", [False, True])
def test_effective_firewalls_reject_non_iap_ingress(
    access: Access, monkeypatch: pytest.MonkeyPatch, hierarchical: bool
) -> None:
    broad: Document = {
        "direction": "INGRESS",
        "source_ranges": ["0.0.0.0/0"],
        "allowed": [{"I_p_protocol": "tcp", "ports": ["1-65535"]}],
    }
    payload: Document = {"firewalls": [broad]}
    if hierarchical:
        payload = {
            "firewall_policys": [
                {
                    "rules": [
                        {
                            "direction": "INGRESS",
                            "action": "allow",
                            "match": {
                                "src_ip_ranges": ["0.0.0.0/0"],
                                "layer4_configs": [
                                    {"ip_protocol": "6", "ports": ["22"]}
                                ],
                            },
                        }
                    ]
                }
            ]
        }
    response = compute_v1.NetworksGetEffectiveFirewallsResponse.from_json(
        json.dumps(payload)
    )
    monkeypatch.setattr(
        access.clients.networks, "get_effective_firewalls", Mock(return_value=response)
    )
    assert access.network_policy()["unsafe_ingress"]
    with pytest.raises(PiccoloError, match="non-IAP ingress"):
        access.ensure()
    assert not objects(access.journal.operation, "access_actions")


@pytest.mark.parametrize(
    "role",
    [
        "roles/owner",
        "roles/editor",
        "roles/storage.admin",
        "roles/compute.instanceAdmin.v1",
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountOpenIdTokenCreator",
    ],
)
def test_guest_privileged_roles_are_rejected(config_path: Path, role: str) -> None:
    config_path.write_text(
        config_path.read_text() + f'[gcp.iam]\nproject_roles=["{role}"]\n'
    )
    with pytest.raises(PiccoloError, match="privileged role"):
        load(config_path)


def test_inherited_guest_privilege_is_reported(
    access: Access, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = policy_pb2.Policy(version=3, etag=b"org")
    policy.bindings.add(
        role="roles/editor", members=[f"serviceAccount:{access.gcp.service_account}"]
    )
    monkeypatch.setattr(
        access.clients.organizations, "get_iam_policy", Mock(return_value=policy)
    )
    result = access.guest_iam("organizations/123")
    assert result["privileged_roles"][0]["resource"] == "organizations/123"


def test_conditional_guest_access_is_never_broadened(
    access: Access, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = policy_pb2.Policy(version=3, etag=b"condition")
    policy.bindings.add(
        role="roles/bigquery.dataViewer",
        members=[f"serviceAccount:{access.gcp.service_account}"],
        condition={"expression": "true"},
    )
    monkeypatch.setattr(
        access.clients.projects, "get_iam_policy", Mock(return_value=policy)
    )
    setter = Mock()
    monkeypatch.setattr(access.clients.projects, "set_iam_policy", setter)
    with pytest.raises(PiccoloError, match="Conditional-only"):
        access.grant("projects/test-project", "roles/bigquery.dataViewer", secret=False)
    setter.assert_not_called()


def test_missing_etag_blocks_iam_write(
    access: Access, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        access.clients.projects,
        "get_iam_policy",
        Mock(return_value=policy_pb2.Policy(version=3)),
    )
    setter = Mock()
    monkeypatch.setattr(access.clients.projects, "set_iam_policy", setter)
    with pytest.raises(PiccoloError, match="no etag"):
        access.grant("projects/test-project", "roles/bigquery.dataViewer", secret=False)
    setter.assert_not_called()


def test_action_permission_error_names_acting_service_account(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients = Clients(AnonymousCredentials())
    monkeypatch.setattr(
        type(clients),
        "principal",
        property(lambda _: "provisioner@test-project.iam.gserviceaccount.com"),
    )
    monkeypatch.setattr(
        clients.instances, "delete", Mock(side_effect=exceptions.Forbidden("denied"))
    )
    with pytest.raises(PiccoloError) as caught:
        SDKCloud(config, clients).submit(
            "instance.delete", "test-vm", "us-west1-a", {}, "uuid"
        )
    message = str(caught.value)
    assert "GCP:roles/compute.instanceAdmin.v1" in message
    assert "provisioner@test-project.iam.gserviceaccount.com" in message
    assert config.gcp.service_account not in message


def test_iam_grant_is_limited_to_configured_guest_and_journaled(
    access: Access, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = policy_pb2.Policy(version=3, etag=b"etag")
    stored: list[policy_pb2.Policy] = [policy]
    monkeypatch.setattr(
        access.clients.projects, "get_iam_policy", lambda **_kwargs: stored[0]
    )

    def setter(**kwargs: object) -> policy_pb2.Policy:
        request = kwargs["request"]
        assert isinstance(
            request,
            __import__(
                "google.iam.v1.iam_policy_pb2", fromlist=["SetIamPolicyRequest"]
            ).SetIamPolicyRequest,
        )
        durable = Journal(access.config)
        assert objects(durable.operation, "access_actions")[0]["status"] == "intent"
        stored[0] = request.policy
        return request.policy

    monkeypatch.setattr(access.clients.projects, "set_iam_policy", setter)
    access.grant("projects/test-project", "roles/bigquery.dataViewer", secret=False)
    assert list(stored[0].bindings[0].members) == [
        f"serviceAccount:{access.gcp.service_account}"
    ]
    action = objects(Journal(access.config).operation, "access_actions")[0]
    assert action["status"] == "done" and action["preexisting"] is False


def test_firewall_lost_response_never_blindly_resubmits(
    access: Access, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        access.clients.firewalls, "get", Mock(side_effect=exceptions.NotFound("absent"))
    )
    insert = Mock(side_effect=exceptions.ServiceUnavailable("lost"))
    monkeypatch.setattr(access.clients.firewalls, "insert", insert)
    monkeypatch.setattr(SDKCloud, "recover", lambda *_args: "")
    with pytest.raises(UncertainError):
        access.firewall()
    action = objects(Journal(access.config).operation, "access_actions")[0]
    assert action["request_id"] == insert.call_args.kwargs["request"].request_id
    with pytest.raises(UncertainError, match="unknown"):
        Access(access.config, access.clients, Journal(access.config)).firewall()
    insert.assert_called_once()


def test_compute_target_id_cannot_be_replaced(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poll = cloud.poll

    def substituted(name: str, zone: str) -> Document:
        result = poll(name, zone)
        for (kind, _, resource_zone), resource in cloud.resources.items():
            if kind == "disk" and resource_zone == zone:
                resource["id"] = "999999"
        return result

    monkeypatch.setattr(cloud, "poll", substituted)
    provider = GCPProvider(config, cloud, connection)
    with pytest.raises(PiccoloError, match="target ID"):
        provider.init()
    assert "fresh_disk_id" not in provider.journal.data
    assert not any(call[0] == "instance.insert" for call in cloud.calls)


def test_snapshot_replacement_is_retained(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = GCPProvider(config, cloud, connection)
    provider.init()

    def replace_snapshot(_zone: str) -> None:
        for (kind, _, _), resource in cloud.resources.items():
            if kind == "snapshot":
                resource["id"] = "substituted"

    monkeypatch.setattr(connection, "ready", replace_snapshot)
    with pytest.raises(PiccoloError, match="snapshot identity changed"):
        provider.move("us-east1-b")
    assert not any(call[0] == "snapshot.delete" for call in cloud.calls)


@pytest.mark.parametrize(
    "unknown", ["new_security_setting", "network_performance_config"]
)
def test_unknown_source_settings_fail_before_stop(
    config: Config, cloud: FakeCloud, connection: GuestConnection, unknown: str
) -> None:
    provider = GCPProvider(config, cloud, connection)
    provider.init()
    cloud.resources[("instance", "test-vm", "us-west1-a")][unknown] = {"enabled": True}
    before = len(cloud.calls)
    with pytest.raises(PiccoloError, match="Unsupported source"):
        provider.move("us-east1-b")
    assert len(cloud.calls) == before


@pytest.mark.parametrize(
    "component", [".piccolo", ".piccolo/bootstrap", ".piccolo/bootstrap/setup.sh"]
)
def test_staging_rejects_guest_symlinks(
    bootstrap_config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    tmp_path: Path,
    component: str,
) -> None:
    external = tmp_path / "outside"
    external.mkdir()
    target = connection.directory / component
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(external, target_is_directory=True)
    with pytest.raises(PiccoloError):
        GCPProvider(bootstrap_config, cloud, connection).init()
    assert connection.copies == 0
    assert not list(external.iterdir())


def test_script_and_runner_are_private_before_copy(
    bootstrap_config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copy = connection.copy
    modes: list[int] = []

    def private_copy(zone: str, source: Path, destination: str) -> None:
        target = connection.directory / destination
        modes.append(target.stat().st_mode & 0o777)
        assert target.parent.stat().st_mode & 0o777 == 0o700
        assert source.stat().st_mode & 0o777 == 0o600
        copy(zone, source, destination)

    monkeypatch.setattr(connection, "copy", private_copy)
    provider = GCPProvider(bootstrap_config, cloud, connection)
    provider.init()
    assert provider.bootstrap(False, False)["status"] == "completed"
    assert modes == [0o600, 0o600]


def test_runner_digest_tampering_blocks_launch(
    bootstrap_config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = GCPProvider(bootstrap_config, cloud, connection)
    provider.init()
    copy = connection.copy

    def tamper(zone: str, source: Path, destination: str) -> None:
        copy(zone, source, destination)
        if destination.endswith(".runner.sh"):
            (connection.directory / destination).write_text("exit 0\n")

    monkeypatch.setattr(connection, "copy", tamper)
    with pytest.raises(PiccoloError, match="digest mismatch"):
        provider.bootstrap(False, False)
    assert text(document(provider.journal.data["bootstrap"]), "status") == "staged"


def test_runtime_and_build_metadata_pin_dependency_versions() -> None:
    metadata = tomllib.loads(Path("pyproject.toml").read_text())
    requirements = [
        *metadata["project"]["dependencies"],
        *metadata["project"]["optional-dependencies"]["gcp"],
        *metadata["dependency-groups"]["dev"],
        *metadata["build-system"]["requires"],
    ]
    assert all("==" in requirement for requirement in requirements)
    assert "pytest==9.1.1" in requirements


def test_host_enrollment_uses_authenticated_instance_keys(
    config: Config,
) -> None:
    algorithm = b"ssh-ed25519"
    encoded = base64.b64encode(
        len(algorithm).to_bytes(4, "big") + algorithm + b"testkey"
    ).decode()
    calls: list[str] = []

    def response(zone: str) -> Document:
        calls.append(zone)
        return {
            "query_value": {
                "items": [
                    {"namespace": "hostkeys", "key": "ssh-ed25519", "value": encoded}
                ]
            }
        }

    connection = GCloudConnection(config.gcp, lambda _zone: {"id": "123"}, response)
    options = connection.host_options("us-west1-a", "scp-flag")
    assert "--strict-host-key-checking=yes" in options
    assert "--ssh-key-expire-after=24h" in options
    assert "--scp-flag=-oHostKeyAlias=compute.123" in options
    assert calls == ["us-west1-a"]
    path = connection.host_files["us-west1-a"][1]
    assert encoded in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("changed", [False, True])
def test_host_enrollment_refuses_unknown_or_replaced_vm(
    config: Config, monkeypatch: pytest.MonkeyPatch, changed: bool
) -> None:
    identity = Mock(side_effect=[{"id": "123"}, {"id": "456"}])
    connection = GCloudConnection(config.gcp, identity)
    algorithm = b"ssh-ed25519"
    key = base64.b64encode(
        len(algorithm).to_bytes(4, "big") + algorithm + b"testkey"
    ).decode()
    entries = (
        [{"namespace": "hostkeys", "key": "ssh-ed25519", "value": key}]
        if changed
        else []
    )
    monkeypatch.setattr(
        connection, "host_keys", lambda _zone: {"query_value": {"items": entries}}
    )
    with pytest.raises(
        PiccoloError, match=r"Instance changed|No trusted GCP host keys"
    ):
        connection.host_options("us-west1-a", "ssh-flag")


def test_passphrase_mode_forwards_prompts_and_preserves_output(
    config: Config, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    connection = GCloudConnection(replace(config.gcp, require_passphrase=True))
    monkeypatch.setattr(connection, "launcher", lambda: ["ignored"])
    real_popen = subprocess.Popen

    def local_process(args: list[str], **kwargs: object) -> subprocess.Popen[str]:
        command = next(
            argument.removeprefix("--command=")
            for argument in args
            if argument.startswith("--command=")
        )
        assert "--quiet" not in args
        assert "stdin" not in kwargs and "stderr" not in kwargs
        return real_popen(
            ["bash", "-c", "printf 'gcloud prompt\\n'; " + command], **kwargs
        )

    monkeypatch.setattr(subprocess, "Popen", local_process)
    result = connection.interactive_invoke(
        ["compute", "ssh", "test-vm", "--command=printf 123"],
        dict(os.environ),
        timeout=10,
    )
    assert result.returncode == 0 and result.stdout == "123"
    assert "gcloud prompt" in capsys.readouterr().out


def test_scp_uses_isolated_host_trust_and_normal_gcloud_key_path(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    algorithm = b"ssh-ed25519"
    value = base64.b64encode(
        len(algorithm).to_bytes(4, "big") + algorithm + b"testkey"
    ).decode()
    connection = GCloudConnection(
        config.gcp,
        lambda _zone: {"id": "123"},
        lambda _zone: {
            "query_value": {
                "items": [
                    {"namespace": "hostkeys", "key": "ssh-ed25519", "value": value}
                ]
            }
        },
    )
    monkeypatch.setattr(
        connection,
        "environment",
        lambda: {"HOME": "/original", "CLOUDSDK_CONFIG": "/original/gcloud"},
    )
    monkeypatch.setattr(connection, "launcher", lambda: ["gcloud"])
    connection.identity_checked = True
    invoke = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(subprocess, "run", invoke)
    source = tmp_path / "script"
    source.write_text("exit 0")
    connection.copy("us-west1-a", source, ".piccolo/setup.upload")
    args = invoke.call_args.args[0]
    assert "--strict-host-key-checking=yes" in args
    assert "--ssh-key-expire-after=24h" in args
    assert (
        f"--ssh-key-file={connection.user_home / '.ssh' / 'google_compute_engine'}"
        in args
    )
    assert "--scp-flag=-oBatchMode=yes" in args
    assert "--scp-flag=-F/dev/null" in args
    environment = invoke.call_args.kwargs["env"]
    assert environment["HOME"] == connection.host_directory.name
    assert environment["CLOUDSDK_CONFIG"] == "/original/gcloud"
    assert (
        connection.known_hosts
        == Path(environment["HOME"]) / ".ssh" / "google_compute_known_hosts"
    )


def test_host_publication_is_polled_without_accepting_unknown_keys(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    algorithm = b"ssh-ed25519"
    key = base64.b64encode(
        len(algorithm).to_bytes(4, "big") + algorithm + b"key"
    ).decode()
    host_keys = Mock(
        side_effect=[
            {},
            {
                "query_value": {
                    "items": [
                        {"namespace": "hostkeys", "key": "ssh-ed25519", "value": key}
                    ]
                }
            },
        ]
    )
    connection = GCloudConnection(config.gcp, lambda _zone: {"id": "123"}, host_keys)
    monkeypatch.setattr(connection, "check_identity", lambda: None)
    run = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(connection, "run", run)
    monkeypatch.setattr(
        "piccolo.providers.gcp.connection.time.sleep", lambda _seconds: None
    )
    connection.ready("us-west1-a")
    assert host_keys.call_count == 2
    run.assert_called_once()
    assert "--strict-host-key-checking=yes" in run.call_args.args[0]


def test_compute_host_key_read_uses_api_and_distinguishes_permission_denial(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients = Clients(AnonymousCredentials())
    attributes = compute_v1.GuestAttributes(
        query_value=compute_v1.GuestAttributesValue(
            items=[
                compute_v1.GuestAttributesEntry(
                    namespace="hostkeys", key="ssh-ed25519", value="opaque"
                )
            ]
        )
    )
    read = Mock(return_value=attributes)
    monkeypatch.setattr(clients.instances, "get_guest_attributes", read)
    cloud = SDKCloud(config, clients)
    assert (
        objects(document(cloud.host_keys("us-west1-a")["query_value"]), "items")[0][
            "value"
        ]
        == "opaque"
    )
    assert read.call_args.kwargs["request"].query_path == "hostkeys/"
    read.side_effect = exceptions.NotFound("not published")
    assert cloud.host_keys("us-west1-a") == {}
    read.side_effect = exceptions.Forbidden("denied")
    with pytest.raises(PiccoloError, match=r"GCP:roles/compute\.viewer"):
        cloud.host_keys("us-west1-a")


def test_staging_refuses_disk_replacement_during_readiness(
    bootstrap_config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def replace_disk(_zone: str) -> None:
        for (kind, _, _), resource in cloud.resources.items():
            if kind == "disk":
                resource["id"] = "replaced"

    monkeypatch.setattr(connection, "ready", replace_disk)
    provider = GCPProvider(bootstrap_config, cloud, connection)
    with pytest.raises(PiccoloError, match="boot disk differs"):
        provider.init()
    assert connection.copies == 0
    assert text(document(provider.journal.data["bootstrap"]), "status") == "staging"


def test_source_tag_bindings_block_move_policy(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients = Clients(AnonymousCredentials())
    monkeypatch.setattr(
        clients.projects,
        "get_project",
        Mock(return_value=resourcemanager_v3.Project(name="projects/123")),
    )
    tags = Mock()
    tags.list_tag_bindings.return_value = [
        resourcemanager_v3.TagBinding(name="binding")
    ]
    constructor = Mock(return_value=tags)
    monkeypatch.setattr(resourcemanager_v3, "TagBindingsClient", constructor)
    with pytest.raises(PiccoloError, match="source tag bindings"):
        SDKCloud(config, clients).move_policy(
            {"id": "456", "zone": "us-west1-a"}, {"id": "789"}
        )
    assert (
        tags.list_tag_bindings.call_args.kwargs["parent"]
        == "//compute.googleapis.com/projects/123/zones/us-west1-a/instances/456"
    )
    assert (
        constructor.call_args.kwargs["client_options"]["api_endpoint"]
        == "us-west1-a-cloudresourcemanager.googleapis.com"
    )
    tags.transport.close.assert_called_once()


def test_firewall_operation_is_durable_before_wait(
    access: Access, monkeypatch: pytest.MonkeyPatch
) -> None:
    firewall = access.firewall_spec()
    firewall.id = 123
    reads = Mock(side_effect=[exceptions.NotFound("absent"), firewall])
    monkeypatch.setattr(access.clients.firewalls, "get", reads)
    operation = Mock()
    operation.name = "firewall-operation"

    def wait(*, timeout: int) -> None:
        assert timeout == access.gcp.operation_timeout
        action = objects(Journal(access.config).operation, "access_actions")[0]
        assert (
            action["operation_id"] == "firewall-operation"
            and action["status"] == "submitted"
        )

    operation.result.side_effect = wait
    monkeypatch.setattr(
        access.clients.firewalls, "insert", Mock(return_value=operation)
    )
    access.firewall()
    action = objects(Journal(access.config).operation, "access_actions")[0]
    assert action["resource_id"] == "123" and action["status"] == "done"


def test_api_enablement_records_intent_before_call_and_operation_before_wait(
    access: Access, monkeypatch: pytest.MonkeyPatch
) -> None:
    getter = Mock(
        side_effect=[
            service_usage_v1.Service(state=service_usage_v1.State.DISABLED),
            service_usage_v1.Service(state=service_usage_v1.State.ENABLED),
        ]
    )
    monkeypatch.setattr(access.clients.services, "get_service", getter)
    operation = Mock()
    operation.operation.name = "operations/enable"

    def wait(*, timeout: int) -> None:
        assert timeout == access.gcp.operation_timeout
        action = objects(Journal(access.config).operation, "access_actions")[0]
        assert (
            action["status"] == "submitted"
            and action["operation_id"] == "operations/enable"
        )

    operation.result.side_effect = wait

    def enable(**_kwargs: object) -> Mock:
        assert (
            objects(Journal(access.config).operation, "access_actions")[0]["status"]
            == "intent"
        )
        return operation

    monkeypatch.setattr(access.clients.services, "enable_service", enable)
    access.api("projects/123/services/compute.googleapis.com")
    assert (
        objects(Journal(access.config).operation, "access_actions")[0]["status"]
        == "done"
    )


def test_api_unknown_outcome_never_reenables(
    access: Access, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        access.clients.services,
        "get_service",
        Mock(
            return_value=service_usage_v1.Service(state=service_usage_v1.State.DISABLED)
        ),
    )
    enable = Mock(side_effect=exceptions.ServiceUnavailable("lost"))
    monkeypatch.setattr(access.clients.services, "enable_service", enable)
    with pytest.raises(UncertainError):
        access.api("projects/123/services/compute.googleapis.com")
    with pytest.raises(UncertainError):
        Access(access.config, access.clients, Journal(access.config)).api(
            "projects/123/services/compute.googleapis.com"
        )
    enable.assert_called_once()


def test_source_and_replacement_disk_ids_are_independent(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = cloud.mutate

    def forged_attachment(kind: str, name: str, zone: str, resource: Document) -> None:
        original(kind, name, zone, resource)
        if kind == "instance.insert":
            instance = cloud.resources[("instance", name, zone)]
            disk_name = text(objects(instance, "disks")[0], "source").split("/")[-1]
            cloud.resources[("disk", disk_name, zone)]["id"] = "forged-disk"

    monkeypatch.setattr(cloud, "mutate", forged_attachment)
    provider = GCPProvider(config, cloud, connection)
    with pytest.raises(PiccoloError, match=r"disk changed|identity"):
        provider.init()
    assert "fresh_disk_id" not in provider.journal.data


def test_creation_settings_are_verified_independently_of_labels(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mutate = cloud.mutate

    def changed(kind: str, name: str, zone: str, resource: Document) -> None:
        mutate(kind, name, zone, resource)
        if kind == "disk.insert":
            cloud.resources[("disk", name, zone)]["size_gb"] = 1

    monkeypatch.setattr(cloud, "mutate", changed)
    provider = GCPProvider(config, cloud, connection)
    with pytest.raises(PiccoloError, match="settings differ"):
        provider.init()
    assert "fresh_disk_id" not in provider.journal.data


def test_interrupted_firewall_wait_keeps_returned_operation(
    access: Access, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        access.clients.firewalls, "get", Mock(side_effect=exceptions.NotFound("absent"))
    )
    operation = Mock()
    operation.name = "accepted-operation"
    operation.result.side_effect = KeyboardInterrupt()
    monkeypatch.setattr(
        access.clients.firewalls, "insert", Mock(return_value=operation)
    )
    with pytest.raises(KeyboardInterrupt):
        access.firewall()
    action = objects(Journal(access.config).operation, "access_actions")[0]
    assert action["operation_id"] == "accepted-operation"
    assert action["status"] == "submitted"


@pytest.mark.parametrize(
    "path",
    [
        ".piccolo/bootstrap/attempt-123",
        ".piccolo/bootstrap/attempt-123/script",
        ".piccolo/bootstrap/file.runner.sh",
        ".piccolo/bootstrap/file.upload-test",
        "directory/../script",
        "directory//script",
        "directory/./script",
    ],
)
def test_reserved_remote_paths_are_rejected(config_path: Path, path: str) -> None:
    (config_path.parent / "script.sh").write_text("exit 0")
    config_path.write_text(
        config_path.read_text()
        + f'[bootstrap]\nscript="script.sh"\nremote_path="{path}"\n'
        'execution_user="researcher"\n'
    )
    with pytest.raises(PiccoloError, match=r"bootstrap\.remote_path"):
        load(config_path)


def test_ssh_user_mismatch_stops_readiness_immediately(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = GCloudConnection(config.gcp)
    monkeypatch.setattr(connection, "check_identity", lambda: None)
    monkeypatch.setattr(
        connection,
        "host_options",
        lambda _zone, _flag: ["--strict-host-key-checking=yes"],
    )
    run = Mock(
        return_value=subprocess.CompletedProcess(
            [], 65, "", "Piccolo SSH user mismatch"
        )
    )
    monkeypatch.setattr(connection, "run", run)
    with pytest.raises(PiccoloError, match="SSH user mismatch"):
        connection.ready("us-west1-a")
    run.assert_called_once()
    remote = next(
        item for item in run.call_args.args[0] if item.startswith("--command=")
    )
    assert '"$(id -un)" != researcher' in remote


@pytest.mark.parametrize("impersonate", [False, True])
def test_guest_account_cannot_be_sdk_provisioner(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, impersonate: bool
) -> None:
    class GuestCredentials(AnonymousCredentials):
        @property
        def service_account_email(self) -> str:
            return config.gcp.service_account

    path = tmp_path / "credential.json"
    path.write_text("{}")
    gcp = replace(
        config.gcp,
        auth=replace(
            config.gcp.auth,
            mode="file",
            credential_file=path,
            impersonate_service_account=config.gcp.service_account
            if impersonate
            else "",
        ),
    )
    source = AnonymousCredentials() if impersonate else GuestCredentials()
    monkeypatch.setattr(auth, "file_credentials", lambda _path: source)
    with pytest.raises(PiccoloError, match="provisioner identity must differ"):
        auth.credentials(gcp)


def test_metadata_provisioner_identity_is_rechecked_before_access_mutations(
    access: Access, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        type(access.clients),
        "principal",
        property(lambda _: access.gcp.service_account),
    )
    with pytest.raises(PiccoloError, match="Provisioner and guest"):
        access.ensure()
    assert not objects(access.journal.operation, "access_actions")


@pytest.mark.parametrize(
    "permission",
    [
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.getOpenIdToken",
        "iam.serviceAccounts.delete",
        "compute.instances.setMetadata",
        "resourcemanager.projects.delete",
        "storage.buckets.setIamPolicy",
    ],
)
def test_custom_guest_roles_cannot_delegate_credentials(
    access: Access, monkeypatch: pytest.MonkeyPatch, permission: str
) -> None:
    getter = Mock(return_value=iam_admin_v1.Role(included_permissions=[permission]))
    monkeypatch.setattr(access.clients.iam, "get_role", getter)
    role = "projects/test-project/roles/development"
    assert access.unsafe_custom_role(role)
    assert getter.call_args.kwargs["request"].name == role


def test_interactive_timeout_returns_with_descendant_stdout_open(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = GCloudConnection(replace(config.gcp, require_passphrase=True))
    monkeypatch.setattr(connection, "launcher", lambda: ["ignored"])
    real_popen = subprocess.Popen

    def local_process(_args: list[str], **kwargs: object) -> subprocess.Popen[str]:
        code = (
            "import subprocess,sys,time; subprocess.Popen([sys.executable, "
            "'-c', 'import time; time.sleep(0.5)']); time.sleep(10)"
        )
        return real_popen([sys.executable, "-c", code], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", local_process)
    before = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        connection.interactive_invoke(
            ["compute", "ssh", "--command=true"], dict(os.environ), timeout=0.1
        )
    assert time.monotonic() - before < 0.4
