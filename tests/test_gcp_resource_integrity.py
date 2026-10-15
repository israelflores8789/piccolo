# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_resource_integrity.py — Resource identity and relocation policy."""

from unittest.mock import Mock

import pytest
from conftest import FakeCloud, GuestConnection
from google.auth.credentials import AnonymousCredentials
from google.cloud import resourcemanager_v3

from piccolo.config import Config
from piccolo.data import Document, document, objects, text
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.provider import GCPProvider
from piccolo.providers.gcp.resources import SDKCloud


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
