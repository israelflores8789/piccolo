# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_lifecycle.py — Offline failure injection for provisioning and recovery."""

import pytest
from conftest import FakeCloud, GuestConnection

from piccolo.config import Config
from piccolo.data import Document, document, objects, text
from piccolo.errors import CapacityError, PiccoloError, UncertainError
from piccolo.providers.gcp.provider import GCPProvider
from piccolo.providers.gcp.provision import zone_of


def provision(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> GCPProvider:
    provider = GCPProvider(config, cloud, connection)
    provider.init()
    return provider


def test_repeated_init_and_daily_operations_preserve_disk(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    original = provider.disk(provider.active())
    calls = len(cloud.calls)
    provider.init()
    assert len(cloud.calls) == calls
    assert provider.disk(provider.active())["id"] == original["id"]
    provider.stop()
    provider.start()
    assert not connection.commands
    assert provider.disk(provider.active())["id"] == original["id"]


def test_capacity_fallback_only_after_terminal_failure(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    cloud.errors[("instance.insert", "us-west1-a")] = "ZONE_RESOURCE_POOL_EXHAUSTED"
    provider = provision(config, cloud, connection)
    assert zone_of(provider.active()) == "us-east1-b"
    assert len(cloud.list("instance")) == 1
    assert len(cloud.list("disk")) == 2


@pytest.mark.parametrize(
    "code",
    [
        "QUOTA_EXCEEDED",
        "PERMISSION_DENIED",
        "SERVICE_UNAVAILABLE",
        "INVALID_FIELD_VALUE",
    ],
)
def test_noncapacity_stops_without_fallback(
    config: Config, cloud: FakeCloud, connection: GuestConnection, code: str
) -> None:
    cloud.errors[("instance.insert", "us-west1-a")] = code
    provider = GCPProvider(config, cloud, connection)
    with pytest.raises(PiccoloError):
        provider.init()
    assert {call[2] for call in cloud.calls} == {"us-west1-a"}
    assert provider.journal.operation


def test_unknown_submission_never_retries_elsewhere(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    cloud.uncertain.add(("instance.insert", "us-west1-a"))
    provider = GCPProvider(config, cloud, connection)
    with pytest.raises(UncertainError):
        provider.init()
    count = len(cloud.calls)
    with pytest.raises(UncertainError):
        GCPProvider(config, cloud, connection).resume()
    assert len(cloud.calls) == count
    assert not cloud.list("instance")
    assert provider.cleanup(False)["protected"]


def test_crash_after_acceptance_resumes_without_duplicate(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    cloud.lost_response.add(("instance.insert", "us-west1-a"))
    provider = GCPProvider(config, cloud, connection)
    with pytest.raises(UncertainError):
        provider.init()
    count = len(cloud.calls)
    recovered = GCPProvider(config, cloud, connection)
    recovered.resume()
    assert len(cloud.calls) == count
    assert len(cloud.list("instance")) == 1
    assert not recovered.journal.operation
    assert all(
        item["status"] == "done"
        for item in objects(
            document(objects(recovered.journal.data, "history")[-1]), "actions"
        )
    )


def test_move_stops_before_snapshot_and_preserves_contents(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    source = provider.active()
    disk = provider.disk(source)
    cloud.resources[("disk", text(disk, "name"), zone_of(source))]["contents"] = (
        "research writable layer + repository + bootstrap receipt"
    )
    source_key = ("instance", "test-vm", zone_of(source))
    cloud.resources[source_key]["metadata"] = {
        "items": [{"key": "research", "value": "keep-me"}]
    }
    provider.move("us-east1-b")
    replacement = provider.active()
    assert zone_of(replacement) == "us-east1-b"
    assert (
        provider.disk(replacement)["contents"]
        == "research writable layer + repository + bootstrap receipt"
    )
    assert replacement["metadata"] == {
        "items": [{"key": "research", "value": "keep-me"}]
    }
    assert len(cloud.list("snapshot")) == 1
    assert len(cloud.list("disk")) == 2
    kinds = [item[0] for item in cloud.calls]
    assert (
        kinds.index("instance.stop")
        < kinds.index("snapshot.insert")
        < kinds.index("instance.delete")
    )
    assert not connection.commands


def test_readiness_failure_keeps_source_and_snapshot_then_resumes(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    connection.readiness_failure = True
    with pytest.raises(PiccoloError, match="SSH unavailable"):
        provider.move("us-east1-b")
    assert len(cloud.list("instance")) == 2
    assert cloud.get("instance", "test-vm", "us-west1-a")["status"] == "TERMINATED"
    assert len(cloud.list("snapshot")) == 1
    assert provider.cleanup(False)["eligible"] == []
    with pytest.raises(PiccoloError, match="replacement exists"):
        provider.rollback()
    connection.readiness_failure = False
    GCPProvider(config, cloud, connection).resume()
    assert len(cloud.list("instance")) == 1
    assert len(cloud.list("snapshot")) == 1


def test_failed_move_can_rollback_only_when_requests_settled(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    cloud.errors[("instance.insert", "us-east1-b")] = "ZONE_RESOURCE_POOL_EXHAUSTED"
    with pytest.raises(CapacityError):
        provider.move("us-east1-b")
    provider.rollback()
    assert zone_of(provider.active()) == "us-west1-a"
    assert provider.active()["status"] == "RUNNING"
    assert provider.cleanup(False)["eligible"]
    provider.cleanup(True)
    assert len(cloud.list("disk")) == 1
    assert not cloud.list("snapshot")


def test_uncertain_move_blocks_rollback(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    cloud.uncertain.add(("instance.insert", "us-east1-b"))
    with pytest.raises(UncertainError):
        provider.move("us-east1-b")
    with pytest.raises(PiccoloError, match="unresolved"):
        provider.rollback()
    assert cloud.get("instance", "test-vm", "us-west1-a")["status"] == "TERMINATED"


def test_unknown_existing_disk_is_never_bootstrap_eligible(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    provider.journal.path.unlink()
    provider = GCPProvider(config, cloud, connection)
    provider.init()
    assert "fresh_disk_id" not in provider.journal.data
    assert "bootstrap" not in provider.journal.data


def test_cleanup_does_not_delete_foreign_or_attached_disks(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    disk = provider.disk(provider.active())
    foreign = document(disk)
    foreign["name"] = "foreign"
    foreign["labels"] = {"managed-by": "piccolo", "piccolo-environment": "someone-else"}
    foreign["users"] = []
    cloud.resources[("disk", "foreign", "us-west1-a")] = foreign
    provider.cleanup(True)
    assert cloud.get("disk", "foreign", "us-west1-a")
    assert provider.disk(provider.active())["id"] == disk["id"]


def test_source_startup_metadata_blocks_move(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    cloud.resources[("instance", "test-vm", "us-west1-a")]["metadata"] = {
        "items": [{"key": "startup-script", "value": "destructive"}]
    }
    count = len(cloud.calls)
    with pytest.raises(PiccoloError, match="startup"):
        provider.move(None)
    assert len(cloud.calls) == count


def test_project_startup_metadata_blocks_fresh_creation(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    cloud.metadata = {"items": [{"key": "startup-script-url", "value": "gs://danger"}]}
    with pytest.raises(PiccoloError, match="startup"):
        GCPProvider(config, cloud, connection).init()
    assert not cloud.calls


def test_changed_config_blocks_resume(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    cloud.uncertain.add(("instance.insert", "us-west1-a"))
    provider = GCPProvider(config, cloud, connection)
    with pytest.raises(UncertainError):
        provider.init()
    config.path.write_text(
        config.path.read_text().replace(
            'machine_type = "n2-standard-4"', 'machine_type = "n2-standard-8"'
        )
    )
    from piccolo.config import load

    with pytest.raises(PiccoloError, match="Configuration changed"):
        GCPProvider(load(config.path), cloud, connection).resume()


def test_interrupted_rollback_resumes_source_restart(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    cloud.errors[("instance.insert", "us-east1-b")] = "ZONE_RESOURCE_POOL_EXHAUSTED"
    with pytest.raises(CapacityError):
        provider.move("us-east1-b")
    cloud.lost_response.add(("instance.start", "us-west1-a"))
    with pytest.raises(UncertainError):
        provider.rollback()
    recovered = GCPProvider(config, cloud, connection)
    count = len(cloud.calls)
    recovered.resume()
    assert len(cloud.calls) == count
    assert recovered.active()["status"] == "RUNNING"
    assert len(cloud.list("instance")) == 1


def test_failed_source_cleanup_can_resume_after_permission_repair(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    cloud.errors[("instance.delete", "us-west1-a")] = "PERMISSION_DENIED"
    with pytest.raises(PiccoloError):
        provider.move("us-east1-b")
    assert provider.journal.operation["committed"] is True
    assert len(cloud.list("snapshot")) == 1
    assert len(cloud.list("instance")) == 2
    cloud.errors.clear()
    recovered = GCPProvider(config, cloud, connection)
    recovered.resume()
    assert not recovered.journal.operation
    assert len(cloud.list("instance")) == 1
    assert len(cloud.list("snapshot")) == 1


def test_extra_disks_rejected_before_source_mutation(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    source = cloud.resources[("instance", "test-vm", "us-west1-a")]
    source["disks"] = [*objects(source, "disks"), {"boot": False, "source": "extra"}]
    count = len(cloud.calls)
    with pytest.raises(PiccoloError, match="exactly one"):
        provider.move("us-east1-b")
    assert len(cloud.calls) == count


def test_snapshot_poll_failure_preserves_stopped_source(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = provision(config, cloud, connection)
    original_poll = cloud.poll

    def interrupted_poll(name: str, zone: str) -> Document:
        if not zone:
            raise UncertainError("Snapshot inspection interrupted")
        return original_poll(name, zone)

    monkeypatch.setattr(cloud, "poll", interrupted_poll)
    with pytest.raises(UncertainError):
        provider.move("us-east1-b")
    assert cloud.get("instance", "test-vm", "us-west1-a")["status"] == "TERMINATED"
    assert len(cloud.list("snapshot")) == 1
    assert len(cloud.list("instance")) == 1
    monkeypatch.setattr(cloud, "poll", original_poll)
    GCPProvider(config, cloud, connection).resume()
    assert len(cloud.list("instance")) == 1


def test_source_id_reuse_blocks_retired_instance_deletion(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = provision(config, cloud, connection)
    connection.readiness_failure = True
    with pytest.raises(PiccoloError):
        provider.move("us-east1-b")
    cloud.resources[("instance", "test-vm", "us-west1-a")]["id"] = "different"
    connection.readiness_failure = False
    with pytest.raises(PiccoloError, match="identity changed"):
        GCPProvider(config, cloud, connection).resume()
    assert len(cloud.list("instance")) == 2
    assert len(cloud.list("snapshot")) == 1
