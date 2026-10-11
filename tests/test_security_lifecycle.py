# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_security_lifecycle.py — H03 through H06 regressions using local adapters."""

from dataclasses import replace
from pathlib import Path

import pytest
from conftest import FakeCloud, GuestConnection

from piccolo.config import Config
from piccolo.config.models import Bootstrap
from piccolo.data import Document, document, objects, text
from piccolo.errors import PiccoloError, UncertainError
from piccolo.providers.gcp.provider import GCPProvider
from piccolo.providers.gcp.provision import zone_of


@pytest.mark.parametrize(
    "workflow,interruption",
    [
        ("init", "submission"),
        ("init", "poll"),
        ("init", "staging"),
        ("move", "submission"),
        ("move", "poll"),
        ("move", "readiness"),
        ("move", "commit"),
    ],
)
def test_later_fallback_resumes_without_duplicate_creation(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    workflow: str,
    interruption: str,
) -> None:
    if interruption == "staging":
        script = tmp_path / "setup.sh"
        script.write_text("printf harmless\\n")
        config = replace(
            config, bootstrap=Bootstrap(script, ".piccolo/setup.sh", "researcher", 30)
        )
    provider = GCPProvider(config, cloud, connection)
    if workflow == "move":
        provider.init()
    failed_zone, accepted_zone = (
        ("us-west1-a", "us-east1-b")
        if workflow == "init"
        else ("us-east1-b", "us-east1-c")
    )
    cloud.errors[("instance.insert", failed_zone)] = "ZONE_RESOURCE_POOL_EXHAUSTED"
    with monkeypatch.context() as injection:
        if interruption == "submission":
            cloud.lost_response.add(("instance.insert", accepted_zone))
        elif interruption == "poll":
            original_poll = cloud.poll

            def interrupted_poll(name: str, zone: str) -> Document:
                if zone == accepted_zone and cloud.get("instance", "test-vm", zone):
                    raise UncertainError("Injected later-candidate poll failure")
                return original_poll(name, zone)

            injection.setattr(cloud, "poll", interrupted_poll)
        elif interruption in {"staging", "readiness"}:
            injection.setattr(connection, "readiness_failure", True)
        else:

            def interrupted_commit() -> None:
                raise UncertainError("Injected interruption after durable commit")

            injection.setattr(provider, "commit_cleanup", interrupted_commit)
        with pytest.raises(PiccoloError):
            if workflow == "init":
                provider.init()
            else:
                provider.move(None)
    replacement = cloud.get("instance", "test-vm", accepted_zone)
    assert replacement is not None
    replacement_id = text(replacement, "id")
    creates = [call for call in cloud.calls if call[0].endswith(".insert")]
    recovered = GCPProvider(config, cloud, connection)
    recovered.resume()
    assert [call for call in cloud.calls if call[0].endswith(".insert")] == creates
    assert zone_of(recovered.active()) == accepted_zone
    assert text(recovered.active(), "id") == replacement_id
    assert len(cloud.list("instance")) == 1
    assert not recovered.journal.operation
    if interruption == "staging":
        assert document(recovered.journal.data["bootstrap"])["status"] == "staged"


@pytest.mark.parametrize("state_loss", ["new-root", "deleted-state"])
def test_unknown_move_artifacts_survive_cleanup(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state_loss: str,
) -> None:
    provider = GCPProvider(config, cloud, connection)
    provider.init()
    connection.readiness_failure = True
    with pytest.raises(PiccoloError):
        provider.move("us-east1-b")
    original_operation = provider.journal.operation
    snapshot = cloud.list("snapshot")[0]
    if state_loss == "new-root":
        monkeypatch.setenv("PICCOLO_STATE_DIR", str(tmp_path / "new-state"))
    else:
        provider.journal.path.unlink()
    other = GCPProvider(config, cloud, connection)
    preview = other.cleanup(False)
    assert preview["eligible"] == []
    assert text(snapshot, "id") in {
        text(entry, "id") for entry in objects(preview, "protected")
    }
    before = list(cloud.calls)
    other.cleanup(True)
    assert cloud.calls == before
    assert cloud.list("snapshot")[0]["id"] == snapshot["id"]
    assert provider.journal.operation == original_operation


@pytest.mark.parametrize(
    "missing",
    ["manifest", "history", "active-id", "operation-result", "topology", "resource-id"],
)
def test_cleanup_requires_positive_resolved_evidence(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    missing: str,
) -> None:
    cloud.errors[("instance.insert", "us-west1-a")] = "ZONE_RESOURCE_POOL_EXHAUSTED"
    provider = GCPProvider(config, cloud, connection)
    provider.init()
    assert provider.cleanup(False)["eligible"]
    history = objects(provider.journal.data, "history")
    if missing == "manifest":
        history[0].pop("artifacts")
    elif missing == "history":
        history = []
    elif missing == "active-id":
        provider.journal.data.pop("active_instance_id")
    elif missing == "operation-result":
        cloud.operations[next(iter(cloud.operations))] = {"status": "RUNNING"}
    elif missing == "topology":
        extra = document(provider.active())
        extra["zone"], extra["id"] = "us-east1-c", "other"
        cloud.resources[("instance", "test-vm", "us-east1-c")] = extra
    else:
        entry = objects(provider.cleanup(False), "eligible")[0]
        cloud.resources[("disk", text(entry, "name"), text(entry, "zone"))]["id"] = (
            "replaced"
        )
    provider.journal.data["history"] = [item for item in history]
    provider.journal.save()
    before = list(cloud.calls)
    assert provider.cleanup(False)["eligible"] == []
    provider.cleanup(True)
    assert cloud.calls == before


def test_cleanup_resume_rechecks_history_after_preview(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
) -> None:
    cloud.errors[("instance.insert", "us-west1-a")] = "ZONE_RESOURCE_POOL_EXHAUSTED"
    provider = GCPProvider(config, cloud, connection)
    provider.init()
    entries = provider.cleanup(False)["eligible"]
    provider.journal.begin({"kind": "cleanup", "id": "cleanup", "resources": entries})
    provider.journal.data["history"] = []
    provider.journal.save()
    before = list(cloud.calls)
    with pytest.raises(PiccoloError, match="retained"):
        GCPProvider(config, cloud, connection).resume()
    assert cloud.calls == before


@pytest.mark.parametrize(
    "command", ["init", "adopt", "start", "stop", "move", "bootstrap"]
)
def test_foreign_environment_cannot_select_or_mutate_vm(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    command: str,
) -> None:
    owner = GCPProvider(config, cloud, connection)
    owner.init()
    intruder = GCPProvider(
        replace(config, environment="another-env"), cloud, connection
    )
    intruder.journal.data["active_instance_id"] = text(owner.active(), "id")
    before, access_calls = list(cloud.calls), cloud.access_calls
    with pytest.raises(PiccoloError, match="ownership"):
        if command == "init":
            intruder.init()
        elif command == "adopt":
            intruder.init(adopt=True)
        elif command == "move":
            intruder.move("us-east1-b")
        elif command == "bootstrap":
            intruder.bootstrap(False, True)
        elif command == "start":
            intruder.start()
        else:
            intruder.stop()
    assert cloud.calls == before
    assert cloud.access_calls == access_calls
    assert not intruder.journal.operation


def test_legacy_vm_requires_explicit_adoption_and_records_id(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
) -> None:
    original = GCPProvider(config, cloud, connection)
    original.init()
    original.journal.path.unlink()
    cloud.resources[("instance", "test-vm", "us-west1-a")]["labels"] = {}
    provider = GCPProvider(config, cloud, connection)
    with pytest.raises(PiccoloError, match="init --adopt"):
        provider.stop()
    with pytest.raises(PiccoloError, match="init --adopt"):
        provider.init()
    provider.init(adopt=True)
    assert provider.journal.data["active_instance_id"] == provider.active()["id"]
    assert "fresh_disk_id" not in provider.journal.data
    assert "bootstrap" not in provider.journal.data
    provider.stop()
    cloud.resources[("instance", "test-vm", "us-west1-a")]["id"] = "different"
    with pytest.raises(PiccoloError, match="identity changed"):
        provider.start()


@pytest.mark.parametrize("scope", ["instance", "project"])
@pytest.mark.parametrize(
    "key", ["shutdown-script", "shutdown-script-url", "windows-shutdown-script-ps1"]
)
@pytest.mark.parametrize("command", ["init", "start", "stop", "move"])
def test_automatic_shutdown_hooks_block_lifecycle_without_mutations(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    scope: str,
    key: str,
    command: str,
) -> None:
    provider = GCPProvider(config, cloud, connection)
    provider.init()
    metadata: Document = {"items": [{"key": key, "value": "harmless-but-unauthorized"}]}
    if scope == "instance":
        cloud.resources[("instance", "test-vm", "us-west1-a")]["metadata"] = metadata
    else:
        cloud.metadata = metadata
    before, access_calls = list(cloud.calls), cloud.access_calls
    with pytest.raises(PiccoloError, match="lifecycle metadata"):
        if command == "move":
            provider.move("us-east1-b")
        elif command == "init":
            provider.init()
        elif command == "start":
            provider.start()
        else:
            provider.stop()
    assert cloud.calls == before
    assert cloud.access_calls == access_calls
    assert not provider.journal.operation


def test_shutdown_metadata_added_after_commit_blocks_source_deletion(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = GCPProvider(config, cloud, connection)
    provider.init()

    def add_shutdown_hook(_zone: str) -> None:
        cloud.metadata = {"items": [{"key": "shutdown-script", "value": "true"}]}

    monkeypatch.setattr(connection, "ready", add_shutdown_hook)
    with pytest.raises(PiccoloError, match="shutdown-script"):
        provider.move("us-east1-b")
    assert provider.journal.operation["committed"] is True
    assert not any(call[0].endswith(".delete") for call in cloud.calls)
    assert len(cloud.list("snapshot")) == 1
    with pytest.raises(PiccoloError, match="shutdown-script"):
        GCPProvider(config, cloud, connection).resume()


def test_resume_stop_rechecks_shutdown_metadata(
    config: Config, cloud: FakeCloud, connection: GuestConnection
) -> None:
    provider = GCPProvider(config, cloud, connection)
    provider.init()
    instance = provider.active()
    provider.journal.begin(
        {
            "kind": "stop",
            "id": "stop",
            "zone": zone_of(instance),
            "instance_id": text(instance, "id"),
        }
    )
    cloud.metadata = {
        "items": [{"key": "shutdown-script-url", "value": "gs://unapproved"}]
    }
    before = list(cloud.calls)
    with pytest.raises(PiccoloError, match="shutdown-script-url"):
        GCPProvider(config, cloud, connection).resume()
    assert cloud.calls == before


def test_resumed_init_rejects_foreign_vm_before_access(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
) -> None:
    provider = GCPProvider(config, cloud, connection)
    cloud.lost_response.add(("instance.insert", "us-west1-a"))
    with pytest.raises(UncertainError):
        provider.init()
    cloud.resources[("instance", "test-vm", "us-west1-a")]["labels"] = {
        "managed-by": "piccolo",
        "piccolo-environment": "foreign-environment",
    }
    before, access_calls = list(cloud.calls), cloud.access_calls
    with pytest.raises(PiccoloError, match="ownership"):
        GCPProvider(config, cloud, connection).resume()
    assert cloud.calls == before
    assert cloud.access_calls == access_calls


def test_replacement_ownership_changed_during_readiness_blocks_commit(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = GCPProvider(config, cloud, connection)
    provider.init()

    def change_owner(zone: str) -> None:
        cloud.resources[("instance", "test-vm", zone)]["labels"] = {
            "managed-by": "piccolo",
            "piccolo-environment": "foreign-environment",
        }

    monkeypatch.setattr(connection, "ready", change_owner)
    with pytest.raises(PiccoloError, match="ownership"):
        provider.move("us-east1-b")
    assert provider.journal.operation.get("committed") is not True
    assert not any(call[0].endswith(".delete") for call in cloud.calls)
    assert len(cloud.list("snapshot")) == 1
