# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_sdk.py — SDK wire contracts with anonymous credentials and mocked methods."""

from unittest.mock import Mock

import pytest
from google.api_core import exceptions
from google.auth.credentials import AnonymousCredentials
from google.cloud import compute_v1, resourcemanager_v3, service_usage_v1
from google.iam.v1 import policy_pb2

from piccolo.config import Config
from piccolo.data import Document, decode
from piccolo.errors import CapacityError, PiccoloError, UncertainError
from piccolo.providers.gcp.access import Access, add_binding
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.operations import failure
from piccolo.providers.gcp.provision import instance_resource
from piccolo.providers.gcp.resources import SDKCloud


def test_instance_payload_can_be_encoded_by_sdk(config: Config) -> None:
    payload = instance_resource(
        config,
        "us-west1-a",
        "projects/test-project/zones/us-west1-a/disks/boot",
        "projects/test-project/regions/us-west1/subnetworks/default",
        "operation",
    )
    instance = compute_v1.Instance(**payload)
    assert instance.disks[0].auto_delete is False
    assert instance.network_interfaces[0].access_configs[0].type_ == "ONE_TO_ONE_NAT"
    assert instance.shielded_instance_config.enable_secure_boot
    assert not instance.metadata.items


@pytest.mark.parametrize(
    "kind,name,zone,resource,client_field,method",
    [
        (
            "instance.insert",
            "test-vm",
            "us-west1-a",
            {"name": "test-vm"},
            "instances",
            "insert",
        ),
        (
            "disk.insert",
            "boot",
            "us-west1-a",
            {
                "name": "boot",
                "source_image": "projects/debian-cloud/global/images/debian-13",
            },
            "disks",
            "insert",
        ),
        (
            "snapshot.insert",
            "snapshot",
            "",
            {
                "name": "snapshot",
                "source_disk": "projects/test-project/zones/us-west1-a/disks/boot",
            },
            "snapshots",
            "insert",
        ),
        (
            "instance.protect",
            "test-vm",
            "us-west1-a",
            {"device_name": "test-vm"},
            "instances",
            "set_disk_auto_delete",
        ),
        ("instance.start", "test-vm", "us-west1-a", {}, "instances", "start"),
        ("instance.stop", "test-vm", "us-west1-a", {}, "instances", "stop"),
        ("instance.delete", "test-vm", "us-west1-a", {}, "instances", "delete"),
        ("disk.delete", "boot", "us-west1-a", {}, "disks", "delete"),
        ("snapshot.delete", "snapshot", "", {}, "snapshots", "delete"),
    ],
)
def test_mutation_requests_have_project_idempotency_and_no_retry(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    name: str,
    zone: str,
    resource: Document,
    client_field: str,
    method: str,
) -> None:
    clients = Clients(AnonymousCredentials())
    mocked = Mock(return_value=Mock(name="ignored"))
    mocked.return_value.name = "compute-operation"
    monkeypatch.setattr(getattr(clients, client_field), method, mocked)
    result = SDKCloud(config, clients).submit(
        kind, name, zone, resource, "903e8a3f-3620-497d-b14e-9b74b932bd65"
    )
    assert result == "compute-operation"
    arguments = mocked.call_args.kwargs
    assert arguments["retry"] is None
    request = arguments["request"]
    assert request.project == "test-project"
    assert request.request_id == "903e8a3f-3620-497d-b14e-9b74b932bd65"


def test_transport_failure_is_uncertain_not_capacity(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients = Clients(AnonymousCredentials())
    monkeypatch.setattr(
        clients.instances,
        "insert",
        Mock(side_effect=exceptions.ServiceUnavailable("503")),
    )
    with pytest.raises(UncertainError):
        SDKCloud(config, clients).submit(
            "instance.insert", "test-vm", "us-west1-a", {"name": "test-vm"}, "request"
        )


def test_notfound_is_distinct_from_permission_denied(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients = Clients(AnonymousCredentials())
    cloud = SDKCloud(config, clients)
    monkeypatch.setattr(
        clients.instances, "get", Mock(side_effect=exceptions.NotFound("absent"))
    )
    assert cloud.get("instance", "test-vm", "us-west1-a") is None
    monkeypatch.setattr(
        clients.instances, "get", Mock(side_effect=exceptions.Forbidden("denied"))
    )
    with pytest.raises(PiccoloError):
        cloud.get("instance", "test-vm", "us-west1-a")


def test_capacity_mixed_with_quota_is_never_fallback() -> None:
    result = failure(
        {
            "error": {
                "errors": [
                    {"code": "ZONE_RESOURCE_POOL_EXHAUSTED"},
                    {"code": "QUOTA_EXCEEDED"},
                ]
            }
        }
    )
    assert isinstance(result, PiccoloError)
    assert not isinstance(result, CapacityError)
    assert isinstance(failure({"http_error_status_code": 503}), PiccoloError)


def test_additive_iam_preserves_etag_and_conditions() -> None:
    policy = policy_pb2.Policy(version=3, etag=b"unchanged")
    condition = policy.bindings.add(
        role="roles/viewer", members=["user:unrelated@example.com"]
    )
    condition.condition.expression = "true"
    assert add_binding(policy, "roles/viewer", "serviceAccount:vm@example.com")
    assert len(policy.bindings) == 2
    assert policy.bindings[0].condition.expression == "true"
    assert policy.bindings[0].members == ["user:unrelated@example.com"]
    assert policy.etag == b"unchanged"
    assert not add_binding(policy, "roles/viewer", "serviceAccount:vm@example.com")


def test_iam_etag_conflict_rereads_policy(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients = Clients(AnonymousCredentials())
    policy = policy_pb2.Policy(version=3, etag=b"first")
    second = policy_pb2.Policy(version=3, etag=b"second")
    getter = Mock(side_effect=[policy, second])
    setter = Mock(side_effect=[exceptions.Aborted("etag"), policy_pb2.Policy()])
    monkeypatch.setattr(clients.projects, "get_iam_policy", getter)
    monkeypatch.setattr(clients.projects, "set_iam_policy", setter)
    Access(config, clients).grant("projects/test-project", "roles/viewer", secret=False)
    assert getter.call_count == 2
    assert setter.call_args.kwargs["request"].policy.etag == b"second"
    assert getter.call_args.kwargs["request"].options.requested_policy_version == 3


def test_operation_error_is_structured_sdk_json() -> None:
    operation = compute_v1.Operation(
        status="DONE",
        error=compute_v1.Error(
            errors=[
                compute_v1.Errors(
                    code="ZONE_RESOURCE_POOL_EXHAUSTED", message="capacity"
                )
            ]
        ),
    )
    decoded = decode(
        compute_v1.Operation.to_json(operation, preserving_proto_field_name=True)
    )
    assert isinstance(failure(decoded), CapacityError)


def test_relocation_preserves_items_without_update_fingerprints(config: Config) -> None:
    source: Document = {
        "metadata": {
            "fingerprint": "metadata-update-only",
            "items": [{"key": "keep", "value": "value"}],
        },
        "tags": {"fingerprint": "tags-update-only", "items": ["research"]},
        "disks": [
            {
                "boot": True,
                "source": "projects/test-project/zones/us-west1-a/disks/boot",
            }
        ],
        "network_interfaces": [{"access_configs": []}],
    }
    payload = instance_resource(
        config,
        "us-east1-b",
        "projects/test-project/zones/us-east1-b/disks/boot",
        "subnet",
        "operation",
        source,
    )
    assert payload["metadata"] == {"items": [{"key": "keep", "value": "value"}]}
    assert payload["tags"] == {"items": ["research"]}


def test_access_plan_reports_missing_resources_without_mutations(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients = Clients(AnonymousCredentials())
    monkeypatch.setattr(
        clients.projects,
        "get_project",
        Mock(return_value=resourcemanager_v3.Project(name="projects/123456")),
    )
    monkeypatch.setattr(
        clients.services,
        "get_service",
        Mock(
            return_value=service_usage_v1.Service(state=service_usage_v1.State.DISABLED)
        ),
    )
    monkeypatch.setattr(
        clients.iam,
        "get_service_account",
        Mock(side_effect=exceptions.NotFound("absent")),
    )
    monkeypatch.setattr(
        clients.firewalls, "get", Mock(side_effect=exceptions.NotFound("absent"))
    )
    enable = Mock(side_effect=AssertionError("plan must not enable APIs"))
    insert = Mock(side_effect=AssertionError("plan must not create a firewall"))
    create_account = Mock(side_effect=AssertionError("plan must not create an SA"))
    monkeypatch.setattr(clients.services, "enable_service", enable)
    monkeypatch.setattr(clients.firewalls, "insert", insert)
    monkeypatch.setattr(clients.iam, "create_service_account", create_account)
    result = Access(config, clients).inspect()
    assert result["service_account"]["exists"] is False
    assert result["firewall"]["will_create"] is True
    assert all(item["enabled"] is False for item in result["apis"])
    enable.assert_not_called()
    insert.assert_not_called()
    create_account.assert_not_called()
