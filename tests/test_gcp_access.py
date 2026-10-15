# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_access.py — IAM, firewall, and service API reconciliation."""

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from google.api_core import exceptions
from google.auth.credentials import AnonymousCredentials
from google.cloud import compute_v1, iam_admin_v1, resourcemanager_v3, service_usage_v1
from google.iam.v1 import policy_pb2

from piccolo.config import Config, load
from piccolo.data import Document, objects
from piccolo.errors import PiccoloError, UncertainError
from piccolo.providers.gcp import auth
from piccolo.providers.gcp.access import Access
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.resources import SDKCloud
from piccolo.state.journal import Journal


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
            credentials_file=path,
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
