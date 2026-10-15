# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_ssh_authorization.py — Offline connection credentials, policy, and renewal."""

import copy
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from email.message import Message
from unittest.mock import MagicMock, Mock
from urllib.error import HTTPError

import pytest

from piccolo.config import Config
from piccolo.data import Document, document, objects, text
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.connection import GCloudConnection
from piccolo.providers.gcp.ssh_auth import KeyAuthorization

PUBLIC = "ssh-ed25519 Zml4dHVyZS1wdWJsaWM= fixture"


class MetadataAPI:
    def __init__(self) -> None:
        self.instance: Document = {
            "id": "123",
            "metadata": {
                "fingerprint": "original",
                "items": [
                    {"key": "unrelated", "value": "preserved"},
                    {"key": "ssh-keys", "value": "other:ssh-rsa unrelated other"},
                ],
            },
        }
        self.project: Document = {"commonInstanceMetadata": {"items": []}}
        self.zonal: Document = {"metadata": {"items": {}}}
        self.writes: list[Document] = []
        self.conflicts = 0
        self.accepted = False

    def request(self, path: str, body: Document | None = None) -> Document:
        if body is not None:
            self.writes.append(copy.deepcopy(body))
            if self.conflicts:
                self.conflicts -= 1
                metadata = document(self.instance["metadata"])
                metadata["fingerprint"] = "concurrent"
                items = objects(metadata, "items")
                for item in items:
                    if item["key"] == "ssh-keys":
                        item["value"] = (
                            text(item, "value")
                            + "\nconcurrent:ssh-rsa added concurrently"
                        )
                metadata["items"] = list(items)
                self.instance["metadata"] = metadata
                raise HTTPError(
                    "https://compute.googleapis.com/",
                    412,
                    "fingerprint conflict",
                    Message(),
                    None,
                )
            assert (
                body["fingerprint"]
                == document(self.instance["metadata"])["fingerprint"]
            )
            self.instance["metadata"] = {
                **copy.deepcopy(body),
                "fingerprint": "updated",
            }
            self.accepted = True
            return {"name": "operation", "status": "DONE", "targetId": "123"}
        if path.endswith("/instanceSettings"):
            return copy.deepcopy(self.zonal)
        if "/instances/" in path:
            return copy.deepcopy(self.instance)
        return copy.deepcopy(self.project)


@pytest.fixture
def authorization(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> tuple[KeyAuthorization, MetadataAPI]:
    connection = GCloudConnection(
        replace(config.gcp, connection_account="connector@example.test")
    )
    api = MetadataAPI()
    auth = connection.ssh.authorization
    monkeypatch.setattr(auth, "request", api.request)
    return auth, api


def test_metadata_merge_retains_other_keys_and_metadata_and_finite_ttl(
    authorization: tuple[KeyAuthorization, MetadataAPI],
) -> None:
    auth, api = authorization
    auth.authorize("us-west1-a", "123", PUBLIC)
    items = objects(api.writes[0], "items")
    assert {"key": "unrelated", "value": "preserved"} in items
    keys = next(text(item, "value") for item in items if item["key"] == "ssh-keys")
    assert "other:ssh-rsa unrelated other" in keys
    own = next(line for line in keys.splitlines() if line.startswith("researcher:"))
    stamp = json.loads(own.partition(" google-ssh ")[2])
    assert stamp["userName"] == "researcher"
    expiry = datetime.fromisoformat(stamp["expireOn"])
    assert (
        timedelta(hours=23, minutes=59)
        < expiry - datetime.now(UTC)
        < timedelta(hours=24, minutes=1)
    )
    assert api.writes[0]["fingerprint"] == "original"


def test_conflict_rereads_fingerprint_and_preserves_concurrent_keys(
    authorization: tuple[KeyAuthorization, MetadataAPI],
) -> None:
    auth, api = authorization
    api.conflicts = 1
    auth.authorize("us-west1-a", "123", PUBLIC)
    assert len(api.writes) == 2
    assert api.writes[-1]["fingerprint"] == "concurrent"
    assert "concurrent:ssh-rsa added concurrently" in json.dumps(api.writes[-1])


def test_conflict_retries_are_bounded(
    authorization: tuple[KeyAuthorization, MetadataAPI],
) -> None:
    auth, api = authorization
    api.conflicts = 10
    with pytest.raises(PiccoloError, match="kept changing"):
        auth.authorize("us-west1-a", "123", PUBLIC)
    assert len(api.writes) == 3


def test_live_key_is_idempotent_and_expired_key_is_renewed(
    authorization: tuple[KeyAuthorization, MetadataAPI],
) -> None:
    auth, api = authorization
    auth.authorize("us-west1-a", "123", PUBLIC)
    auth.authorize("us-west1-a", "123", PUBLIC)
    assert len(api.writes) == 1
    metadata = document(api.instance["metadata"])
    items = objects(metadata, "items")
    for item in items:
        if item["key"] == "ssh-keys":
            item["value"] = (
                "other:ssh-rsa unrelated other\nresearcher:"
                + " ".join(PUBLIC.split()[:2])
                + " google-ssh "
                + '{"userName":"researcher","expireOn":"2000-01-01T00:00:00+0000"}'
            )
    metadata["items"] = list(items)
    api.instance["metadata"] = metadata
    auth.authorize("us-west1-a", "123", PUBLIC)
    assert len(api.writes) == 2


@pytest.mark.parametrize(
    "problem",
    ["missing-fingerprint", "duplicate-key", "legacy-key", "instance-replaced"],
)
def test_unsafe_metadata_never_writes(
    authorization: tuple[KeyAuthorization, MetadataAPI], problem: str
) -> None:
    auth, api = authorization
    metadata = document(api.instance["metadata"])
    if problem == "missing-fingerprint":
        metadata.pop("fingerprint")
    elif problem == "duplicate-key":
        metadata["items"] = [
            {"key": "enable-oslogin", "value": "true"},
            {"key": "enable-oslogin", "value": "false"},
        ]
    elif problem == "legacy-key":
        metadata["items"] = [{"key": "sshKeys", "value": "old format"}]
    else:
        api.instance["id"] = "456"
    api.instance["metadata"] = metadata
    with pytest.raises(PiccoloError):
        auth.authorize("us-west1-a", "123", PUBLIC)
    assert not api.writes


def test_instance_policy_overrides_project_and_zonal_oslogin(
    authorization: tuple[KeyAuthorization, MetadataAPI],
) -> None:
    auth, api = authorization
    api.project = {
        "commonInstanceMetadata": {
            "items": [{"key": "enable-oslogin", "value": "true"}]
        }
    }
    api.zonal = {"metadata": {"items": {"enable-oslogin": "true"}}}
    api.instance["metadata"] = {
        "fingerprint": "original",
        "items": [{"key": "enable-oslogin", "value": "false"}],
    }
    auth.authorize("us-west1-a", "123", PUBLIC)
    assert api.writes


@pytest.mark.parametrize(
    "setting", ["enable-oslogin-2fa", "enable-oslogin-certificates"]
)
def test_unsupported_oslogin_modes_fail_before_key_mutation(
    authorization: tuple[KeyAuthorization, MetadataAPI], setting: str
) -> None:
    auth, api = authorization
    api.project = {
        "commonInstanceMetadata": {
            "items": [
                {"key": "enable-oslogin", "value": "true"},
                {"key": setting, "value": "true"},
            ]
        }
    }
    with pytest.raises(PiccoloError, match="does not support"):
        auth.authorize("us-west1-a", "123", PUBLIC)
    assert not api.writes


@pytest.mark.parametrize(
    "username,imports", [("researcher", True), ("different-user", False)]
)
def test_oslogin_identity_is_checked_before_import(
    authorization: tuple[KeyAuthorization, MetadataAPI],
    monkeypatch: pytest.MonkeyPatch,
    username: str,
    imports: bool,
) -> None:
    import subprocess

    auth, api = authorization
    api.project = {
        "commonInstanceMetadata": {
            "items": [{"key": "enable-oslogin", "value": "true"}]
        }
    }
    profile = {
        "posixAccounts": [
            {"username": username, "primary": True, "operatingSystemType": "LINUX"}
        ]
    }
    runner = Mock(
        side_effect=[
            subprocess.CompletedProcess([], 0, json.dumps(profile), ""),
            subprocess.CompletedProcess([], 0, "{}", ""),
        ]
    )
    monkeypatch.setattr(auth.connection, "run", runner)
    if imports:
        auth.authorize("us-west1-a", "123", PUBLIC)
        assert runner.call_count == 2
        arguments = runner.call_args.args[0]
        assert arguments[:4] == ["compute", "os-login", "ssh-keys", "add"]
        assert "--ttl=24h" in arguments
        assert f"--key={PUBLIC}" in arguments
    else:
        with pytest.raises(PiccoloError, match="OS Login user mismatch"):
            auth.authorize("us-west1-a", "123", PUBLIC)
        assert runner.call_count == 1
    assert not api.writes


@pytest.mark.parametrize("duplicate", [False, True])
def test_oslogin_primary_accounts_are_scoped_to_the_selected_project(
    authorization: tuple[KeyAuthorization, MetadataAPI],
    monkeypatch: pytest.MonkeyPatch,
    duplicate: bool,
) -> None:
    """Ignore another project's primary entry and reject local ambiguity."""
    import subprocess

    auth, _api = authorization
    account = {
        "username": auth.connection.config.ssh_user,
        "primary": True,
        "accountId": auth.connection.config.project_id,
    }
    profile = {
        "posixAccounts": [
            {**account, "accountId": "another-project", "username": "other-user"},
            account,
            *([account] if duplicate else []),
        ]
    }
    runner = Mock(
        side_effect=[
            subprocess.CompletedProcess([], 0, json.dumps(profile), ""),
            subprocess.CompletedProcess([], 0, "{}", ""),
        ]
    )
    monkeypatch.setattr(auth.connection, "run", runner)
    if duplicate:
        with pytest.raises(PiccoloError, match="OS Login user mismatch"):
            auth.oslogin("us-west1-a", "123", PUBLIC)
        assert runner.call_count == 1
    else:
        auth.oslogin("us-west1-a", "123", PUBLIC)
        assert runner.call_count == 2


def test_api_uses_connection_token_and_never_adc(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    connection = GCloudConnection(
        replace(
            config.gcp,
            connection_account="connector@example.test",
            connection_impersonate="connector-sa@example.test",
        )
    )
    monkeypatch.setattr(connection, "environment", lambda: {})
    monkeypatch.setattr(connection, "launcher", lambda: ["fake-gcloud"])
    subprocess_run = Mock(
        return_value=subprocess.CompletedProcess(
            [], 0, "offline-connection-token\n", ""
        )
    )
    monkeypatch.setattr(subprocess, "run", subprocess_run)
    monkeypatch.setattr("piccolo.providers.gcp.connection.run_command", subprocess_run)
    response = MagicMock()
    response.__enter__.return_value.read.return_value = b'{"id":"123"}'
    urlopen = Mock(return_value=response)
    monkeypatch.setattr("piccolo.providers.gcp.ssh_auth.urlopen", urlopen)
    assert connection.ssh.authorization.request("projects/test-project") == {
        "id": "123"
    }
    arguments = subprocess_run.call_args.args[0]
    assert "print-access-token" in arguments
    assert "--account=connector@example.test" in arguments
    assert "--impersonate-service-account=connector-sa@example.test" in arguments
    request = urlopen.call_args.args[0]
    assert request.get_header("Authorization") == "Bearer offline-connection-token"
    assert (
        request.full_url
        == "https://compute.googleapis.com/compute/v1/projects/test-project"
    )


def test_connector_token_reuse_is_bounded_and_identity_scoped(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reuse one token per operation and refresh after identity changes or errors."""
    import subprocess

    connection = GCloudConnection(config.gcp)
    connection.selected_account = "connector@example.test"
    runner = Mock(return_value=subprocess.CompletedProcess([], 0, "fixture-token", ""))
    monkeypatch.setattr(connection, "run", runner)
    response = MagicMock()
    response.__enter__.return_value.read.return_value = b'{"id":"123"}'
    monkeypatch.setattr(
        "piccolo.providers.gcp.ssh_auth.urlopen", Mock(return_value=response)
    )
    auth = connection.ssh.authorization
    with (
        pytest.raises(PiccoloError, match="fixture interruption"),
        connection.ssh.bounded(60),
    ):
        auth.request("projects/test-project")
        auth.request("projects/test-project")
        assert runner.call_count == 1
        connection.selected_account = "changed@example.test"
        auth.request("projects/test-project")
        assert runner.call_count == 2
        raise PiccoloError("fixture interruption")
    with connection.ssh.bounded(60):
        auth.request("projects/test-project")
        assert runner.call_count == 3
    auth.request("projects/test-project")
    auth.request("projects/test-project")
    assert runner.call_count == 5


@pytest.mark.parametrize(
    "condition", ["valid", "expired", "unbounded", "overlong", "different", "duplicate"]
)
def test_oslogin_reuses_only_one_matching_key_with_a_bounded_valid_expiry(
    authorization: tuple[KeyAuthorization, MetadataAPI],
    monkeypatch: pytest.MonkeyPatch,
    condition: str,
) -> None:
    """Avoid redundant imports while renewing expired or excessive authorizations."""
    import subprocess

    auth, _api = authorization
    monkeypatch.setattr("piccolo.providers.gcp.ssh_auth.time.time", lambda: 1000.0)
    expiration = {
        "expired": 999,
        "unbounded": 0,
        "overlong": 1000 + 2 * 86400,
    }.get(condition, 4600)
    key = {
        "key": "ssh-ed25519 other-key comment" if condition == "different" else PUBLIC,
        "expirationTimeUsec": str(expiration * 1_000_000),
    }
    keys = {"first": key}
    if condition == "duplicate":
        keys["second"] = key
    profile = {
        "posixAccounts": [
            {"primary": True, "username": auth.connection.config.ssh_user}
        ],
        "sshPublicKeys": keys,
    }
    runner = Mock(
        side_effect=[
            subprocess.CompletedProcess([], 0, json.dumps(profile), ""),
            subprocess.CompletedProcess([], 0, "{}", ""),
        ]
    )
    monkeypatch.setattr(auth.connection, "run", runner)
    auth.oslogin("us-west1-a", "123", PUBLIC)
    assert runner.call_count == (1 if condition == "valid" else 2)
