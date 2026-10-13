# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_recycle_bin.py — Ownership, pagination, and durable permanent purge checks."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from gcp_live_support.manifest import Manifest
from gcp_live_support.recycle_bin import RecycleBin
from google.auth.credentials import AnonymousCredentials
from requests import Response, Session
from requests.exceptions import Timeout

from piccolo.data import Document, document, text
from piccolo.errors import PiccoloError, UncertainError

PROJECT = "piccolo-offline-tests"
RUN = "plive-0123456789abcdef"


def response(status: int, body: Document) -> Response:
    """Return an HTTP response without a connection or credential refresh."""
    result = Response()
    result.status_code = status
    result._content = json.dumps(body).encode()
    return result


@pytest.fixture
def recycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[RecycleBin, Manifest, Document]:
    """Record the original snapshot identity before exposing a recoverable copy."""
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", PROJECT)
    manifest = Manifest.create(
        tmp_path / "run" / "manifest.json",
        tmp_path / "profile.toml",
        RUN,
        project=PROJECT,
    )
    entry = manifest.register("snapshot", RUN + "-snapshot", "", {})
    entry["id"] = "100"
    manifest.put("resources", entry)
    item: Document = {
        "name": RUN + "-recycled",
        "id": "200",
        "originalResource": {"name": RUN + "-snapshot", "id": "100"},
    }
    return RecycleBin(PROJECT, AnonymousCredentials()), manifest, item


def test_purge_records_intent_operation_and_verified_absence(
    recycle: tuple[RecycleBin, Manifest, Document], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Delete an exact recoverable copy once, with durable intent before submission."""
    client, manifest, item = recycle
    frames = [
        response(200, {"items": [item]}),
        response(200, item),
        response(200, {"name": "operation-purge"}),
        response(200, {"status": "DONE"}),
        response(404, {}),
    ]

    def request(method: str, url: str, **kwargs: object) -> Response:
        assert url.startswith(
            f"https://compute.googleapis.com/compute/beta/projects/{PROJECT}/global/"
        )
        assert kwargs["allow_redirects"] is False
        if method == "DELETE":
            saved = Manifest.open(manifest.path).entries("recycle_bin")[0]
            assert saved["outcome"] == "intent"
            assert f"requestId={text(saved, 'request_id')}" in url
        return frames.pop(0)

    sender = Mock(side_effect=request)
    monkeypatch.setattr(client.session, "request", sender)
    client.purge(manifest)
    saved = Manifest.open(manifest.path).entries("recycle_bin")[0]
    assert saved["outcome"] == "purged"
    assert saved["operation"] == "operation-purge"
    assert sum(call.args[0] == "DELETE" for call in sender.call_args_list) == 1


@pytest.mark.parametrize("changed", ["original", "recoverable", "unrecorded"])
def test_purge_rejects_unproven_or_changed_identity(
    recycle: tuple[RecycleBin, Manifest, Document],
    monkeypatch: pytest.MonkeyPatch,
    changed: str,
) -> None:
    """Retain an unowned copy or one replaced between inventory and deletion."""
    client, manifest, item = recycle
    current = document(item)
    if changed == "original":
        current["originalResource"] = {"name": RUN + "-snapshot", "id": "replaced"}
    elif changed == "recoverable":
        current["id"] = "replaced"
    else:
        manifest.data["resources"] = []
    sender = Mock(
        side_effect=[response(200, {"items": [item]}), response(200, current)]
    )
    monkeypatch.setattr(client.session, "request", sender)
    with pytest.raises(PiccoloError, match=r"ownership|changed"):
        client.purge(manifest)
    assert all(call.args[0] == "GET" for call in sender.call_args_list)


@pytest.mark.parametrize("remains_visible", [True, False])
def test_lost_purge_response_is_not_resubmitted(
    recycle: tuple[RecycleBin, Manifest, Document],
    monkeypatch: pytest.MonkeyPatch,
    remains_visible: bool,
) -> None:
    """Retain an uncertain request for recovery without a second delete."""
    client, manifest, item = recycle
    sender = Mock(
        side_effect=[
            response(200, {"items": [item]}),
            response(200, item),
            Timeout("lost response"),
            response(200, {"items": [item]} if remains_visible else {}),
        ]
    )
    monkeypatch.setattr(client.session, "request", sender)
    with pytest.raises(Timeout):
        client.purge(manifest)
    with pytest.raises(UncertainError, match="Previous"):
        client.purge(Manifest.open(manifest.path))
    assert sum(call.args[0] == "DELETE" for call in sender.call_args_list) == 1


def test_inventory_reads_later_pages_and_rejects_cycles(
    recycle: tuple[RecycleBin, Manifest, Document], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Read complete inventory without following a server-supplied endpoint."""
    client, _, item = recycle
    sender = Mock(
        side_effect=[
            response(200, {"nextPageToken": "opaque/page token"}),
            response(200, {"items": [item]}),
        ]
    )
    monkeypatch.setattr(client.session, "request", sender)
    assert client.inventory() == [item]
    assert "pageToken=opaque%2Fpage+token" in sender.call_args.args[1]
    sender.side_effect = [
        response(200, {"nextPageToken": "same"}),
        response(200, {"nextPageToken": "same"}),
    ]
    with pytest.raises(PiccoloError, match="repeated"):
        client.inventory()


def test_unauthorized_purge_has_no_authenticated_replay(
    recycle: tuple[RecycleBin, Manifest, Document], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise AuthorizedSession's real wrapper while replacing its HTTP transport."""
    client, _, item = recycle
    sender = Mock(return_value=response(401, {}))
    monkeypatch.setattr(Session, "request", sender)
    with pytest.raises(PiccoloError, match="HTTP 401"):
        client.request("DELETE", f"recoverableSnapshots/{text(item, 'name')}")
    assert sender.call_count == 1
