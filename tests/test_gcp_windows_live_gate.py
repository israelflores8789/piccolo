# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_windows_live_gate.py — Offline Windows live credential policy checks."""

from collections.abc import Callable, Generator
from dataclasses import replace
from inspect import unwrap
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest
import test_gcp_live
from gcp_live_support.gcp_live import approval_digest

from piccolo.config import Config
from piccolo.errors import PiccoloError


@pytest.mark.parametrize("connector", ["human@example.com", "provisioner"])
def test_windows_fixture_preserves_human_connector_policy(
    config: Config, monkeypatch: pytest.MonkeyPatch, connector: str
) -> None:
    """Accept a human before SDK loading and reject a provisioner connector."""
    account = (
        f"piccolo-test-provisioner@{config.gcp.project_id}.iam.gserviceaccount.com"
        if connector == "provisioner"
        else connector
    )
    approved = replace(config, gcp=replace(config.gcp, connection_account=account))
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", config.gcp.project_id)
    monkeypatch.setenv("PICCOLO_GCP_LIVE_CONFIG", str(config.path))
    monkeypatch.setenv("PICCOLO_GCP_LIVE_BUDGET_FILE", "reviewed-ledger.json")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_APPROVAL_SHA256", approval_digest(approved))
    monkeypatch.setattr("gcp_live_support.gcp_live.load", Mock(return_value=approved))
    preflight = Mock(side_effect=PiccoloError("reached local prerequisites"))
    monkeypatch.setattr(test_gcp_live, "local_preflight", preflight)
    request = cast(
        pytest.FixtureRequest,
        SimpleNamespace(
            config=SimpleNamespace(getoption=Mock(return_value=True)),
            node=SimpleNamespace(callspec=SimpleNamespace(params={})),
        ),
    )
    fixture = cast(
        Callable[[pytest.FixtureRequest, pytest.MonkeyPatch, None], Generator[object]],
        unwrap(test_gcp_live.gcp_run),
    )
    run = fixture(request, monkeypatch, None)
    message = "human" if connector == "provisioner" else "local prerequisites"
    with pytest.raises(PiccoloError, match=message):
        next(run)
    assert preflight.call_count == (0 if connector == "provisioner" else 1)
