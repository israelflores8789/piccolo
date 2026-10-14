# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_live_session.py — Offline checks for environment-scoped live sessions."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from gcp_live_support import session
from google.cloud import iam_admin_v1

from piccolo.config import Config
from piccolo.errors import PiccoloError


@pytest.mark.parametrize("project", ["approval-alpha", "approval-bravo"])
def test_session_identities_follow_explicit_project(
    project: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resolve each invocation's identities without an import-time project cache."""
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", project)
    monkeypatch.delenv("PICCOLO_GCP_LIVE_BASELINE", raising=False)
    settings = session.SessionSettings.from_environment()
    assert settings.project == project
    assert settings.accounts == (
        f"piccolo-test-provisioner@{project}.iam.gserviceaccount.com",
        f"piccolo-test-vm@{project}.iam.gserviceaccount.com",
    )
    assert settings.secret == f"projects/{project}/secrets/PICCOLO_LIVE_DUMMY"
    assert settings.baseline == Path(f".test_runs/{project}-session-baseline.json")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", "approval-charlie")
    assert session.SessionSettings.from_environment().project == "approval-charlie"
    assert settings.project == project


def test_session_baseline_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Honor an explicitly selected session baseline without a dated fallback."""
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", "approval-alpha")
    path = tmp_path / "reviewed-baseline.json"
    monkeypatch.setenv("PICCOLO_GCP_LIVE_BASELINE", str(path))
    assert session.SessionSettings.from_environment().baseline == path


@pytest.mark.parametrize("project", [None, "", "INVALID", "approval-alpha"])
def test_session_rejects_invalid_approval_before_loading_credentials(
    project: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep missing, invalid, and non-opted-in sessions entirely cloud-free."""
    monkeypatch.setattr(sys, "argv", ["session", "prepare"])
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "0" if project == "approval-alpha" else "1")
    if project is None:
        monkeypatch.delenv("PICCOLO_GCP_LIVE_PROJECT", raising=False)
    else:
        monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", project)
    loader, auth, clients = Mock(), Mock(), Mock()
    monkeypatch.setattr(session, "load", loader)
    monkeypatch.setattr(session, "credentials", auth)
    monkeypatch.setattr(session, "Clients", clients)
    with pytest.raises(PiccoloError, match="PICCOLO_GCP_LIVE"):
        session.main()
    loader.assert_not_called()
    auth.assert_not_called()
    clients.assert_not_called()


def test_session_rejects_profile_mismatch_before_loading_credentials(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prevent a valid environment approval from authorizing another profile."""
    monkeypatch.setattr(sys, "argv", ["session", "prepare"])
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", "approval-alpha")
    monkeypatch.setattr(session, "load", Mock(return_value=config))
    auth, clients = Mock(), Mock()
    monkeypatch.setattr(session, "credentials", auth)
    monkeypatch.setattr(session, "Clients", clients)
    with pytest.raises(PiccoloError, match="Profile project differs"):
        session.main()
    auth.assert_not_called()
    clients.assert_not_called()


def test_session_prepare_uses_approved_account_and_resource_names(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Capture the mocked original accounts and policies in the approved project."""
    project = config.gcp.project_id
    settings = session.SessionSettings(project, tmp_path / "baseline.json")
    monkeypatch.setattr(sys, "argv", ["session", "prepare"])
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", project)
    monkeypatch.setenv("PICCOLO_GCP_LIVE_BASELINE", str(settings.baseline))
    monkeypatch.setattr(session, "load", Mock(return_value=config))
    monkeypatch.setattr(
        session,
        "credentials",
        Mock(return_value=SimpleNamespace(service_account_email=settings.accounts[0])),
    )
    clients = Mock()
    clients.secrets.get_secret.return_value = SimpleNamespace(
        create_time="original", labels={"piccolo-live-dummy": "true"}
    )
    clients.iam.get_service_account.side_effect = [
        iam_admin_v1.ServiceAccount(email=account) for account in settings.accounts
    ]
    monkeypatch.setattr(session, "Clients", Mock(return_value=clients))
    monkeypatch.setattr(session, "bind_clients", Mock())
    policy = Mock(return_value={"bindings": []})
    saved = Mock()
    monkeypatch.setattr(session, "policy", policy)
    monkeypatch.setattr(session, "save", saved)
    session.main()
    clients.secrets.get_secret.assert_called_once_with(
        name=settings.secret, retry=None, timeout=30
    )
    assert [
        call.kwargs["name"] for call in clients.iam.get_service_account.call_args_list
    ] == [
        f"projects/{project}/serviceAccounts/{account}" for account in settings.accounts
    ]
    assert [call.args[1] for call in policy.call_args_list] == [
        *(
            f"projects/{project}/serviceAccounts/{account}"
            for account in settings.accounts
        ),
        f"projects/{project}",
        settings.secret,
    ]
    assert saved.call_args.args[0]["project"] == project
    assert saved.call_args.args[1] == settings


def test_session_rejects_another_provisioner_before_creating_clients(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bind the fixed provisioner account name to the environment's project."""
    monkeypatch.setattr(sys, "argv", ["session", "prepare"])
    monkeypatch.setenv("PICCOLO_GCP_LIVE", "1")
    monkeypatch.setenv("PICCOLO_GCP_LIVE_PROJECT", config.gcp.project_id)
    monkeypatch.setattr(session, "load", Mock(return_value=config))
    monkeypatch.setattr(
        session,
        "credentials",
        Mock(
            return_value=SimpleNamespace(
                service_account_email="piccolo-test-provisioner@other-project.iam.gserviceaccount.com"
            )
        ),
    )
    clients = Mock()
    monkeypatch.setattr(session, "Clients", clients)
    with pytest.raises(PiccoloError, match="approved provisioner"):
        session.main()
    clients.assert_not_called()
