# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_auth.py — Credential configuration validation without token refresh."""

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from google.auth import compute_engine, impersonated_credentials
from google.oauth2 import credentials as user_credentials

from piccolo.config import Config
from piccolo.data import Document
from piccolo.errors import PiccoloError
from piccolo.providers.gcp import auth


@pytest.mark.parametrize("discovery", ["file", "environment", "sdk-adc"])
@pytest.mark.parametrize(
    "payload",
    [
        {
            "type": "external_account",
            "credential_source": {"url": "http://localhost/private"},
        },
        {"type": "external_account", "credential_source": {"file": "/private"}},
        {
            "type": "external_account",
            "credential_source": {"executable": {"command": "false"}},
        },
        {
            "type": "external_account_authorized_user",
            "token_url": "https://untrusted.test",
        },
        {
            "type": "impersonated_service_account",
            "source_credentials": {"type": "external_account"},
        },
        {"type": "gdch_service_account"},
        {"type": "authorized_user", "token_uri": "https://untrusted.test/token"},
        {
            "type": "service_account",
            "token_uri": "https://oauth2.googleapis.com/token?redirect=evil",
        },
        {"type": "service_account", "universe_domain": "untrusted.test"},
        {"type": "authorized_user", "credential_source": {"file": "/private"}},
        {
            "type": "authorized_user",
            "service_account_impersonation_url": "https://untrusted.test",
        },
    ],
)
def test_untrusted_json_rejected_before_library_loading(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    discovery: str,
    payload: Document,
) -> None:
    path = tmp_path / "application_default_credentials.json"
    path.write_text(json.dumps(payload))
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(tmp_path))
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    gcp = config.gcp
    if discovery == "file":
        gcp = replace(gcp, auth=replace(gcp.auth, mode="file", credentials_file=path))
    elif discovery == "environment":
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(path))
    service_loader, user_loader = Mock(), Mock()
    monkeypatch.setattr(
        auth.service_account.Credentials, "from_service_account_info", service_loader
    )
    monkeypatch.setattr(
        auth.user_credentials.Credentials, "from_authorized_user_info", user_loader
    )
    with pytest.raises(PiccoloError):
        auth.credentials(gcp)
    service_loader.assert_not_called()
    user_loader.assert_not_called()


@pytest.mark.parametrize("payload", ["{", "[]", '{"type": "authorized_user"}'])
def test_invalid_json_and_missing_fields_are_user_errors(
    config: Config,
    tmp_path: Path,
    payload: str,
) -> None:
    path = tmp_path / "invalid.json"
    path.write_text(payload)
    gcp = replace(
        config.gcp, auth=replace(config.gcp.auth, mode="file", credentials_file=path)
    )
    with pytest.raises(PiccoloError):
        auth.credentials(gcp)


def test_user_adc_and_explicit_impersonation_without_refresh(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(tmp_path))
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_QUOTA_PROJECT", raising=False)
    path = tmp_path / "application_default_credentials.json"
    path.write_text(
        json.dumps(
            {
                "type": "authorized_user",
                "client_id": "dummy.apps.googleusercontent.com",
                "client_secret": "dummy",
                "refresh_token": "dummy",
                "quota_project_id": "quota-project",
            }
        )
    )
    source = auth.credentials(config.gcp)
    assert isinstance(source, user_credentials.Credentials)
    assert source.token_uri == auth.TOKEN_URI
    assert source.quota_project_id == "quota-project"
    assert source.token is None
    gcp = replace(
        config.gcp,
        auth=replace(
            config.gcp.auth,
            impersonate_service_account="provisioner@test-project.iam.gserviceaccount.com",
        ),
    )
    target = auth.credentials(gcp)
    assert isinstance(target, impersonated_credentials.Credentials)
    assert target.service_account_email == gcp.auth.impersonate_service_account
    assert target.token is None


def test_service_account_uses_type_specific_loader(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "service.json"
    info: Document = {
        "type": "service_account",
        "token_uri": auth.TOKEN_URI,
        "universe_domain": "googleapis.com",
    }
    path.write_text(json.dumps(info))
    source = Mock()
    source.with_quota_project_from_environment.return_value = source
    loader = Mock(return_value=source)
    monkeypatch.setattr(
        auth.service_account.Credentials, "from_service_account_info", loader
    )
    gcp = replace(
        config.gcp, auth=replace(config.gcp.auth, mode="file", credentials_file=path)
    )
    assert auth.credentials(gcp) is source
    loader.assert_called_once_with(info, scopes=auth.SCOPES)


def test_metadata_adc_does_not_load_json(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(tmp_path))
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    source = auth.credentials(config.gcp)
    assert isinstance(source, compute_engine.Credentials)
    assert source.token is None


def test_missing_explicit_adc_never_falls_back(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "missing.json"))
    with pytest.raises(PiccoloError, match="Cannot read"):
        auth.credentials(config.gcp)
