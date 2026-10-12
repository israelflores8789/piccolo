# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""auth.py — Validate credential inputs before type-specific SDK loading."""

import os
from pathlib import Path

from google.auth import compute_engine, impersonated_credentials
from google.auth.credentials import Credentials
from google.auth.exceptions import GoogleAuthError
from google.oauth2 import credentials as user_credentials
from google.oauth2 import service_account

from piccolo.config.models import GCP
from piccolo.data import decode, text
from piccolo.errors import PiccoloError

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
TOKEN_URI = "https://oauth2.googleapis.com/token"


def adc_path() -> Path:
    """Locate the well-known ADC file using the Cloud SDK directory rules."""
    override = os.environ.get("CLOUDSDK_CONFIG")
    if override:
        directory = Path(override)
    elif os.name == "nt":
        directory = (
            Path(os.environ.get("APPDATA", os.environ.get("SYSTEMDRIVE", "C:") + "\\"))
            / "gcloud"
        )
    else:
        directory = Path.home() / ".config" / "gcloud"
    return directory / "application_default_credentials.json"


def file_credentials(path: Path) -> Credentials:
    """Load vetted Google user/service-account JSON without refreshing tokens.

    Args:
        path: Operator-controlled credential file from a trusted source.

    Returns:
        User or service-account credentials with fixed Google endpoints.

    Raises:
        PiccoloError: Unsupported types, endpoints, or invalid credential fields.
    """
    try:
        info = decode(path.read_text())
    except (OSError, ValueError) as exc:
        raise PiccoloError("Cannot read SDK credential JSON") from exc
    kind = text(info, "type")
    if kind not in {"service_account", "authorized_user"}:
        raise PiccoloError(
            "Unsupported SDK credential type; use service_account or authorized_user "
            "JSON from a trusted operator, or metadata ADC with explicit impersonation"
        )
    if info.get("universe_domain", "googleapis.com") != "googleapis.com":
        raise PiccoloError("SDK credential universe must be googleapis.com")
    if info.get("token_uri", TOKEN_URI) != TOKEN_URI:
        raise PiccoloError("SDK credential token_uri must be the Google OAuth endpoint")
    if any(
        key in info
        for key in (
            "credential_source",
            "source_credentials",
            "service_account_impersonation_url",
            "token_url",
            "token_info_url",
            "workforce_pool_user_project",
            "trust_boundary",
            "refresh_handler",
        )
    ):
        raise PiccoloError(
            "Unsupported SDK credential source or endpoint configuration"
        )
    try:
        if kind == "service_account":
            source = service_account.Credentials.from_service_account_info(
                info, scopes=SCOPES
            )
        else:
            source = user_credentials.Credentials.from_authorized_user_info(
                info, scopes=SCOPES
            )
        return source.with_quota_project_from_environment()
    except (GoogleAuthError, ValueError, TypeError) as exc:
        raise PiccoloError("Invalid SDK credential fields") from exc


def credentials(config: GCP) -> Credentials:
    """Resolve vetted file/ADC credentials and explicit provisioner impersonation."""
    try:
        path = config.auth.credential_file
        if path is None:
            explicit = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            if explicit:
                path = Path(explicit)
            else:
                local = adc_path()
                path = local if local.exists() else None
        source = (
            file_credentials(path)
            if path is not None
            else compute_engine.Credentials(scopes=SCOPES)
        )
        source_principal: object = getattr(source, "service_account_email", "")
        principal = config.auth.impersonate_service_account or (
            source_principal if isinstance(source_principal, str) else ""
        )
        if principal == config.service_account:
            raise PiccoloError(
                "The provisioner identity must differ from the guest service account"
            )
        if config.auth.impersonate_service_account:
            return impersonated_credentials.Credentials(
                source_credentials=source,
                target_principal=config.auth.impersonate_service_account,
                target_scopes=SCOPES,
                lifetime=3600,
            )
        return source
    except GoogleAuthError as exc:
        raise PiccoloError("SDK authentication failed") from exc
