# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""auth.py — Resolve ADC, credential files, and impersonation once per command."""

import google.auth
from google.auth import impersonated_credentials
from google.auth.credentials import Credentials
from google.auth.exceptions import GoogleAuthError

from piccolo.config.models import GCP
from piccolo.errors import PiccoloError

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def credentials(config: GCP) -> Credentials:
    """Resolve the provisioner without deriving the target project from credentials."""
    try:
        if config.auth.credential_file is not None:
            source, _ = google.auth.load_credentials_from_file(
                str(config.auth.credential_file), scopes=SCOPES
            )
        else:
            source, _ = google.auth.default(scopes=SCOPES)
        if config.auth.impersonate_service_account:
            return impersonated_credentials.Credentials(
                source_credentials=source,
                target_principal=config.auth.impersonate_service_account,
                target_scopes=SCOPES,
                lifetime=3600,
            )
        return source
    except GoogleAuthError as exc:
        raise PiccoloError(f"SDK authentication failed: {exc}") from exc
