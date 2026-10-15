# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""models.py — Immutable provider-neutral and GCP configuration models."""

import hashlib
import json
from dataclasses import dataclass, fields, is_dataclass
from pathlib import Path

from piccolo.data import Document, Value, value


def privileged_role(role: str) -> bool:
    """Identify basic, administrative, and credential delegation guest roles."""
    lowered = role.lower()
    return (
        role in {"roles/owner", "roles/editor"}
        or lowered.endswith("admin")
        or ".admin" in lowered
        or "admin." in lowered
        or role
        in {
            "roles/iam.serviceAccountTokenCreator",
            "roles/iam.serviceAccountOpenIdTokenCreator",
            "roles/iam.serviceAccountUser",
            "roles/iam.workloadIdentityUser",
        }
    )


@dataclass(frozen=True)
class Auth:
    """Separate SDK credentials from the selected gcloud connection account."""

    mode: str
    credentials_file: Path | None
    impersonate_service_account: str


@dataclass(frozen=True)
class Bootstrap:
    """Describe an opaque script and its development-user invocation."""

    script: Path
    remote_path: str
    execution_user: str
    timeout: int


@dataclass(frozen=True)
class GCP:
    """Describe supported Compute infrastructure and connection policy."""

    project_id: str
    auth: Auth
    name: str
    machine_type: str
    service_account: str
    zones: tuple[str, ...]
    snapshot_location: str
    size_gb: int
    disk_type: str
    image: str
    network: str
    subnet: str
    subnets: dict[str, str]
    external_ip: bool
    firewall_name: str
    ports: tuple[int, ...]
    source_ranges: tuple[str, ...]
    create_service_account: bool
    secrets: tuple[str, ...]
    project_roles: tuple[str, ...]
    enable_apis: bool
    ssh_user: str
    via_iap: bool
    connection_account: str
    connection_impersonate: str
    readiness_timeout: int
    readiness_command: str
    remote_port: int
    local_port: int
    operation_timeout: int
    internal_ip: bool = False
    require_passphrase: bool = False
    expire_after: str = "24h"


@dataclass(frozen=True)
class Config:
    """Describe an environment and its provider-specific desired state."""

    path: Path
    environment: str
    provider: str
    spinner: str
    gcp: GCP
    bootstrap: Bootstrap | None
    fingerprint: str


def canonical_value(raw: object) -> Value:
    """Convert parsed settings to JSON, preserving significant array order."""
    if isinstance(raw, Path):
        return str(raw)
    if is_dataclass(raw) and not isinstance(raw, type):
        return {
            field.name: canonical_value(getattr(raw, field.name))
            for field in fields(raw)
        }
    if isinstance(raw, tuple):
        return [canonical_value(item) for item in raw]
    return value(raw)


def settings_fingerprint(config: Config) -> str:
    """Hash effective parsed settings independently of source formatting/path."""
    settings: Document = {
        "schema_version": 1,
        "environment": config.environment,
        "provider": config.provider,
        "gcp": canonical_value(config.gcp),
        "bootstrap": canonical_value(config.bootstrap),
    }
    canonical = json.dumps(
        settings, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode()).hexdigest()
