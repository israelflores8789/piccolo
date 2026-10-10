# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""models.py — Immutable provider-neutral and GCP configuration models."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Auth:
    """Separate SDK credentials from the selected gcloud connection account."""

    mode: str
    credential_file: Path | None
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


@dataclass(frozen=True)
class Config:
    """Describe an environment and its provider-specific desired state."""

    path: Path
    environment: str
    provider: str
    gcp: GCP
    bootstrap: Bootstrap | None
    fingerprint: str
