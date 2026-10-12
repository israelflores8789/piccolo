# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""clients.py — SDK client bundle with one explicitly resolved identity."""

from google.auth.credentials import Credentials
from google.cloud import (
    compute_v1,
    iam_admin_v1,
    resourcemanager_v3,
    secretmanager_v1,
    service_usage_v1,
)


class Clients:
    """Hold the service-specific clients used by the GCP adapter."""

    def __init__(self, credentials: Credentials) -> None:
        """Construct clients sharing the provisioner's credentials."""
        self.credentials = credentials
        self.instances = compute_v1.InstancesClient(credentials=credentials)
        self.compute_projects = compute_v1.ProjectsClient(credentials=credentials)
        self.disks = compute_v1.DisksClient(credentials=credentials)
        self.snapshots = compute_v1.SnapshotsClient(credentials=credentials)
        self.firewalls = compute_v1.FirewallsClient(credentials=credentials)
        self.networks = compute_v1.NetworksClient(credentials=credentials)
        self.subnets = compute_v1.SubnetworksClient(credentials=credentials)
        self.zone_operations = compute_v1.ZoneOperationsClient(credentials=credentials)
        self.global_operations = compute_v1.GlobalOperationsClient(
            credentials=credentials
        )
        self.projects = resourcemanager_v3.ProjectsClient(credentials=credentials)
        self.folders = resourcemanager_v3.FoldersClient(credentials=credentials)
        self.organizations = resourcemanager_v3.OrganizationsClient(
            credentials=credentials
        )
        self.secrets = secretmanager_v1.SecretManagerServiceClient(
            credentials=credentials
        )
        self.iam = iam_admin_v1.IAMClient(credentials=credentials)
        self.services = service_usage_v1.ServiceUsageClient(credentials=credentials)

    @property
    def principal(self) -> str:
        """Read the acting identity from ordinary SDK authentication results."""
        identity: object = getattr(self.credentials, "service_account_email", "")
        if isinstance(identity, str) and identity not in {"", "default"}:
            return identity
        return "configured ADC/file provisioner"
