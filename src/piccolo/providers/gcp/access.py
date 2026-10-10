# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""access.py — API prerequisites and additive, etag-protected IAM grants."""

import time

from google.api_core import exceptions
from google.cloud import compute_v1, iam_admin_v1, service_usage_v1
from google.iam.v1 import iam_policy_pb2, options_pb2, policy_pb2

from piccolo.config.models import Config
from piccolo.data import Document, Value, decode
from piccolo.errors import PiccoloError, UncertainError
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.resources import READ_RETRY


def add_binding(policy: policy_pb2.Policy, role: str, member: str) -> bool:
    """Add an unconditional grant while preserving etag and conditional bindings."""
    for binding in policy.bindings:
        if binding.role == role and not binding.HasField("condition"):
            if member in binding.members:
                return False
            binding.members.append(member)
            return True
    policy.bindings.add(role=role, members=[member])
    return True


class Access:
    """Reconcile supported access resources before provisioning a VM."""

    def __init__(self, config: Config, clients: Clients) -> None:
        """Record provider configuration and authenticated clients."""
        self.config = config
        self.gcp = config.gcp
        self.clients = clients

    def required_apis(self) -> set[str]:
        """Return the provisioning API baseline for the configured features."""
        services = {
            "compute.googleapis.com",
            "cloudresourcemanager.googleapis.com",
            "iam.googleapis.com",
            "serviceusage.googleapis.com",
        }
        if self.gcp.secrets:
            services.add("secretmanager.googleapis.com")
        if self.gcp.auth.impersonate_service_account:
            services.add("iamcredentials.googleapis.com")
        return services

    def inspect(self) -> Document:
        """Inspect access state and missing unconditional grants without mutations."""
        try:
            project = self.clients.projects.get_project(
                name=f"projects/{self.gcp.project_id}", retry=READ_RETRY, timeout=30
            )
            apis: list[Value] = []
            for api in sorted(self.required_apis()):
                service = self.clients.services.get_service(
                    request=service_usage_v1.GetServiceRequest(
                        name=f"{project.name}/services/{api}"
                    ),
                    retry=READ_RETRY,
                    timeout=30,
                )
                enabled = service.state == service_usage_v1.State.ENABLED
                apis.append(
                    {
                        "name": api,
                        "enabled": enabled,
                        "will_enable": not enabled and self.gcp.enable_apis,
                    }
                )
            sa_exists = True
            sa_disabled = False
            try:
                account = self.clients.iam.get_service_account(
                    name=f"projects/-/serviceAccounts/{self.gcp.service_account}",
                    retry=READ_RETRY,
                    timeout=30,
                )
                sa_disabled = account.disabled
            except exceptions.NotFound:
                sa_exists = False
            grants: list[tuple[str, str, bool]] = [
                (f"projects/{self.gcp.project_id}", role, False)
                for role in self.gcp.project_roles
            ]
            grants.extend(
                (
                    f"projects/{self.gcp.project_id}/secrets/{secret}",
                    "roles/secretmanager.secretAccessor",
                    True,
                )
                for secret in self.gcp.secrets
            )
            missing: list[Value] = []
            for resource, role, secret in grants:
                client = self.clients.secrets if secret else self.clients.projects
                policy = client.get_iam_policy(
                    request=iam_policy_pb2.GetIamPolicyRequest(
                        resource=resource,
                        options=options_pb2.GetPolicyOptions(
                            requested_policy_version=3
                        ),
                    ),
                    retry=READ_RETRY,
                    timeout=30,
                )
                member = f"serviceAccount:{self.gcp.service_account}"
                if add_binding(policy, role, member):
                    missing.append(
                        {"resource": resource, "role": role, "member": member}
                    )
            rule: Document = {"name": self.gcp.firewall_name, "exists": False}
            try:
                existing = self.clients.firewalls.get(
                    project=self.gcp.project_id,
                    firewall=self.gcp.firewall_name,
                    retry=READ_RETRY,
                    timeout=30,
                )
                rule["exists"] = True
                rule["matches"] = self.firewall_matches(existing)
            except exceptions.NotFound:
                rule["will_create"] = True
            return {
                "apis": apis,
                "missing_grants": missing,
                "firewall": rule,
                "service_account": {
                    "email": self.gcp.service_account,
                    "exists": sa_exists,
                    "disabled": sa_disabled,
                    "will_create": not sa_exists and self.gcp.create_service_account,
                },
            }
        except exceptions.GoogleAPICallError as exc:
            raise PiccoloError(f"Cannot inspect access resources: {exc}") from exc

    def ensure(self) -> None:
        """Inspect APIs and apply only explicitly declared additive grants."""
        try:
            project = self.clients.projects.get_project(
                name=f"projects/{self.gcp.project_id}", retry=READ_RETRY, timeout=30
            )
            number = project.name.split("/")[-1]
            for api in sorted(self.required_apis()):
                name = f"projects/{number}/services/{api}"
                service = self.clients.services.get_service(
                    request=service_usage_v1.GetServiceRequest(name=name),
                    retry=READ_RETRY,
                    timeout=30,
                )
                if service.state != service_usage_v1.State.ENABLED:
                    if not self.gcp.enable_apis:
                        raise PiccoloError(
                            f"Required API {api} is disabled; enable it "
                            f"explicitly or set gcp.enable_apis=true"
                        )
                    self.clients.services.enable_service(
                        request=service_usage_v1.EnableServiceRequest(name=name),
                        retry=None,
                        timeout=30,
                    ).result(timeout=self.gcp.operation_timeout)
            self.service_account()
            for role in self.gcp.project_roles:
                self.grant(f"projects/{self.gcp.project_id}", role, secret=False)
            for secret in self.gcp.secrets:
                self.grant(
                    f"projects/{self.gcp.project_id}/secrets/{secret}",
                    "roles/secretmanager.secretAccessor",
                    secret=True,
                )
            self.firewall()
        except (exceptions.GoogleAPICallError, TimeoutError) as exc:
            raise PiccoloError(f"Access reconciliation failed: {exc}") from exc

    def service_account(self) -> None:
        """Inspect the attached VM account or explicitly create it without keys."""
        name = f"projects/-/serviceAccounts/{self.gcp.service_account}"
        try:
            account = self.clients.iam.get_service_account(
                name=name, retry=READ_RETRY, timeout=30
            )
            if account.disabled:
                raise PiccoloError("The configured VM service account is disabled")
        except exceptions.NotFound as exc:
            if not self.gcp.create_service_account:
                raise PiccoloError(
                    "VM service account does not exist; create it "
                    "or set gcp.iam.create_service_account=true"
                ) from exc
            self.clients.iam.create_service_account(
                request=iam_admin_v1.CreateServiceAccountRequest(
                    name=f"projects/{self.gcp.project_id}",
                    account_id=self.gcp.service_account.split("@")[0],
                    service_account=iam_admin_v1.ServiceAccount(
                        display_name=f"Piccolo {self.config.environment}"
                    ),
                ),
                retry=None,
                timeout=30,
            )

    def grant(self, resource: str, role: str, *, secret: bool) -> None:
        """Merge IAM policy with version three and retry concurrent etag conflicts."""
        member = f"serviceAccount:{self.gcp.service_account}"
        for attempt in range(3):
            request = iam_policy_pb2.GetIamPolicyRequest(
                resource=resource,
                options=options_pb2.GetPolicyOptions(requested_policy_version=3),
            )
            client = self.clients.secrets if secret else self.clients.projects
            policy = client.get_iam_policy(
                request=request, retry=READ_RETRY, timeout=30
            )
            if not add_binding(policy, role, member):
                return
            try:
                client.set_iam_policy(
                    request=iam_policy_pb2.SetIamPolicyRequest(
                        resource=resource, policy=policy
                    ),
                    retry=None,
                    timeout=30,
                )
                return
            except (exceptions.Aborted, exceptions.Conflict):
                if attempt == 2:
                    raise
                time.sleep(0.25 * 2**attempt)

    def firewall_spec(self) -> compute_v1.Firewall:
        """Build the exact desired VM-account-scoped IAP rule."""
        return compute_v1.Firewall(
            name=self.gcp.firewall_name,
            description=f"Piccolo {self.gcp.project_id}/{self.config.environment}",
            network=f"projects/{self.gcp.project_id}/global/networks/{self.gcp.network}",
            direction="INGRESS",
            priority=1000,
            source_ranges=list(self.gcp.source_ranges),
            target_service_accounts=[self.gcp.service_account],
            allowed=[
                compute_v1.Allowed(
                    I_p_protocol="tcp",
                    ports=[str(port) for port in sorted(self.gcp.ports)],
                )
            ],
        )

    def firewall(self) -> None:
        """Create a scoped IAP rule or reject unsupported drift."""
        expected = self.firewall_spec()
        try:
            existing = self.clients.firewalls.get(
                project=self.gcp.project_id,
                firewall=self.gcp.firewall_name,
                retry=READ_RETRY,
                timeout=30,
            )
        except exceptions.NotFound:
            try:
                self.clients.firewalls.insert(
                    project=self.gcp.project_id,
                    firewall_resource=expected,
                    retry=None,
                    timeout=30,
                ).result(timeout=self.gcp.operation_timeout)
            except (
                exceptions.DeadlineExceeded,
                exceptions.ServiceUnavailable,
                TimeoutError,
            ) as exc:
                raise UncertainError(
                    "Firewall creation is uncertain; resume will inspect it"
                ) from exc
            return
        if not self.firewall_matches(existing):
            details = decode(compute_v1.Firewall.to_json(existing))
            raise PiccoloError(
                f"Firewall drift for {self.gcp.firewall_name}; "
                f"inspect rule before changing it: {details}"
            )

    def firewall_matches(self, existing: compute_v1.Firewall) -> bool:
        """Compare every supported firewall constraint without modifying the rule."""
        expected = self.firewall_spec()
        return not (
            existing.description != expected.description
            or not existing.network.endswith(expected.network)
            or existing.direction != "INGRESS"
            or existing.disabled
            or existing.priority != 1000
            or set(existing.source_ranges) != set(expected.source_ranges)
            or set(existing.target_service_accounts) != {self.gcp.service_account}
            or existing.target_tags
            or existing.source_tags
            or existing.source_service_accounts
            or existing.denied
            or len(existing.allowed) != 1
            or existing.allowed[0].I_p_protocol != "tcp"
            or set(existing.allowed[0].ports) != set(expected.allowed[0].ports)
        )
