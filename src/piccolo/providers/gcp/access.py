# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""access.py — API prerequisites and additive, etag-protected IAM grants."""

import ipaddress
import time
import uuid
from collections.abc import Callable

from google.api_core import exceptions
from google.cloud import compute_v1, iam_admin_v1, service_usage_v1
from google.iam.v1 import iam_policy_pb2, options_pb2, policy_pb2

from piccolo.config.models import Config, privileged_role
from piccolo.data import Document, Value, decode, document, objects, text
from piccolo.errors import PiccoloError, UncertainError
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.permissions import permission_error
from piccolo.providers.gcp.resources import READ_RETRY
from piccolo.state.journal import Journal


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

    def __init__(
        self, config: Config, clients: Clients, journal: Journal | None = None
    ) -> None:
        """Record provider configuration and authenticated clients."""
        self.config = config
        self.gcp = config.gcp
        self.clients = clients
        self.journal = journal

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
        required_role = "roles/browser"
        try:
            project = self.clients.projects.get_project(
                name=f"projects/{self.gcp.project_id}", retry=READ_RETRY, timeout=30
            )
            apis: list[Value] = []
            for api in sorted(self.required_apis()):
                required_role = "roles/serviceusage.serviceUsageViewer"
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
                required_role = "roles/iam.serviceAccountViewer"
                account = self.clients.iam.get_service_account(
                    name=f"projects/-/serviceAccounts/{self.gcp.service_account}",
                    retry=READ_RETRY,
                    timeout=30,
                )
                sa_disabled = account.disabled
            except exceptions.NotFound:
                sa_exists = False
            required_role = "roles/iam.securityReviewer"
            guest_policy = self.guest_iam(project.parent)
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
                required_role = (
                    "roles/secretmanager.viewer"
                    if secret
                    else "roles/iam.securityReviewer"
                )
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
                present = any(
                    binding.role == role
                    and member in binding.members
                    and not binding.HasField("condition")
                    for binding in policy.bindings
                )
                conditional = any(
                    binding.role == role
                    and member in binding.members
                    and binding.HasField("condition")
                    for binding in policy.bindings
                )
                if not present:
                    missing.append(
                        {
                            "resource": resource,
                            "role": role,
                            "member": member,
                            "conditional_only": conditional,
                            "will_grant": not conditional,
                        }
                    )
            rule: Document = {"name": self.gcp.firewall_name, "exists": False}
            try:
                required_role = "roles/compute.networkViewer"
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
                "guest_iam": guest_policy,
                "network_policy": self.network_policy(),
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
        except exceptions.Forbidden as exc:
            raise permission_error(
                self.clients.principal,
                required_role,
                f"projects/{self.gcp.project_id}",
            ) from exc
        except exceptions.GoogleAPICallError as exc:
            raise PiccoloError(f"Cannot inspect access resources: {exc}") from exc

    def ensure(self) -> None:
        """Inspect APIs and apply only explicitly declared additive grants."""
        network = self.network_policy()
        if self.clients.principal == self.gcp.service_account:
            raise PiccoloError("Provisioner and guest service accounts must differ")
        if self.gcp.via_iap and network.get("unsafe_ingress"):
            raise PiccoloError(
                "Effective firewall policy permits non-IAP ingress: "
                f"{network['unsafe_ingress']}. "
                "Review network policy before provisioning."
            )
        required_role = "roles/browser"
        try:
            project = self.clients.projects.get_project(
                name=f"projects/{self.gcp.project_id}", retry=READ_RETRY, timeout=30
            )
            required_role = "roles/iam.securityReviewer"
            guest_policy = self.guest_iam(project.parent)
            if guest_policy.get("privileged_roles"):
                raise PiccoloError(
                    "Guest account already has privileged IAM roles: "
                    f"{guest_policy['privileged_roles']}; review direct and inherited "
                    "grants before provisioning"
                )
            number = project.name.split("/")[-1]
            for api in sorted(self.required_apis()):
                name = f"projects/{number}/services/{api}"
                required_role = "roles/serviceusage.serviceUsageViewer"
                service = self.clients.services.get_service(
                    request=service_usage_v1.GetServiceRequest(name=name),
                    retry=READ_RETRY,
                    timeout=30,
                )
                if (
                    service.state != service_usage_v1.State.ENABLED
                    and not self.gcp.enable_apis
                ):
                    raise PiccoloError(
                        f"Required API {api} is disabled; enable it "
                        f"explicitly or set gcp.enable_apis=true"
                    )
                self.api(name)
            required_role = "roles/iam.serviceAccountViewer"
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
        except exceptions.Forbidden as exc:
            raise permission_error(
                self.clients.principal,
                required_role,
                f"projects/{self.gcp.project_id}",
            ) from exc
        except (exceptions.GoogleAPICallError, TimeoutError) as exc:
            raise PiccoloError(f"Access reconciliation failed: {exc}") from exc

    def guest_iam(self, parent: str) -> Document:
        """Report direct ancestor grants and reject unsafe custom-role permissions."""
        scopes = [f"projects/{self.gcp.project_id}"]
        current = parent
        visited: set[str] = set()
        while current:
            if current in visited:
                raise PiccoloError("IAM ancestor hierarchy contains a cycle")
            visited.add(current)
            scopes.append(current)
            if current.startswith("folders/"):
                current = self.clients.folders.get_folder(
                    name=current, retry=READ_RETRY, timeout=30
                ).parent
            elif current.startswith("organizations/"):
                current = ""
            else:
                raise PiccoloError("Unsupported project IAM parent")
        roles: list[Value] = []
        privileged: list[Value] = []
        member = f"serviceAccount:{self.gcp.service_account}"
        for scope in scopes:
            if scope.startswith("projects/"):
                client = self.clients.projects
            elif scope.startswith("folders/"):
                client = self.clients.folders
            else:
                client = self.clients.organizations
            policy = client.get_iam_policy(
                request=iam_policy_pb2.GetIamPolicyRequest(
                    resource=scope,
                    options=options_pb2.GetPolicyOptions(requested_policy_version=3),
                ),
                retry=READ_RETRY,
                timeout=30,
            )
            for binding in policy.bindings:
                if member not in binding.members and not any(
                    value in binding.members
                    for value in ("allUsers", "allAuthenticatedUsers")
                ):
                    continue
                record: Document = {
                    "resource": scope,
                    "role": binding.role,
                    "conditional": binding.HasField("condition"),
                }
                roles.append(record)
                if privileged_role(binding.role) or self.unsafe_custom_role(
                    binding.role
                ):
                    privileged.append(record)
        for role in self.gcp.project_roles:
            if self.unsafe_custom_role(role):
                raise PiccoloError(
                    f"Configured guest custom role {role} "
                    "contains privileged IAM permissions"
                )
        return {
            "roles": roles,
            "privileged_roles": privileged,
            "coverage": (
                "Direct service-account and public grants at project, folder and "
                "organization "
                "scopes; group membership and IAM conditions require operator review."
            ),
        }

    def unsafe_custom_role(self, role: str) -> bool:
        """Inspect custom definitions before permitting guest privilege delegation."""
        if role.startswith("roles/"):
            return False
        definition = self.clients.iam.get_role(
            request=iam_admin_v1.GetRoleRequest(name=role), retry=READ_RETRY, timeout=30
        )
        token_permissions = {
            "iam.serviceAccounts.getAccessToken",
            "iam.serviceAccounts.getOpenIdToken",
        }
        return any(
            permission.endswith(".setIamPolicy")
            or permission in token_permissions
            or (
                permission.startswith(("iam.", "resourcemanager.", "compute."))
                and not permission.rsplit(".", 1)[-1].startswith(("get", "list"))
            )
            for permission in definition.included_permissions
        )

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

        def observe() -> str:
            try:
                current = self.clients.iam.get_service_account(
                    name=name, retry=READ_RETRY, timeout=30
                )
                if current.disabled:
                    raise PiccoloError("The configured VM service account is disabled")
                if not current.unique_id:
                    raise PiccoloError("Service account lacks an immutable unique ID")
                return current.unique_id
            except exceptions.NotFound:
                return ""

        def submit() -> str:
            if not self.gcp.create_service_account:
                raise PiccoloError(
                    "Account disappeared; explicit account creation is required"
                )
            try:
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
            except exceptions.Forbidden as exc:
                raise permission_error(
                    self.clients.principal, "roles/iam.serviceAccountAdmin", name
                ) from exc
            return ""

        self.mutation(f"service-account:{self.gcp.service_account}", submit, observe)

    def remember(self, key: str, operation_id: str) -> None:
        """Persist a returned long-running operation before awaiting its result."""
        if self.journal is None:
            raise PiccoloError("Missing access journal")
        operation = self.journal.operation
        actions = objects(operation, "access_actions")
        for action in actions:
            if action.get("key") == key:
                action["operation_id"] = operation_id
                action["status"] = "submitted"
        operation["access_actions"] = [item for item in actions]
        self.journal.update(operation)

    def api(self, name: str) -> None:
        """Record API enablement and retain uncertain outcomes without resubmission."""
        key = f"api:{name}"

        def observe() -> str:
            service = self.clients.services.get_service(
                request=service_usage_v1.GetServiceRequest(name=name),
                retry=READ_RETRY,
                timeout=30,
            )
            return name if service.state == service_usage_v1.State.ENABLED else ""

        def submit() -> str:
            try:
                result = self.clients.services.enable_service(
                    request=service_usage_v1.EnableServiceRequest(name=name),
                    retry=None,
                    timeout=30,
                )
                self.remember(key, result.operation.name)
                result.result(timeout=self.gcp.operation_timeout)
                return result.operation.name
            except exceptions.Forbidden as exc:
                raise permission_error(
                    self.clients.principal, "roles/serviceusage.serviceUsageAdmin", name
                ) from exc

        self.mutation(key, submit, observe)

    def grant(self, resource: str, role: str, *, secret: bool) -> None:
        """Journal additive IAM grants, requiring etags and preserving conditions."""
        member = f"serviceAccount:{self.gcp.service_account}"
        client = self.clients.secrets if secret else self.clients.projects
        policy_role = (
            "roles/secretmanager.admin"
            if secret
            else "roles/resourcemanager.projectIamAdmin"
        )

        def read() -> policy_pb2.Policy:
            try:
                return client.get_iam_policy(
                    request=iam_policy_pb2.GetIamPolicyRequest(
                        resource=resource,
                        options=options_pb2.GetPolicyOptions(
                            requested_policy_version=3
                        ),
                    ),
                    retry=READ_RETRY,
                    timeout=30,
                )
            except exceptions.Forbidden as exc:
                raise permission_error(
                    self.clients.principal,
                    "roles/secretmanager.viewer"
                    if secret
                    else "roles/iam.securityReviewer",
                    resource,
                ) from exc

        def observe() -> str:
            policy = read()
            if any(
                binding.role == role
                and member in binding.members
                and not binding.HasField("condition")
                for binding in policy.bindings
            ):
                return f"{resource}:{role}:{member}"
            if any(
                binding.role == role
                and member in binding.members
                and binding.HasField("condition")
                for binding in policy.bindings
            ):
                raise PiccoloError(
                    f"Conditional-only IAM access for {member} and {role} "
                    f"on {resource}; "
                    "refusing to create an unconditional grant. Review it manually."
                )
            return ""

        def submit() -> str:
            deadline = time.monotonic() + 60
            conflicts = 0
            while True:
                policy = read()
                if not policy.etag:
                    raise PiccoloError(
                        "IAM policy has no etag; refusing an unprotected write"
                    )
                # Recheck conditions after every concurrent policy change.
                if any(
                    binding.role == role
                    and member in binding.members
                    and binding.HasField("condition")
                    for binding in policy.bindings
                ) and not any(
                    binding.role == role
                    and member in binding.members
                    and not binding.HasField("condition")
                    for binding in policy.bindings
                ):
                    raise PiccoloError(
                        "Conditional-only IAM access changed during reconciliation; "
                        "refusing to widen it"
                    )
                if not add_binding(policy, role, member):
                    return ""
                try:
                    client.set_iam_policy(
                        request=iam_policy_pb2.SetIamPolicyRequest(
                            resource=resource, policy=policy
                        ),
                        retry=None,
                        timeout=30,
                    )
                    return ""
                except exceptions.Forbidden as exc:
                    raise permission_error(
                        self.clients.principal, policy_role, resource
                    ) from exc
                except (exceptions.Aborted, exceptions.Conflict):
                    conflicts += 1
                    if conflicts == 3:
                        raise
                    time.sleep(0.25 * 2 ** (conflicts - 1))
                except exceptions.InvalidArgument as exc:
                    if time.monotonic() >= deadline or not self.account_propagating(
                        exc
                    ):
                        raise
                    time.sleep(min(2, max(0, deadline - time.monotonic())))

        self.mutation(
            f"iam:{resource}:{role}:{member}",
            submit,
            observe,
            recover=lambda _: submit(),
        )

    def account_propagating(self, error: exceptions.InvalidArgument) -> bool:
        """Retry a rejected grant only for the journaled newly created identity."""
        account = self.gcp.service_account
        if (
            not self.gcp.create_service_account
            or f"service account {account} does not exist" not in str(error).lower()
            or self.journal is None
        ):
            return False
        action = next(
            (
                a
                for a in objects(self.journal.operation, "access_actions")
                if text(a, "key") == f"service-account:{account}"
            ),
            None,
        )
        if (
            action is None
            or action.get("preexisting") is not False
            or text(action, "status") != "done"
            or not text(action, "resource_id")
        ):
            return False
        try:
            observed = self.clients.iam.get_service_account(
                name=f"projects/{self.gcp.project_id}/serviceAccounts/{account}",
                retry=READ_RETRY,
                timeout=30,
            )
        except exceptions.NotFound:
            return False
        return (
            observed.unique_id == text(action, "resource_id") and not observed.disabled
        )

    def mutation(
        self,
        key: str,
        submit: Callable[[], str],
        observe: Callable[[], str],
        *,
        recover: Callable[[Document], str] | None = None,
    ) -> None:
        """Journal each access intent and reconcile before repeating a mutation."""
        if self.journal is None or not self.journal.operation:
            raise PiccoloError("Access mutations require an active operation journal")
        operation = self.journal.operation
        actions = objects(operation, "access_actions")
        action: Document | None = next(
            (item for item in actions if item.get("key") == key), None
        )
        identity = observe()
        if action is None:
            action = {
                "key": key,
                "request_id": str(uuid.uuid4()),
                "status": "preexisting" if identity else "intent",
                "preexisting": bool(identity),
                "resource_id": identity,
            }
            actions.append(action)
            operation["access_actions"] = [item for item in actions]
            self.journal.update(operation)
            if identity:
                return
        elif identity:
            recorded = text(action, "resource_id")
            if recorded and recorded != identity:
                raise PiccoloError(f"Access resource identity changed: {key}")
            action["resource_id"] = identity
            action["status"] = (
                "done" if not action.get("preexisting") else "preexisting"
            )
            operation["access_actions"] = [item for item in actions]
            self.journal.update(operation)
            return
        elif text(action, "status") in {"done", "preexisting"}:
            raise UncertainError(
                f"Access resource disappeared or remains uncertain: {key}; "
                "inspect access_actions"
            )
        elif text(action, "status") != "failed":
            if recover is None:
                raise UncertainError(
                    f"Access submission remains uncertain: {key}; "
                    "preserve access_actions and inspect manually"
                )
            action["operation_id"] = recover(action)
            operation["access_actions"] = [item for item in actions]
            self.journal.update(operation)
            identity = observe()
            if not identity:
                raise UncertainError(
                    f"Access operation completed without its resource: {key}"
                )
            action["resource_id"] = identity
            action["status"] = "done"
            operation["access_actions"] = [item for item in actions]
            self.journal.update(operation)
            return
        try:
            action["operation_id"] = submit()
            action["status"] = "submitted"
            operation["access_actions"] = [item for item in actions]
            self.journal.update(operation)
            identity = observe()
            if not identity:
                raise UncertainError(f"Access mutation cannot be verified: {key}")
            action["resource_id"] = identity
            action["status"] = "done"
        except PiccoloError as exc:
            latest = next(
                item
                for item in objects(self.journal.operation, "access_actions")
                if item.get("key") == key
            )
            if latest.get("operation_id"):
                action["operation_id"] = latest["operation_id"]
            action["status"] = (
                "failed"
                if isinstance(exc.__cause__, exceptions.Forbidden)
                else "uncertain"
            )
            action["error"] = str(exc)
            raise
        except (exceptions.GoogleAPICallError, TimeoutError, OSError) as exc:
            latest = next(
                item
                for item in objects(self.journal.operation, "access_actions")
                if item.get("key") == key
            )
            if latest.get("operation_id"):
                action["operation_id"] = latest["operation_id"]
            action["error"] = str(exc)
            action["status"] = "uncertain"
            raise UncertainError(
                f"Access mutation uncertain: {key}; inspect access_actions"
            ) from exc
        finally:
            latest = next(
                item
                for item in objects(self.journal.operation, "access_actions")
                if item.get("key") == key
            )
            if latest.get("operation_id") and not action.get("operation_id"):
                action["operation_id"] = latest["operation_id"]
                if action.get("status") == "intent":
                    action["status"] = latest["status"]
            operation["access_actions"] = [item for item in actions]
            self.journal.update(operation)

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
        """Persist firewall UUID and operation; reconcile before permitting creation."""
        key = f"firewall:{self.gcp.firewall_name}"

        def observe() -> str:
            try:
                current = self.clients.firewalls.get(
                    project=self.gcp.project_id,
                    firewall=self.gcp.firewall_name,
                    retry=READ_RETRY,
                    timeout=30,
                )
            except exceptions.NotFound:
                return ""
            if not self.firewall_matches(current) or not current.id:
                raise PiccoloError(
                    f"Firewall drift or missing identity for {self.gcp.firewall_name}; "
                    "inspect before changing it"
                )
            return str(current.id)

        def submit() -> str:
            if self.journal is None:
                raise PiccoloError("Missing access journal")
            action = next(
                item
                for item in objects(self.journal.operation, "access_actions")
                if item.get("key") == key
            )
            try:
                result = self.clients.firewalls.insert(
                    request=compute_v1.InsertFirewallRequest(
                        project=self.gcp.project_id,
                        firewall_resource=self.firewall_spec(),
                        request_id=text(action, "request_id"),
                    ),
                    retry=None,
                    timeout=30,
                )
                self.remember(key, str(result.name))
                result.result(timeout=self.gcp.operation_timeout)
                return str(result.name)
            except exceptions.Forbidden as exc:
                raise permission_error(
                    self.clients.principal,
                    "roles/compute.securityAdmin",
                    f"projects/{self.gcp.project_id}",
                ) from exc

        def recover(action: Document) -> str:
            from piccolo.providers.gcp.operations import failure
            from piccolo.providers.gcp.resources import SDKCloud

            cloud = SDKCloud(self.config, self.clients)
            operation_id = text(action, "operation_id") or cloud.recover(
                text(action, "request_id"), ""
            )
            if not operation_id:
                raise UncertainError(
                    "Firewall request remains unknown; "
                    "retain journal and inspect before retrying"
                )
            self.remember(key, operation_id)
            deadline = time.monotonic() + self.gcp.operation_timeout
            while time.monotonic() < deadline:
                result = cloud.poll(operation_id, "")
                if text(result, "status") == "DONE":
                    error = failure(result)
                    if error:
                        raise error
                    return operation_id
                time.sleep(1)
            raise UncertainError("Firewall operation remains pending; run resume")

        self.mutation(key, submit, observe, recover=recover)

    def network_policy(self, instance: Document | None = None) -> Document:
        """Inspect effective VPC and inherited policy ingress, conservatively."""
        try:
            if instance is None:
                response = self.clients.networks.get_effective_firewalls(
                    project=self.gcp.project_id,
                    network=self.gcp.network,
                    retry=READ_RETRY,
                    timeout=30,
                )
                policy = decode(
                    compute_v1.NetworksGetEffectiveFirewallsResponse.to_json(
                        response, preserving_proto_field_name=True
                    )
                )
            else:
                from piccolo.providers.gcp.provision import zone_of

                observed = self.clients.instances.get_effective_firewalls(
                    project=self.gcp.project_id,
                    zone=zone_of(instance),
                    instance=self.gcp.name,
                    network_interface="nic0",
                    retry=READ_RETRY,
                    timeout=30,
                )
                policy = decode(
                    compute_v1.InstancesGetEffectiveFirewallsResponse.to_json(
                        observed, preserving_proto_field_name=True
                    )
                )
        except exceptions.Forbidden as exc:
            raise permission_error(
                self.clients.principal,
                "roles/compute.networkViewer",
                f"projects/{self.gcp.project_id}",
            ) from exc
        except exceptions.GoogleAPICallError as exc:
            raise PiccoloError(
                f"Cannot inspect effective firewall policy: {exc}"
            ) from exc
        unsafe: list[Value] = []

        def check(rule: Document, *, hierarchical: bool) -> None:
            if rule.get("disabled") or text(rule, "direction", "INGRESS") != "INGRESS":
                return
            if hierarchical and text(rule, "action") not in {
                "allow",
                "apply_security_profile_group",
            }:
                return
            accounts = rule.get("target_service_accounts", [])
            if (
                isinstance(accounts, list)
                and accounts
                and self.gcp.service_account not in accounts
            ):
                return
            match = document(rule.get("match", {})) if hierarchical else rule
            layers = objects(match, "layer4_configs" if hierarchical else "allowed")
            relevant = False
            for layer in layers:
                protocol = text(
                    layer, "ip_protocol" if hierarchical else "I_p_protocol"
                )
                if protocol not in {"tcp", "6", "all", ""}:
                    continue
                ports = layer.get("ports", [])
                if not ports:
                    relevant = True
                elif isinstance(ports, list):
                    for port in ports:
                        if not isinstance(port, str):
                            relevant = True
                            continue
                        start, _, end = port.partition("-")
                        if (
                            not start.isdecimal()
                            or (end and not end.isdecimal())
                            or any(
                                int(start) <= required <= int(end or start)
                                for required in self.gcp.ports
                            )
                        ):
                            relevant = True
            if not layers and hierarchical:
                relevant = True
            if not relevant:
                return
            ranges = match.get("src_ip_ranges" if hierarchical else "source_ranges", [])
            safe = bool(ranges) and isinstance(ranges, list)
            if isinstance(ranges, list):
                for source in ranges:
                    try:
                        safe = (
                            safe
                            and isinstance(source, str)
                            and ipaddress.IPv4Network(source).subnet_of(
                                ipaddress.IPv4Network("35.235.240.0/20")
                            )
                        )
                    except ValueError:
                        safe = False
            if any(
                match.get(key)
                for key in (
                    "source_tags",
                    "source_service_accounts",
                    "src_secure_tags",
                    "src_address_groups",
                    "src_fqdns",
                    "src_networks",
                    "src_network_context",
                    "src_network_type",
                    "src_region_codes",
                    "src_threat_intelligences",
                )
            ):
                safe = False
            if not safe:
                unsafe.append(
                    {
                        "name": text(rule, "name", text(rule, "rule_name")),
                        "priority": rule.get("priority"),
                        "source_ranges": ranges,
                    }
                )

        for rule in objects(policy, "firewalls"):
            check(rule, hierarchical=False)
        for inherited in objects(policy, "firewall_policys"):
            for rule in objects(inherited, "rules"):
                check(rule, hierarchical=True)
        return {
            "unsafe_ingress": unsafe,
            "external_ip": self.gcp.external_ip,
            "egress": (
                "Private guests require Cloud NAT or another outbound route "
                "for package downloads; IAP provides ingress only."
            ),
        }

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
