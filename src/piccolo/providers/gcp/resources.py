# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""resources.py — Typed Google SDK resource inspection and mutation adapter."""

import json

from google.api_core import exceptions, retry
from google.cloud import compute_v1, resourcemanager_v3

from piccolo.config.models import Config
from piccolo.data import Document, decode, text
from piccolo.errors import PiccoloError, UncertainError
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.permissions import permission_error
from piccolo.state.journal import Journal

READ_RETRY = retry.Retry(initial=1, maximum=8, deadline=30)


class SDKCloud:
    """Use SDK APIs exclusively for Compute and access operations."""

    def __init__(self, config: Config, clients: Clients) -> None:
        """Bind a client bundle to an explicit project."""
        self.config = config
        self.clients = clients
        self.project = config.gcp.project_id
        self.journal: Journal | None = None

    def get(self, kind: str, name: str, zone: str = "") -> Document | None:
        """Get one resource, treating only NotFound as absence."""
        try:
            match kind:
                case "instance":
                    result = self.clients.instances.get(
                        project=self.project,
                        zone=zone,
                        instance=name,
                        retry=READ_RETRY,
                        timeout=30,
                    )
                    return decode(
                        compute_v1.Instance.to_json(
                            result,
                            preserving_proto_field_name=True,
                            use_integers_for_enums=False,
                        )
                    )
                case "disk":
                    disk = self.clients.disks.get(
                        project=self.project,
                        zone=zone,
                        disk=name,
                        retry=READ_RETRY,
                        timeout=30,
                    )
                    return decode(
                        compute_v1.Disk.to_json(
                            disk,
                            preserving_proto_field_name=True,
                            use_integers_for_enums=False,
                        )
                    )
                case "snapshot":
                    snapshot = self.clients.snapshots.get(
                        project=self.project,
                        snapshot=name,
                        retry=READ_RETRY,
                        timeout=30,
                    )
                    return decode(
                        compute_v1.Snapshot.to_json(
                            snapshot,
                            preserving_proto_field_name=True,
                            use_integers_for_enums=False,
                        )
                    )
                case _:
                    raise PiccoloError(f"Unknown resource kind: {kind}")
        except exceptions.NotFound:
            return None
        except exceptions.Forbidden as exc:
            raise permission_error(
                self.clients.principal,
                "roles/compute.viewer",
                f"projects/{self.project}",
            ) from exc
        except exceptions.GoogleAPICallError as exc:
            raise PiccoloError(f"Cannot inspect {kind} {name}: {exc}") from exc

    def list(self, kind: str) -> list[Document]:
        """Enumerate paginated global or aggregated zonal resource lists."""
        try:
            match kind:
                case "instance":
                    instances: list[Document] = []
                    for _, scope in self.clients.instances.aggregated_list(
                        project=self.project, retry=READ_RETRY, timeout=30
                    ):
                        warning = decode(compute_v1.Warning.to_json(scope.warning))
                        if text(warning, "code") not in {"", "NO_RESULTS_ON_PAGE"}:
                            raise PiccoloError(
                                f"Incomplete discovery: {text(warning, 'code')}"
                            )
                        instances.extend(
                            decode(
                                compute_v1.Instance.to_json(
                                    item,
                                    preserving_proto_field_name=True,
                                    use_integers_for_enums=False,
                                )
                            )
                            for item in scope.instances
                        )
                    return instances
                case "disk":
                    disks: list[Document] = []
                    for _, scope in self.clients.disks.aggregated_list(
                        project=self.project, retry=READ_RETRY, timeout=30
                    ):
                        warning = decode(compute_v1.Warning.to_json(scope.warning))
                        if text(warning, "code") not in {"", "NO_RESULTS_ON_PAGE"}:
                            raise PiccoloError(
                                f"Incomplete disk discovery: {text(warning, 'code')}"
                            )
                        disks.extend(
                            decode(
                                compute_v1.Disk.to_json(
                                    item,
                                    preserving_proto_field_name=True,
                                    use_integers_for_enums=False,
                                )
                            )
                            for item in scope.disks
                        )
                    return disks
                case "snapshot":
                    return [
                        decode(
                            compute_v1.Snapshot.to_json(
                                item,
                                preserving_proto_field_name=True,
                                use_integers_for_enums=False,
                            )
                        )
                        for item in self.clients.snapshots.list(
                            project=self.project, retry=READ_RETRY, timeout=30
                        )
                    ]
                case _:
                    raise PiccoloError(f"Unknown resource kind: {kind}")
        except exceptions.Forbidden as exc:
            raise permission_error(
                self.clients.principal,
                "roles/compute.viewer",
                f"projects/{self.project}",
            ) from exc
        except exceptions.GoogleAPICallError as exc:
            raise PiccoloError(f"Cannot enumerate {kind}: {exc}") from exc

    def permission_denied(self, kind: str, detail: str = "") -> PiccoloError:
        """Describe missing provisioner roles and guest attachment rights."""
        if "iam.serviceAccounts.actAs" in detail:
            return permission_error(
                self.clients.principal,
                "roles/iam.serviceAccountUser",
                f"projects/{self.project}/serviceAccounts/{self.config.gcp.service_account}",
            )
        role = (
            "roles/compute.storageAdmin"
            if kind.startswith(("disk.", "snapshot."))
            else "roles/compute.instanceAdmin.v1"
        )
        return permission_error(
            self.clients.principal, role, f"projects/{self.project}"
        )

    def submit(
        self, kind: str, name: str, zone: str, resource: Document, request_id: str
    ) -> str:
        """Submit one mutation with a request ID and no transport retries."""
        base = {"project": self.project, "request_id": request_id}
        try:
            match kind:
                case "instance.insert":
                    operation = self.clients.instances.insert(
                        request=compute_v1.InsertInstanceRequest(
                            **base,
                            zone=zone,
                            instance_resource=compute_v1.Instance.from_json(
                                json.dumps(resource)
                            ),
                        ),
                        retry=None,
                        timeout=30,
                    )
                case "disk.insert":
                    operation = self.clients.disks.insert(
                        request=compute_v1.InsertDiskRequest(
                            **base,
                            zone=zone,
                            disk_resource=compute_v1.Disk.from_json(
                                json.dumps(resource)
                            ),
                        ),
                        retry=None,
                        timeout=30,
                    )
                case "snapshot.insert":
                    operation = self.clients.snapshots.insert(
                        request=compute_v1.InsertSnapshotRequest(
                            **base,
                            snapshot_resource=compute_v1.Snapshot.from_json(
                                json.dumps(resource)
                            ),
                        ),
                        retry=None,
                        timeout=30,
                    )
                case "instance.start":
                    operation = self.clients.instances.start(
                        request=compute_v1.StartInstanceRequest(
                            **base, zone=zone, instance=name
                        ),
                        retry=None,
                        timeout=30,
                    )
                case "instance.stop":
                    operation = self.clients.instances.stop(
                        request=compute_v1.StopInstanceRequest(
                            **base, zone=zone, instance=name
                        ),
                        retry=None,
                        timeout=30,
                    )
                case "instance.protect":
                    operation = self.clients.instances.set_disk_auto_delete(
                        request=compute_v1.SetDiskAutoDeleteInstanceRequest(
                            **base,
                            zone=zone,
                            instance=name,
                            auto_delete=False,
                            device_name=resource["device_name"],
                        ),
                        retry=None,
                        timeout=30,
                    )
                case "instance.delete":
                    operation = self.clients.instances.delete(
                        request=compute_v1.DeleteInstanceRequest(
                            **base, zone=zone, instance=name
                        ),
                        retry=None,
                        timeout=30,
                    )
                case "disk.delete":
                    operation = self.clients.disks.delete(
                        request=compute_v1.DeleteDiskRequest(
                            **base, zone=zone, disk=name
                        ),
                        retry=None,
                        timeout=30,
                    )
                case "snapshot.delete":
                    operation = self.clients.snapshots.delete(
                        request=compute_v1.DeleteSnapshotRequest(**base, snapshot=name),
                        retry=None,
                        timeout=30,
                    )
                case _:
                    raise PiccoloError(f"Unknown mutation: {kind}")
            return str(operation.name)
        except exceptions.Forbidden as exc:
            raise self.permission_denied(kind, str(exc)) from exc
        except (
            exceptions.BadRequest,
            exceptions.Unauthorized,
            exceptions.NotFound,
            exceptions.Conflict,
        ) as exc:
            raise PiccoloError(f"{kind} {name}: {exc}") from exc
        except (exceptions.GoogleAPICallError, TimeoutError, OSError) as exc:
            raise UncertainError(
                f"Uncertain submission of {kind} {name}; run resume: {exc}"
            ) from exc

    def poll(self, name: str, zone: str) -> Document:
        """Poll an operation, preserving uncertainty if inspection fails."""
        try:
            if zone:
                operation = self.clients.zone_operations.get(
                    project=self.project,
                    zone=zone,
                    operation=name,
                    retry=READ_RETRY,
                    timeout=30,
                )
            else:
                operation = self.clients.global_operations.get(
                    project=self.project, operation=name, retry=READ_RETRY, timeout=30
                )
            return decode(
                compute_v1.Operation.to_json(
                    operation,
                    preserving_proto_field_name=True,
                    use_integers_for_enums=False,
                )
            )
        except exceptions.Forbidden as exc:
            raise permission_error(
                self.clients.principal,
                "roles/compute.viewer",
                f"projects/{self.project}",
            ) from exc
        except exceptions.GoogleAPICallError as exc:
            raise UncertainError(
                f"Cannot inspect operation {name}; preserve resources: {exc}"
            ) from exc

    def recover(self, request_id: str, zone: str) -> str:
        """Find an operation submitted during a crash before recording its name."""
        try:
            if zone:
                results = self.clients.zone_operations.list(
                    request=compute_v1.ListZoneOperationsRequest(
                        project=self.project,
                        zone=zone,
                        filter=f'clientOperationId = "{request_id}"',
                    ),
                    retry=READ_RETRY,
                    timeout=30,
                )
            else:
                results = self.clients.global_operations.list(
                    request=compute_v1.ListGlobalOperationsRequest(
                        project=self.project,
                        filter=f'clientOperationId = "{request_id}"',
                    ),
                    retry=READ_RETRY,
                    timeout=30,
                )
            names = [item.name for item in results]
            if len(names) > 1:
                raise UncertainError(
                    "Multiple operations match a request ID; inspect manually"
                )
            return names[0] if names else ""
        except exceptions.Forbidden as exc:
            raise permission_error(
                self.clients.principal,
                "roles/compute.viewer",
                f"projects/{self.project}",
            ) from exc
        except exceptions.GoogleAPICallError as exc:
            raise UncertainError(f"Cannot reconcile submitted request: {exc}") from exc

    def access(self) -> None:
        """Ensure required APIs and additive access resources."""
        from piccolo.providers.gcp.access import Access

        Access(self.config, self.clients, self.journal).ensure()

    def access_plan(self) -> Document:
        """Report API, account, IAM, and firewall state without changing them."""
        from piccolo.providers.gcp.access import Access

        return Access(self.config, self.clients).inspect()

    def subnet(self, zone: str) -> str:
        """Resolve the configured region-to-subnet mapping and validate network."""
        region = zone.rsplit("-", 1)[0]
        name = self.config.gcp.subnets.get(region, self.config.gcp.subnet)
        try:
            result = self.clients.subnets.get(
                project=self.project,
                region=region,
                subnetwork=name,
                retry=READ_RETRY,
                timeout=30,
            )
        except exceptions.Forbidden as exc:
            raise permission_error(
                self.clients.principal,
                "roles/compute.networkViewer",
                f"projects/{self.project}",
            ) from exc
        except exceptions.GoogleAPICallError as exc:
            raise PiccoloError(
                f"Cannot resolve subnet {name} in {region}: {exc}"
            ) from exc
        expected = f"projects/{self.project}/global/networks/{self.config.gcp.network}"
        if not result.network.endswith(expected):
            raise PiccoloError(f"Subnet {name} belongs to a different network")
        if result.stack_type not in {"", "IPV4_ONLY"}:
            raise PiccoloError("Only IPv4-only subnets are supported in v1")
        return result.self_link

    def host_keys(self, zone: str) -> Document:
        """Fetch host public keys from the guest agent through authenticated GCP."""
        try:
            result = self.clients.instances.get_guest_attributes(
                request=compute_v1.GetGuestAttributesInstanceRequest(
                    project=self.project,
                    zone=zone,
                    instance=self.config.gcp.name,
                    query_path="hostkeys/",
                ),
                retry=READ_RETRY,
                timeout=30,
            )
            return decode(
                compute_v1.GuestAttributes.to_json(
                    result, preserving_proto_field_name=True
                )
            )
        except exceptions.NotFound:
            return {}
        except exceptions.Forbidden as exc:
            raise permission_error(
                self.clients.principal,
                "roles/compute.viewer",
                f"projects/{self.project}",
            ) from exc
        except exceptions.GoogleAPICallError as exc:
            raise PiccoloError(
                f"Cannot enroll host public keys through Compute: {exc}"
            ) from exc

    def connection_policy(self, instance: Document) -> None:
        """Require effective ingress to remain IAP scoped before SSH or SCP."""
        from piccolo.providers.gcp.access import Access

        policy = Access(self.config, self.clients).network_policy(instance)
        if self.config.gcp.via_iap and policy.get("unsafe_ingress"):
            raise PiccoloError(
                "Effective firewall policy permits non-IAP ingress: "
                f"{policy['unsafe_ingress']}"
            )

    def move_policy(self, instance: Document, disk: Document) -> None:
        """Reject instance/disk tag bindings which snapshots do not preserve."""
        from piccolo.providers.gcp.provision import zone_of

        project = self.clients.projects.get_project(
            name=f"projects/{self.project}", retry=READ_RETRY, timeout=30
        )
        zone = zone_of(instance)
        client = resourcemanager_v3.TagBindingsClient(
            credentials=self.clients.credentials,
            client_options={
                "api_endpoint": f"{zone}-cloudresourcemanager.googleapis.com"
            },
        )
        try:
            for kind, resource in (("instances", instance), ("disks", disk)):
                parent = (
                    f"//compute.googleapis.com/{project.name}/zones/{zone}/"
                    f"{kind}/{text(resource, 'id')}"
                )
                if any(
                    client.list_tag_bindings(
                        parent=parent, retry=READ_RETRY, timeout=30
                    )
                ):
                    raise PiccoloError(
                        f"Unsupported source tag bindings on {kind}; "
                        "inspect before relocation"
                    )
        except exceptions.Forbidden as exc:
            raise permission_error(
                self.clients.principal, "roles/resourcemanager.tagViewer", project.name
            ) from exc
        except exceptions.GoogleAPICallError as exc:
            raise PiccoloError(f"Cannot inspect source tag bindings: {exc}") from exc
        finally:
            client.transport.close()

    def project_metadata(self) -> Document:
        """Read project-wide startup metadata without enabling any hooks."""
        try:
            project = self.clients.compute_projects.get(
                project=self.project, retry=READ_RETRY, timeout=30
            )
        except exceptions.Forbidden as exc:
            raise permission_error(
                self.clients.principal,
                "roles/compute.viewer",
                f"projects/{self.project}",
            ) from exc
        except exceptions.GoogleAPICallError as exc:
            raise PiccoloError(
                f"Cannot inspect project startup metadata: {exc}"
            ) from exc
        return decode(
            compute_v1.Metadata.to_json(
                project.common_instance_metadata,
                preserving_proto_field_name=True,
                use_integers_for_enums=False,
            )
        )
