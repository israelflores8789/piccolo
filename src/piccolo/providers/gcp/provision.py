# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""provision.py — Ownership, supported-state validation, and creation resources."""

import hashlib

from piccolo.config.models import Config
from piccolo.data import Document, document, objects, text
from piccolo.errors import PiccoloError


def zone_of(instance: Document) -> str:
    """Return the zone basename from an observed resource."""
    return text(instance, "zone").rsplit("/", 1)[-1]


def labels(config: Config, operation_id: str = "") -> Document:
    """Create environment-specific ownership labels."""
    identity = f"{config.gcp.project_id}:{config.environment}"
    result: Document = {
        "managed-by": "piccolo",
        "piccolo-environment": hashlib.sha256(identity.encode()).hexdigest()[:24],
    }
    if operation_id:
        result["piccolo-operation"] = operation_id
    return result


def owned(config: Config, resource: Document, operation_id: str = "") -> bool:
    """Check all required ownership labels, including an optional operation."""
    actual = document(resource.get("labels", {}))
    return all(
        actual.get(key) == expected
        for key, expected in labels(config, operation_id).items()
    )


def boot_disk(instance: Document) -> Document:
    """Identify the sole persistent boot disk by its boot flag."""
    disks = objects(instance, "disks")
    boots = [disk for disk in disks if disk.get("boot") is True]
    if (
        len(disks) != 1
        or len(boots) != 1
        or boots[0].get("type_", "PERSISTENT") != "PERSISTENT"
    ):
        raise PiccoloError(
            "v1 supports exactly one persistent boot disk; "
            "extra disks and local SSDs cannot be moved"
        )
    if "/zones/" not in text(boots[0], "source"):
        raise PiccoloError("Only zonal persistent boot disks are supported")
    return boots[0]


def reject_startup(metadata: Document) -> None:
    """Refuse GCP startup scripts that could silently rerun project setup."""
    for item in objects(metadata, "items"):
        key = text(item, "key").lower()
        if "startup-script" in key or "sysprep" in key or key == "user-data":
            raise PiccoloError(
                f"Unsafe automatic startup metadata {key!r}; "
                f"inspect and remove it deliberately before "
                f"using Piccolo"
            )


def validate_source(config: Config, instance: Document, disk: Document) -> None:
    """Reject unsupported VM settings rather than silently discard them in a move."""
    boot_disk(instance)
    reject_startup(document(instance.get("metadata", {})))
    if instance.get("deletion_protection"):
        raise PiccoloError(
            "Instance deletion protection is enabled; inspect before moving"
        )
    for field in (
        "guest_accelerators",
        "resource_policies",
        "instance_encryption_key",
        "confidential_instance_config",
        "advanced_machine_features",
        "network_performance_config",
        "hostname",
        "source_machine_image",
        "workload_identity_config",
    ):
        if instance.get(field):
            raise PiccoloError(f"Unsupported source setting: {field}")
    for field in (
        "disk_encryption_key",
        "resource_policies",
        "async_primary_disk",
        "async_secondary_disks",
        "storage_pool",
        "provisioned_iops",
        "provisioned_throughput",
        "enable_confidential_compute",
    ):
        if disk.get(field):
            raise PiccoloError(f"Unsupported source disk setting: {field}")
    nics = objects(instance, "network_interfaces")
    if len(nics) != 1:
        raise PiccoloError("v1 supports exactly one IPv4 network interface")
    nic = nics[0]
    if (
        nic.get("alias_ip_ranges")
        or nic.get("ipv6_access_configs")
        or nic.get("stack_type", "IPV4_ONLY") != "IPV4_ONLY"
        or nic.get("nic_type", "VIRTIO_NET") != "VIRTIO_NET"
    ):
        raise PiccoloError("Unsupported network interface settings")
    if len(objects(nic, "access_configs")) > 1:
        raise PiccoloError("Unsupported external access configuration")
    scheduling = document(instance.get("scheduling", {}))
    if (
        scheduling.get("provisioning_model", "STANDARD") != "STANDARD"
        or scheduling.get("preemptible")
        or scheduling.get("node_affinities")
        or scheduling.get("max_run_duration")
        or scheduling.get("termination_time")
        or scheduling.get("instance_termination_action")
    ):
        raise PiccoloError(
            "v1 supports standard VMs without node affinity or termination schedules"
        )
    affinity = document(instance.get("reservation_affinity", {}))
    if affinity.get("consume_reservation_type", "NO_RESERVATION") != "NO_RESERVATION":
        raise PiccoloError("Reservation-bound instances cannot be moved in v1")
    differences(config, instance, disk, strict=True)


def differences(
    config: Config, instance: Document, disk: Document, *, strict: bool = False
) -> list[str]:
    """Describe supported configuration drift without changing existing disks."""
    gcp = config.gcp
    result: list[str] = []
    if text(instance, "machine_type").split("/")[-1] != gcp.machine_type:
        result.append("gcp.instance.machine_type differs")
    accounts = objects(instance, "service_accounts")
    if len(accounts) != 1 or text(accounts[0], "email") != gcp.service_account:
        result.append("gcp.instance.service_account differs")
    if text(disk, "type_").split("/")[-1] != gcp.disk_type:
        result.append("gcp.disk.type differs")
    if str(disk.get("size_gb")) != str(gcp.size_gb):
        result.append("gcp.disk.size_gb differs")
    image = text(disk, "source_image")
    if image and not image.endswith(gcp.image):
        result.append("gcp.disk.image differs")
    nics = objects(instance, "network_interfaces")
    if len(nics) != 1:
        result.append("gcp.network: expected one interface")
    else:
        nic = nics[0]
        expected_network = f"projects/{gcp.project_id}/global/networks/{gcp.network}"
        if not text(nic, "network").endswith(expected_network):
            result.append("gcp.network.name differs")
        region = zone_of(instance).rsplit("-", 1)[0]
        if text(nic, "subnetwork").split("/")[-1] != gcp.subnets.get(
            region, gcp.subnet
        ):
            result.append("gcp.network.subnet differs")
        if bool(objects(nic, "access_configs")) != gcp.external_ip:
            result.append("gcp.network.external_ip differs")
    if strict and result:
        raise PiccoloError("Unsupported configuration drift: " + "; ".join(result))
    return result


def instance_resource(
    config: Config,
    zone: str,
    disk_link: str,
    subnet: str,
    operation_id: str,
    source: Document | None = None,
) -> Document:
    """Build managed settings and preserve supported observed settings on relocation."""
    gcp = config.gcp
    nic: Document = {
        "network": f"projects/{gcp.project_id}/global/networks/{gcp.network}",
        "subnetwork": subnet,
        "stack_type": "IPV4_ONLY",
    }
    if gcp.external_ip:
        tier = "PREMIUM"
        if source:
            access = objects(objects(source, "network_interfaces")[0], "access_configs")
            if access:
                tier = text(access[0], "network_tier", "PREMIUM")
        nic["access_configs"] = [
            {"name": "External NAT", "type_": "ONE_TO_ONE_NAT", "network_tier": tier}
        ]
    result: Document = {
        "name": gcp.name,
        "machine_type": f"zones/{zone}/machineTypes/{gcp.machine_type}",
        "labels": labels(config, operation_id),
        "disks": [
            {
                "boot": True,
                "auto_delete": False,
                "type_": "PERSISTENT",
                "source": disk_link,
                "device_name": gcp.name,
                "mode": "READ_WRITE",
            }
        ],
        "network_interfaces": [nic],
        "service_accounts": [
            {
                "email": gcp.service_account,
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            }
        ],
        "shielded_instance_config": {
            "enable_secure_boot": True,
            "enable_vtpm": True,
            "enable_integrity_monitoring": True,
        },
        "scheduling": {
            "automatic_restart": True,
            "on_host_maintenance": "MIGRATE",
            "provisioning_model": "STANDARD",
        },
        "reservation_affinity": {"consume_reservation_type": "NO_RESERVATION"},
    }
    if source:
        for key in (
            "service_accounts",
            "shielded_instance_config",
            "shielded_instance_integrity_policy",
            "scheduling",
            "description",
            "can_ip_forward",
            "min_cpu_platform",
            "display_device",
            "key_revocation_action_type",
        ):
            if key in source:
                result[key] = source[key]
        for key in ("metadata", "tags"):
            if key in source:
                observed = document(source[key])
                result[key] = {"items": observed.get("items", [])}
        preserved = document(source.get("labels", {}))
        preserved.update(labels(config, operation_id))
        result["labels"] = preserved
        attached = objects(result, "disks")[0]
        old = boot_disk(source)
        for key in ("interface", "device_name", "mode"):
            if key in old:
                attached[key] = old[key]
        result["disks"] = [attached]
    return result
