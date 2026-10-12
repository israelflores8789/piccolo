# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""gcp_live.py — Offline profile validation and independently invocable janitor.

Set PICCOLO_GCP_LIVE_PROJECT to match the live profile and recovery manifest.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
from pathlib import Path
from typing import TYPE_CHECKING

from gcp_live_support.deadline import check_work, live_session
from gcp_live_support.manifest import Manifest, cleanup, gate
from piccolo.config import Config, load
from piccolo.data import Document, text
from piccolo.errors import PiccoloError
from piccolo.logger import emit, log
from piccolo.state.lock import environment_lock
from piccolo.state.storage import private_directory


def approval_digest(config: Config) -> str:
    """Bind approval to effective profile, variant selection, and deadline policy."""
    policy = {
        "settings": config.fingerprint,
        "move_cases": os.environ.get("PICCOLO_GCP_LIVE_MOVE_CASES", "all"),
        "duration_seconds": 2700,
        "cleanup_seconds": 300,
        "inventory_seconds": 60,
        "dummy_payload_sha256": hashlib.sha256(
            b"TEST_thisisadummytestsecret_TEST"
        ).hexdigest(),
    }
    return hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def profile(path: Path) -> Config:
    """Validate approved inputs locally before credentials or clients are loaded."""
    config = load(path)
    gcp = config.gcp
    gate(gcp.project_id)
    if (
        (
            gcp.auth.impersonate_service_account
            and not gcp.auth.impersonate_service_account.endswith(
                f"@{gcp.project_id}.iam.gserviceaccount.com"
            )
        )
        or not gcp.connection_account
        or "@" not in gcp.connection_account
        or gcp.connection_account.endswith(".gserviceaccount.com")
        or gcp.connection_impersonate
        or gcp.service_account == gcp.auth.impersonate_service_account
        or gcp.create_service_account
        or gcp.enable_apis
        or gcp.project_roles
        or config.bootstrap is not None
    ):
        raise PiccoloError(
            "Live profile requires a separate provisioner identity and human "
            "connection account, existing VM account, pre-enabled APIs, "
            "and no bootstrap or project roles"
        )
    if len(gcp.zones) < 2 or len({z.rsplit("-", 1)[0] for z in gcp.zones}) < 2:
        raise PiccoloError("Approve at least two zones in different regions")
    if re.fullmatch(r"projects/[^/]+/global/images/[^/]+", gcp.image) is None:
        raise PiccoloError("Approve a pinned image, not an image family")
    if any(
        "REPLACE" in item
        for item in (
            gcp.auth.impersonate_service_account,
            gcp.connection_account,
            gcp.service_account,
            gcp.ssh_user,
            gcp.image,
        )
    ):
        raise PiccoloError("Complete the live profile placeholders before running")
    if os.environ.get("PICCOLO_GCP_LIVE_APPROVAL_SHA256") != approval_digest(config):
        raise PiccoloError(
            "Pin PICCOLO_GCP_LIVE_APPROVAL_SHA256 to the reviewed "
            "profile digest before live execution"
        )
    return config


def local_preflight() -> None:
    """Require gcloud and OpenSSH before loading cloud credentials."""
    missing = [
        name
        for name in ("gcloud", "ssh", "scp", "ssh-keygen")
        if not shutil.which(name)
    ]
    if missing:
        raise PiccoloError("Install connection prerequisites: " + ", ".join(missing))


def run_config(
    base: Config, directory: Path, run: str, *, create_account: bool
) -> Config:
    """Write a sanitized durable config and an exclusively harmless bootstrap."""
    g = base.gcp
    gate(g.project_id)
    check_work()
    private_directory(directory.parent)
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    script = directory / "marker.sh"
    script.write_text(
        "#!/bin/bash\n# Copyright 2026 Israel Flores-Arbolay\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        'set -eu\nprintf "piccolo live marker\\n" >> "$HOME/piccolo-live-marker"\n'
    )
    quote = json.dumps
    account = (
        f"{run}-vm@{g.project_id}.iam.gserviceaccount.com"
        if create_account
        else g.service_account
    )
    subnet_map = ", ".join(f"{quote(k)} = {quote(v)}" for k, v in g.subnets.items())
    credential = (
        f"credential_file = {quote(str(g.auth.credential_file))}\n"
        if g.auth.credential_file
        else ""
    )
    path = directory / "piccolo.toml"
    path.write_text(f"""# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0
schema_version = 1
provider = "gcp"
environment = {quote(run)}
[bootstrap]
script = "marker.sh"
remote_path = ".piccolo/bootstrap/marker.sh"
execution_user = {quote(g.ssh_user)}
timeout = 120
[gcp]
project_id = {quote(g.project_id)}
enable_apis = false
operation_timeout = {g.operation_timeout}
[gcp.auth]
mode = {quote(g.auth.mode)}
{credential}impersonate_service_account = {quote(g.auth.impersonate_service_account)}
[gcp.instance]
name = {quote(run + "-vm")}
service_account = {quote(account)}
machine_type = {quote(g.machine_type)}
[gcp.placement]
zones = {quote(g.zones)}
snapshot_location = {quote(g.snapshot_location)}
[gcp.disk]
image = {quote(g.image)}
size_gb = {g.size_gb}
type = {quote(g.disk_type)}
[gcp.network]
name = {quote(g.network)}
subnet = {quote(g.subnet)}
subnets = {{ {subnet_map} }}
external_ip = {str(g.external_ip).lower()}
[gcp.iap]
firewall_name = {quote(run + "-iap")}
ports = [22, 8080]
source_ranges = ["35.235.240.0/20"]
[gcp.iam]
create_service_account = {str(create_account).lower()}
secrets = {quote((run + "-dummy", *g.secrets))}
project_roles = []
[gcp.ssh]
user = {quote(g.ssh_user)}
account = {quote(g.connection_account)}
via_iap = true
readiness_timeout = {g.readiness_timeout}
[gcp.tunnel]
remote_port = 8080
local_port = {g.local_port}
""")
    script.chmod(0o600)
    path.chmod(0o600)
    return load(path)


def preflight(
    config: Config, cloud: "LiveCloud", connection: "GCloudConnection"
) -> None:
    """Inspect dependencies and baseline before the first fixture mutation."""
    from google.cloud import service_usage_v1
    from google.iam.v1 import iam_policy_pb2

    from piccolo.providers.gcp.access import Access
    from piccolo.providers.gcp.provision import reject_startup
    from piccolo.providers.gcp.resources import READ_RETRY

    project = cloud.clients.projects.get_project(
        name=f"projects/{config.gcp.project_id}", retry=READ_RETRY, timeout=30
    )
    permissions = [
        "compute.instances.create",
        "compute.instances.delete",
        "compute.instances.get",
        "compute.instances.list",
        "compute.instances.start",
        "compute.instances.stop",
        "compute.instances.setDiskAutoDelete",
        "compute.instances.setMetadata",
        "compute.disks.create",
        "compute.disks.delete",
        "compute.disks.get",
        "compute.disks.list",
        "compute.disks.use",
        "compute.disks.createSnapshot",
        "compute.snapshots.create",
        "compute.snapshots.delete",
        "compute.snapshots.get",
        "compute.snapshots.list",
        "compute.snapshots.useReadOnly",
        "compute.firewalls.create",
        "compute.firewalls.delete",
        "compute.firewalls.get",
        "compute.firewalls.list",
        "compute.projects.get",
        "compute.subnetworks.get",
        "compute.subnetworks.use",
        "compute.zoneOperations.get",
        "compute.zoneOperations.list",
        "compute.globalOperations.get",
        "compute.globalOperations.list",
        "iam.serviceAccounts.get",
        "iam.serviceAccounts.list",
        "iam.serviceAccounts.getIamPolicy",
        "secretmanager.secrets.create",
        "secretmanager.secrets.delete",
        "secretmanager.secrets.get",
        "secretmanager.secrets.list",
        "secretmanager.secrets.getIamPolicy",
        "secretmanager.secrets.setIamPolicy",
    ]
    if config.gcp.create_service_account:
        permissions.extend(
            [
                "iam.serviceAccounts.create",
                "iam.serviceAccounts.delete",
                "iam.serviceAccounts.setIamPolicy",
            ]
        )
    if config.gcp.external_ip:
        permissions.append("compute.subnetworks.useExternalIp")
    granted = cloud.clients.projects.test_iam_permissions(
        request=iam_policy_pb2.TestIamPermissionsRequest(
            resource=f"projects/{config.gcp.project_id}",
            permissions=permissions,
        ),
        retry=READ_RETRY,
        timeout=30,
    )
    missing = set(permissions) - set(granted.permissions)
    if missing:
        raise PiccoloError(
            "Provisioner lacks lifecycle/teardown permissions: "
            + ", ".join(sorted(missing))
        )
    required = Access(config, cloud.clients).required_apis() | {
        "secretmanager.googleapis.com",
        "iap.googleapis.com",
        "oslogin.googleapis.com",
    }
    baseline = []
    for api in sorted(required):
        service = cloud.clients.services.get_service(
            request=service_usage_v1.GetServiceRequest(
                name=f"{project.name}/services/{api}"
            ),
            retry=READ_RETRY,
            timeout=30,
        )
        if service.state != service_usage_v1.State.ENABLED:
            raise PiccoloError(
                f"Enable {api} out of band; live tests preserve API state"
            )
        baseline.append(api)
    metadata = cloud.project_metadata()
    reject_startup(metadata)
    # Run-owned VMs receive OS Login metadata; project metadata is preserved.
    for zone in config.gcp.zones:
        cloud.subnet(zone)
    connection.check_identity()
    with socket.socket() as local:
        try:
            local.bind(("127.0.0.1", config.gcp.local_port))
        except OSError as exc:
            raise PiccoloError("Approved local tunnel port is unavailable") from exc
    cloud.manifest.data["baseline_apis"] = [api for api in baseline]
    inventory: Document = {}
    for kind in ("instance", "disk", "snapshot", "firewall", "secret", "account"):
        inventory[kind] = [
            {
                key: item[key]
                for key in ("name", "id", "zone", "status", "email")
                if key in item
            }
            for item in cloud.inventory(kind)
        ]
    cloud.manifest.data["baseline_inventory"] = inventory
    cloud.manifest.save()


def main() -> None:
    """Preview or apply cleanup independently of pytest and its temporary state."""
    parser = argparse.ArgumentParser(description="Piccolo live GCP manifest janitor")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    manifest = Manifest.open(args.manifest)
    gate(text(manifest.data, "project"))
    config = load(Path(text(manifest.data, "config")))
    gate(config.gcp.project_id)
    recorded_fingerprint = text(manifest.data, "run_settings_fingerprint")
    if recorded_fingerprint and recorded_fingerprint != config.fingerprint:
        raise PiccoloError(
            "Recovery settings changed; restore the recorded settings "
            "before janitor execution"
        )
    # Import optional SDKs only after validating local gates and manifest identity.
    from gcp_live_support.gcp_sdk import LiveCloud
    from piccolo.providers.gcp.auth import credentials
    from piccolo.providers.gcp.clients import Clients

    os.environ["PICCOLO_STATE_DIR"] = str(manifest.directory / "state")
    with environment_lock(config), live_session():
        sdk_credentials = credentials(config.gcp)
        cloud = LiveCloud(
            config,
            Clients(sdk_credentials),
            manifest,
            provisioner=provisioner_identity(sdk_credentials, config),
        )
        if not args.apply:
            emit({"resources": [entry for entry in manifest.entries("resources")]})
        failures = cleanup(manifest, cloud, apply=args.apply)
        if args.apply:
            emit(
                {
                    "manifest": str(manifest.path),
                    "residual_cost_exposure": manifest.data.get(
                        "residual_cost_exposure"
                    ),
                }
            )
        if failures:
            raise SystemExit("\n".join(failures))
        log("Zero leftovers verified" if args.apply else "Preview only; no deletions")


# Type-only imports keep profile checks and ordinary collection cloud-free.
if TYPE_CHECKING:
    from gcp_live_support.gcp_sdk import LiveCloud
    from piccolo.providers.gcp.connection import GCloudConnection


def provisioner_identity(credentials: object, config: Config) -> str:
    """Require an authenticated service account distinct from the guest account."""
    identity = getattr(credentials, "service_account_email", None)
    if (
        not isinstance(identity, str)
        or not identity.endswith(f"@{config.gcp.project_id}.iam.gserviceaccount.com")
        or identity == config.gcp.service_account
    ):
        raise PiccoloError(
            "Live SDK credentials must identify the approved project's provisioner"
        )
    return identity


if __name__ == "__main__":
    main()
