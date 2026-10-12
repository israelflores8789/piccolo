# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""session.py — Verify approved account baselines and recover the session network."""

import argparse
import json
import os
import uuid
from pathlib import Path

from google.api_core import exceptions
from google.cloud import compute_v1, iam_admin_v1
from google.iam.v1 import iam_policy_pb2, options_pb2, policy_pb2

from piccolo.config import load
from piccolo.data import Document, decode, document, objects, text
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.access import add_binding
from piccolo.providers.gcp.auth import credentials
from piccolo.providers.gcp.clients import Clients
from piccolo.state.storage import private_directory, private_file

PROJECT = "piccolo-511220"
SECRET = f"projects/{PROJECT}/secrets/PICCOLO_LIVE_DUMMY"
ACCOUNTS = (
    f"piccolo-test-provisioner@{PROJECT}.iam.gserviceaccount.com",
    f"piccolo-test-vm@{PROJECT}.iam.gserviceaccount.com",
)
BASELINE = Path(".test_runs/session-2026-10-12-baseline.json")


def policy(client: object, resource: str) -> Document:
    """Read a complete IAM policy without logging policy members."""
    from typing import Protocol, cast

    class Reader(Protocol):
        """Describe the shared generated IAM policy read method."""

        def get_iam_policy(
            self,
            *,
            request: iam_policy_pb2.GetIamPolicyRequest,
            retry: None,
            timeout: int,
        ) -> policy_pb2.Policy:
            """Return an etag-bearing policy."""
            ...

    result = cast(Reader, client).get_iam_policy(
        request=iam_policy_pb2.GetIamPolicyRequest(
            resource=resource,
            options=options_pb2.GetPolicyOptions(requested_policy_version=3),
        ),
        retry=None,
        timeout=30,
    )
    bindings: list[Document] = []
    for binding in result.bindings:
        record: Document = {
            "role": binding.role,
            "members": [member for member in sorted(binding.members)],
        }
        if binding.HasField("condition"):
            record["condition"] = {
                "expression": binding.condition.expression,
                "title": binding.condition.title,
                "description": binding.condition.description,
                "location": binding.condition.location,
            }
        bindings.append(record)
    return {
        "bindings": [
            b for b in sorted(bindings, key=lambda b: json.dumps(b, sort_keys=True))
        ]
    }


def save(data: Document) -> None:
    """Flush the original baseline before making any session resource change."""
    private_directory(BASELINE.parent)
    with os.fdopen(private_file(BASELINE, create=True), "w") as stream:
        json.dump(data, stream, indent=2)
        stream.flush()
        stream.truncate()
        os.fsync(stream.fileno())


def network(clients: Clients, baseline: Document, *, create: bool) -> None:
    """Create or delete only the recorded session network and temporary role."""
    role, member = "roles/compute.networkAdmin", f"serviceAccount:{ACCOUNTS[0]}"
    resource = f"projects/{PROJECT}"
    if create:
        current = clients.projects.get_iam_policy(
            request=iam_policy_pb2.GetIamPolicyRequest(
                resource=resource,
                options=options_pb2.GetPolicyOptions(requested_policy_version=3),
            ),
            retry=None,
            timeout=30,
        )
        if add_binding(current, role, member):
            if not current.etag:
                raise PiccoloError("Project IAM policy has no etag")
            baseline["network_admin_added"] = True
            save(baseline)
            clients.projects.set_iam_policy(
                request=iam_policy_pb2.SetIamPolicyRequest(
                    resource=resource, policy=current
                ),
                retry=None,
                timeout=30,
            )
        if "network" not in baseline:
            name = "plive-session-" + uuid.uuid4().hex[:12]
            network_entry: Document = {"name": name, "id": "", "subnets": []}
            baseline["network"] = network_entry
            save(baseline)
    entry = document(baseline["network"])
    baseline["network"] = entry
    name = text(entry, "name")
    marker = f"Piccolo approved live session {name}"
    try:
        observed = clients.networks.get(
            project=PROJECT, network=name, retry=None, timeout=30
        )
    except exceptions.NotFound:
        observed = None
    if create and observed is None:
        entry["absent_before"] = True
        save(baseline)
        operation = clients.networks.insert(
            request=compute_v1.InsertNetworkRequest(
                project=PROJECT,
                request_id=str(uuid.uuid4()),
                network_resource=compute_v1.Network(
                    name=name, description=marker, auto_create_subnetworks=False
                ),
            ),
            retry=None,
            timeout=30,
        )
        entry["operation"] = operation.name
        save(baseline)
        operation.result(timeout=120)
        observed = clients.networks.get(
            project=PROJECT, network=name, retry=None, timeout=30
        )
    if observed is not None:
        if (
            entry.get("absent_before") is not True
            or observed.description != marker
            or (text(entry, "id") and text(entry, "id") != str(observed.id))
        ):
            raise PiccoloError("Session network ownership changed")
        entry["id"] = str(observed.id)
        save(baseline)
    for index, region in enumerate(("us-west1", "us-east1"), start=1):
        subnet_name = name + "-subnet"
        entries = objects(entry, "subnets")
        entry["subnets"] = [s for s in entries]
        subnet_entry: Document | None = next(
            (s for s in entries if text(s, "region") == region), None
        )
        if create and subnet_entry is None:
            subnet_entry = {"name": subnet_name, "region": region, "id": ""}
            entries.append(subnet_entry)
            entry["subnets"] = [s for s in entries]
            save(baseline)
        if subnet_entry is None:
            continue
        try:
            subnet = clients.subnets.get(
                project=PROJECT,
                region=region,
                subnetwork=subnet_name,
                retry=None,
                timeout=30,
            )
        except exceptions.NotFound:
            subnet = None
        if create and subnet is None:
            subnet_entry["absent_before"] = True
            save(baseline)
            operation = clients.subnets.insert(
                request=compute_v1.InsertSubnetworkRequest(
                    project=PROJECT,
                    region=region,
                    request_id=str(uuid.uuid4()),
                    subnetwork_resource=compute_v1.Subnetwork(
                        name=subnet_name,
                        description=marker,
                        network=f"projects/{PROJECT}/global/networks/{name}",
                        ip_cidr_range=f"10.250.{index}.0/24",
                        private_ip_google_access=True,
                    ),
                ),
                retry=None,
                timeout=30,
            )
            subnet_entry["operation"] = operation.name
            save(baseline)
            operation.result(timeout=120)
            subnet = clients.subnets.get(
                project=PROJECT,
                region=region,
                subnetwork=subnet_name,
                retry=None,
                timeout=30,
            )
        if subnet is not None:
            if (
                subnet_entry.get("absent_before") is not True
                or subnet.description != marker
                or (
                    text(subnet_entry, "id")
                    and text(subnet_entry, "id") != str(subnet.id)
                )
            ):
                raise PiccoloError("Session subnet ownership changed")
            subnet_entry["id"] = str(subnet.id)
            save(baseline)
            if not create:
                clients.subnets.delete(
                    project=PROJECT,
                    region=region,
                    subnetwork=subnet_name,
                    retry=None,
                    timeout=30,
                ).result(timeout=120)
    if create:
        profile = Path(".test_runs/approved.toml").read_text()
        profile = profile.replace('name = "default"', f'name = "{name}"').replace(
            'subnet = "default"', f'subnet = "{name}-subnet"'
        )
        path = Path(".test_runs/approved-isolated.toml")
        path.write_text(profile)
        path.chmod(0o600)
        print(f"Isolated VPC and two regional subnets ready: {name}")
    else:
        if observed is not None:
            clients.networks.delete(
                project=PROJECT, network=name, retry=None, timeout=30
            ).result(timeout=120)
        if baseline.get("network_admin_added") is True:
            current = clients.projects.get_iam_policy(
                request=iam_policy_pb2.GetIamPolicyRequest(
                    resource=resource,
                    options=options_pb2.GetPolicyOptions(requested_policy_version=3),
                ),
                retry=None,
                timeout=30,
            )
            for binding in list(current.bindings):
                if (
                    binding.role == role
                    and member in binding.members
                    and not binding.HasField("condition")
                ):
                    binding.members.remove(member)
                    if not binding.members:
                        current.bindings.remove(binding)
            if not current.etag:
                raise PiccoloError("Project IAM policy has no etag")
            clients.projects.set_iam_policy(
                request=iam_policy_pb2.SetIamPolicyRequest(
                    resource=resource, policy=current
                ),
                retry=None,
                timeout=30,
            )
            baseline["network_admin_added"] = False
            save(baseline)
        print("Session VPC/subnets deleted and temporary provisioner role removed")


def main() -> None:
    """Record or verify original IAM without changing operator-managed labels."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "prepare",
            "verify",
            "network-prepare",
            "network-remove",
            "purge-snapshots",
        ),
    )
    args = parser.parse_args()
    if os.environ.get("PICCOLO_GCP_LIVE_PROJECT") != PROJECT:
        raise PiccoloError("Session project must be piccolo-511220")
    config = load(Path(".test_runs/approved.toml"))
    if config.gcp.project_id != PROJECT:
        raise PiccoloError("Profile project differs from authorized project")
    auth = credentials(config.gcp)
    if getattr(auth, "service_account_email", None) != ACCOUNTS[0]:
        raise PiccoloError("Session credentials must be the approved provisioner")
    clients = Clients(auth)
    if args.action == "purge-snapshots":
        from gcp_live_support.manifest import Manifest
        from gcp_live_support.recycle_bin import RecycleBin

        recycle = RecycleBin(PROJECT, auth)
        for directory in Path(".test_runs").iterdir():
            path = directory / "manifest.json"
            if not directory.is_dir() or not path.exists():
                continue
            manifest = Manifest.open(path)
            if text(manifest.data, "project") != PROJECT or not any(
                text(entry, "kind") == "snapshot"
                for entry in manifest.entries("resources")
            ):
                continue
            complete = manifest.data.get("complete") is True
            recycle.purge(manifest)
            if complete:
                manifest.data["complete"] = True
                manifest.save()
            print(f"Manifest-proven recycle-bin copies removed: {directory.name}")
        remaining = recycle.inventory()
        if any(
            text(document(item.get("originalResource", {})), "name").startswith(
                "plive-"
            )
            for item in remaining
        ):
            raise PiccoloError("Unproven test snapshots remain in the recycle bin")
        print("Zero test snapshot leftovers verified in the recycle bin")
        return
    secret = clients.secrets.get_secret(name=SECRET, retry=None, timeout=30)
    baseline: Document
    if BASELINE.exists():
        baseline = decode(BASELINE.read_text())
    elif args.action in {"verify", "network-remove"}:
        raise PiccoloError("Original baseline is unavailable")
    else:
        accounts: Document = {}
        for account in ACCOUNTS:
            resource = f"projects/{PROJECT}/serviceAccounts/{account}"
            observed = clients.iam.get_service_account(
                name=resource, retry=None, timeout=30
            )
            accounts[account] = {
                "account": decode(iam_admin_v1.ServiceAccount.to_json(observed)),
                "policy": policy(clients.iam, resource),
            }
        baseline = {
            "project": PROJECT,
            "accounts": accounts,
            "project_policy": policy(clients.projects, f"projects/{PROJECT}"),
            "secret_policy": policy(clients.secrets, SECRET),
            "secret_created": str(secret.create_time),
            "secret_labels": dict(secret.labels),
        }
        save(baseline)
    if baseline.get("project") != PROJECT or baseline.get("secret_created") != str(
        secret.create_time
    ):
        raise PiccoloError("Session project or secret identity changed")
    if args.action.startswith("network-"):
        network(clients, baseline, create=args.action == "network-prepare")
        return
    original = {
        key: str(value) for key, value in document(baseline["secret_labels"]).items()
    }
    original["piccolo-live-dummy"] = "true"
    if dict(secret.labels) != original:
        raise PiccoloError("Operator-managed dummy secret labels changed")
    if args.action == "verify":
        for account, raw in document(baseline["accounts"]).items():
            entry = document(raw)
            resource = f"projects/{PROJECT}/serviceAccounts/{account}"
            observed = clients.iam.get_service_account(
                name=resource, retry=None, timeout=30
            )
            if (
                decode(iam_admin_v1.ServiceAccount.to_json(observed))
                != entry["account"]
                or policy(clients.iam, resource) != entry["policy"]
            ):
                raise PiccoloError(
                    "Original service account or policy was not restored"
                )
        current = policy(clients.projects, f"projects/{PROJECT}")
        for account in ACCOUNTS:
            member = f"serviceAccount:{account}"

            def grants(value: Document, member: str) -> list[str]:
                """Compare original role bindings independent of ordering."""
                return sorted(
                    json.dumps(
                        {"role": b["role"], "condition": b.get("condition")},
                        sort_keys=True,
                    )
                    for b in objects(value, "bindings")
                    if isinstance(b.get("members"), list) and member in b["members"]
                )

            if grants(current, member) != grants(
                document(baseline["project_policy"]), member
            ):
                raise PiccoloError("Original account project roles were not restored")
        if policy(clients.secrets, SECRET) != baseline["secret_policy"]:
            raise PiccoloError("Original dummy secret policy was not restored")
        print("Approved dummy label and both original service accounts/IAM verified")
    else:
        print(f"Original account/IAM/secret baseline saved: {BASELINE}")
        print("Operator-managed dummy-secret label verified without changes")


if __name__ == "__main__":
    main()
