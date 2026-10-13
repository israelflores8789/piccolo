# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""session.py — Verify approved account baselines and recover the session network."""

import argparse
import json
import os
import time
import uuid
from pathlib import Path

from google.api_core import exceptions
from google.cloud import compute_v1, iam_admin_v1
from google.iam.v1 import iam_policy_pb2, options_pb2, policy_pb2

from gcp_live_support.deadline import ACTIVE, bind_clients, live_session, phase, timeout
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
BASELINE = Path(
    os.environ.get(
        "PICCOLO_GCP_LIVE_BASELINE", ".test_runs/session-2026-10-12-baseline.json"
    )
)


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


def inventory(clients: Clients) -> Document:
    """Report test leftovers across the authorized project without deleting them."""
    from gcp_live_support.recycle_bin import RecycleBin
    from piccolo.providers.gcp.resources import SDKCloud

    config = load(Path(".test_runs/approved.toml"))
    cloud = SDKCloud(config, clients)
    result: Document = {}
    for kind in ("instance", "disk", "snapshot"):
        result[kind] = [
            text(item, "name")
            for item in cloud.list(kind)
            if text(item, "name").startswith("plive-")
        ]
    result["firewall"] = [
        f.name
        for f in clients.firewalls.list(project=PROJECT, retry=None, timeout=30)
        if f.name.startswith("plive-")
    ]
    result["network"] = [
        n.name
        for n in clients.networks.list(
            project=PROJECT,
            retry=None,
            timeout=30,
        )
        if n.name.startswith("plive-")
    ]
    result["subnet"] = [
        s.name
        for region in ("us-west1", "us-east1")
        for s in clients.subnets.list(
            project=PROJECT,
            region=region,
            retry=None,
            timeout=30,
        )
        if s.name.startswith("plive-")
    ]
    result["account"] = [
        a.email
        for a in clients.iam.list_service_accounts(
            name=f"projects/{PROJECT}",
            retry=None,
            timeout=30,
        )
        if a.email.startswith("plive-")
    ]
    result["secret"] = [
        s.name
        for s in clients.secrets.list_secrets(
            parent=f"projects/{PROJECT}",
            retry=None,
            timeout=30,
        )
        if s.name.rsplit("/", 1)[-1].startswith("plive-")
    ]
    result["recoverable_snapshot"] = [
        text(item, "name")
        for item in RecycleBin(PROJECT, clients.credentials).inventory()
        if text(document(item.get("originalResource", {})), "name").startswith("plive-")
    ]
    return result


def live_workers() -> list[int]:
    """Identify live pytest workers in this checkout without printing arguments."""
    root = Path(__file__).resolve().parents[2]
    executable = str(root / ".venv/bin/pytest").encode()
    workers: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            arguments = (entry / "cmdline").read_bytes().split(b"\0")
            if executable in arguments and b"--gcp-live" in arguments:
                workers.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as exc:
            raise PiccoloError(
                "Cannot verify live workers; cleanup is blocked"
            ) from exc
    return workers


def finish(clients: Clients) -> None:
    """Wait for live fixtures, reconcile manifests, remove the network, and verify."""
    import sys

    from gcp_live_support.gcp_sdk import LiveCloud
    from gcp_live_support.manifest import Manifest, cleanup
    from piccolo.state.lock import environment_lock

    deadline = ACTIVE.get()
    if deadline is None or not os.environ.get("PICCOLO_GCP_LIVE_STARTED_MONOTONIC"):
        raise PiccoloError("Automatic finalization requires the shared session clock")
    while workers := live_workers():
        print(f"Waiting for {len(workers)} live pytest workers", flush=True)
        with phase("cleanup"):
            time.sleep(timeout(30))
    paths: set[Path] = set()
    for log_path in Path(".test_logs").iterdir():
        if not log_path.name.startswith("continuation-") or log_path.suffix != ".log":
            continue
        for line in log_path.read_text().splitlines():
            if "Durable cleanup manifest: " in line:
                path = Path(line.split("Durable cleanup manifest: ", 1)[1])
                if not path.resolve().is_relative_to(Path(".test_runs").resolve()):
                    raise PiccoloError("Continuation manifest is outside test state")
                paths.add(path)
    failures: list[str] = []
    with phase("cleanup"):
        for path in sorted(paths):
            manifest = Manifest.open(path)
            if text(manifest.data, "project") != PROJECT:
                raise PiccoloError("Continuation manifest project differs")
            if manifest.data.get("complete") is True:
                continue
            config = load(Path(text(manifest.data, "config")))
            if config.gcp.project_id != PROJECT or config.fingerprint != text(
                manifest.data, "run_settings_fingerprint"
            ):
                raise PiccoloError("Continuation recovery settings changed")
            os.environ["PICCOLO_STATE_DIR"] = str(manifest.directory / "state")
            with environment_lock(config):
                failures.extend(
                    cleanup(
                        manifest,
                        LiveCloud(
                            config,
                            clients,
                            manifest,
                            provisioner=ACCOUNTS[0],
                        ),
                        apply=True,
                    )
                )
        if failures:
            raise PiccoloError("Final manifest cleanup failed: " + "; ".join(failures))
        baseline = decode(BASELINE.read_text())
        if baseline.get("project") != PROJECT:
            raise PiccoloError("Session baseline project differs")
        network(clients, baseline, create=False)
    with phase("inventory"):
        previous = sys.argv
        try:
            sys.argv = [previous[0], "verify"]
            main()
        finally:
            sys.argv = previous
        leftovers = inventory(clients)
        if any(leftovers.values()):
            raise PiccoloError("Final test inventory still contains resources")
    report = {
        "project": PROJECT,
        "elapsed_seconds": deadline.clock() - deadline.started,
        "allowed_seconds": deadline.total_seconds,
        "iam_preserved": True,
        "inventory": leftovers,
        "manifests": [str(path) for path in sorted(paths)],
    }
    with os.fdopen(
        private_file(Path(".test_runs/continuation-final-report.json"), create=True),
        "w",
    ) as stream:
        json.dump(report, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    print(
        "Final cleanup and original IAM verified; continuation-final-report.json saved",
        flush=True,
    )


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
        operation.result(timeout=timeout(120))
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
            operation.result(timeout=timeout(120))
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
                ).result(timeout=timeout(120))
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
            ).result(timeout=timeout(120))
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
            "inventory",
            "finish",
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
    bind_clients(clients)
    if args.action == "finish":
        finish(clients)
        return
    if args.action == "inventory":
        result = inventory(clients)
        path = BASELINE.with_name(BASELINE.stem + "-inventory.json")
        with os.fdopen(private_file(path, create=True), "w") as stream:
            json.dump(result, stream, indent=2)
        if any(result.values()):
            raise PiccoloError(f"Test leftovers remain; retained inventory: {path}")
        print(f"Zero test resources across all inventory families: {path}")
        return
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
    import sys

    selected_phase = (
        "inventory"
        if any(a in sys.argv for a in ("verify", "inventory"))
        else "cleanup"
        if any(a in sys.argv for a in ("network-remove", "purge-snapshots"))
        else "work"
    )
    with live_session(), phase(selected_phase):
        main()
