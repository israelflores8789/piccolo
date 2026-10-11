# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_live.py — Explicitly opted-in real SDK lifecycle and human IAP checks.

Set PICCOLO_GCP_LIVE_PROJECT to the approved TOML project before live tests.
The impersonation case also requires PICCOLO_GCP_LIVE_HUMAN_ADC.
"""

import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Generator
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from gcp_live_support.gcp_live import (
    local_preflight,
    preflight,
    profile,
    provisioner_identity,
    run_config,
)
from gcp_live_support.manifest import Manifest, cleanup, gate

from piccolo.data import Document, document, objects, text
from piccolo.errors import CapacityError, PiccoloError, UncertainError

pytestmark = pytest.mark.gcp_live


@pytest.fixture(
    params=[False, True], ids=["existing-vm-account", "piccolo-created-account"]
)
def gcp_run(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    isolated_state: None,
) -> Generator["GCPProvider"]:
    del isolated_state
    if not request.config.getoption("--gcp-live"):
        pytest.skip("requires --gcp-live")
    gate(os.environ.get("PICCOLO_GCP_LIVE_PROJECT", ""))
    path = os.environ.get("PICCOLO_GCP_LIVE_CONFIG")
    if not path:
        pytest.fail("Set PICCOLO_GCP_LIVE_CONFIG to the approved local TOML profile")
    base = profile(Path(path))
    local_preflight()
    from gcp_live_support.gcp_sdk import LiveCloud
    from google.cloud import service_usage_v1

    from piccolo.providers.gcp.auth import credentials
    from piccolo.providers.gcp.clients import Clients
    from piccolo.providers.gcp.connection import GCloudConnection
    from piccolo.providers.gcp.provider import GCPProvider
    from piccolo.state.lock import environment_lock

    run = f"plive-{uuid.uuid4().hex[:16]}"
    directory = Path(".test_runs").resolve() / run
    config = run_config(base, directory, run, create_account=bool(request.param))
    manifest = Manifest.create(
        directory / "manifest.json", config.path, run, project=config.gcp.project_id
    )
    print(f"Durable cleanup manifest: {manifest.path}", flush=True)
    monkeypatch.setenv("PICCOLO_STATE_DIR", str(directory / "state"))
    GCloudConnection(config.gcp).check_identity()
    with environment_lock(config):
        sdk_credentials = credentials(config.gcp)
        clients = Clients(sdk_credentials)
        clients.services = service_usage_v1.ServiceUsageClient(
            credentials=sdk_credentials, transport="rest"
        )
        cloud = LiveCloud(
            config,
            clients,
            manifest,
            provisioner=provisioner_identity(sdk_credentials, config),
        )
        provider = GCPProvider(config, cloud, GCloudConnection(config.gcp))
        try:
            preflight(config, cloud, GCloudConnection(config.gcp))
            existing = cloud.get("account", base.gcp.service_account)
            if existing is None or existing.get("disabled") is True:
                pytest.fail("Precreate and enable the approved VM service account")
            cloud.create_secret(f"{run}-dummy")
            for secret in base.gcp.secrets:
                cloud.preserve_external("secret", secret)
            yield provider
        finally:
            failures = cleanup(manifest, cloud, apply=True)
            if failures:
                pytest.fail(
                    "Teardown incomplete; resources may incur costs. "
                    f"Retained manifest: {manifest.path}\n" + "\n".join(failures)
                )
            print(f"Zero leftovers verified: {manifest.path}", flush=True)


def test_human_source_provisioner_impersonation(tmp_path: Path) -> None:
    """Exercise genuine human-to-provisioner tokens without any IAM mutation."""
    gate(os.environ.get("PICCOLO_GCP_LIVE_PROJECT", ""))
    base = profile(Path(os.environ["PICCOLO_GCP_LIVE_CONFIG"]))
    from google.auth import impersonated_credentials
    from google.cloud import resourcemanager_v3

    from piccolo.providers.gcp.auth import credentials

    direct = credentials(base.gcp)
    target = provisioner_identity(direct, base)
    adc = document(
        json.loads(Path(os.environ["PICCOLO_GCP_LIVE_HUMAN_ADC"]).read_text())
    )
    source = document(adc.get("source_credentials", adc))
    if source.get("type") != "authorized_user":
        pytest.fail("Human impersonation source must be authorized_user credentials")
    source_path = tmp_path / "human-source.json"
    descriptor = os.open(source_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(source, stream)
        config = replace(
            base.gcp,
            auth=replace(
                base.gcp.auth,
                mode="file",
                credential_file=source_path,
                impersonate_service_account=target,
            ),
        )
        impersonated = credentials(config)
        assert isinstance(impersonated, impersonated_credentials.Credentials)
        assert provisioner_identity(impersonated, base) == target
        project = resourcemanager_v3.ProjectsClient(
            credentials=impersonated
        ).get_project(name=f"projects/{base.gcp.project_id}", timeout=30)
        assert project.project_id == base.gcp.project_id
        print("Human-source provisioner impersonation verified; no IAM writes")
    finally:
        source_path.unlink(missing_ok=True)


def verify_guest_secrets(provider: "GCPProvider", zone: str) -> None:
    """Verify approved dummy payloads through the guest service account."""
    connection = provider.connection
    for secret in provider.gcp.secrets:
        if secret.startswith(f"{provider.config.environment}-"):
            continue
        command = (
            "python3 - <<'PY'\n"
            "import json, urllib.request, hashlib\n"
            "import base64\n"
            "r = urllib.request.Request('http://metadata.google.internal/"
            "computeMetadata/v1/instance/service-accounts/default/token', "
            "headers={'Metadata-Flavor': 'Google'})\n"
            "token = json.load(urllib.request.urlopen(r))['access_token']\n"
            f"url = 'https://secretmanager.googleapis.com/v1/projects/"
            f"{provider.gcp.project_id}/secrets/{secret}/versions/latest:access'\n"
            "r = urllib.request.Request(url, "
            "headers={'Authorization': 'Bearer ' + token})\n"
            "payload = json.load(urllib.request.urlopen(r))['payload']['data']\n"
            "print(hashlib.sha256(base64.b64decode(payload)).hexdigest())\nPY"
        )
        digest = connection.execute(zone, command)
        import hashlib

        assert digest == hashlib.sha256(b"TEST_thisisadummytestsecret_TEST").hexdigest()
        print(f"Guest account accessed {secret}; payload verified without logging it")


def test_sdk_lifecycle_bootstrap_and_cross_region_move(gcp_run: "GCPProvider") -> None:
    from piccolo.providers.gcp.provision import owned, zone_of

    provider = gcp_run
    provider.plan()
    provider.init()
    instance = provider.active()
    zone = zone_of(instance)
    disk = provider.disk(instance)
    assert owned(provider.config, instance)
    assert owned(provider.config, disk)
    assert document(instance["shielded_instance_config"])["enable_secure_boot"] is True
    assert (
        objects(instance, "service_accounts")[0]["email"]
        == provider.gcp.service_account
    )
    assert (
        "https://www.googleapis.com/auth/cloud-platform"
        in objects(instance, "service_accounts")[0]["scopes"]
    )
    assert not any(
        "startup" in text(i, "key")
        for i in objects(document(instance.get("metadata", {})), "items")
    )
    connection = provider.connection
    verify_guest_secrets(provider, zone)
    assert (
        connection.execute(zone, "test ! -e ~/piccolo-live-marker && printf absent")
        == "absent"
    )
    staged = document(provider.journal.data["bootstrap"])
    provider.init()
    assert text(provider.active(), "id") == text(instance, "id")
    assert text(provider.disk(provider.active()), "id") == text(disk, "id")
    assert document(provider.journal.data["bootstrap"]) == staged
    assert provider.config.bootstrap is not None
    script = provider.config.bootstrap.script
    original = script.read_text()
    script.write_text(original + "# changed content\n")
    with pytest.raises(PiccoloError, match="changed"):
        provider.bootstrap(False, False)
    script.write_text(original)
    provider.bootstrap(False, False)
    assert connection.execute(zone, "wc -l < ~/piccolo-live-marker") == "1"
    with pytest.raises(PiccoloError, match="blocked"):
        provider.bootstrap(False, False)
    connection.execute(
        zone,
        "mkdir -p ~/piccolo-repository ~/piccolo-layer; "
        "printf repository > ~/piccolo-repository/sentinel; "
        "printf layer > ~/piccolo-layer/sentinel",
    )
    hash_command = "sha256sum ~/piccolo-repository/sentinel ~/piccolo-layer/sentinel"
    before = connection.execute(zone, hash_command)
    provider.stop()
    assert text(provider.active(), "status") == "TERMINATED"
    provider.start()
    connection.ready(zone)
    destination = next(
        z for z in provider.gcp.zones if z.rsplit("-", 1)[0] != zone.rsplit("-", 1)[0]
    )
    perform_move = not (
        os.environ.get("PICCOLO_GCP_LIVE_MOVE_CASES") == "existing"
        and provider.gcp.create_service_account
    )
    if perform_move:
        provider.move(destination)
    else:
        destination = zone
        print("Created-account case: relocation covered by existing-account case")
    moved = provider.active()
    assert zone_of(moved) == destination
    assert (text(moved, "id") != text(instance, "id")) is perform_move
    assert connection.execute(destination, hash_command) == before
    assert connection.execute(destination, "wc -l < ~/piccolo-live-marker") == "1"
    assert text(provider.bootstrap(False, True), "status") == "completed"
    with pytest.raises(PiccoloError, match="blocked"):
        provider.bootstrap(False, False)
    assert objects(moved, "service_accounts") == objects(instance, "service_accounts")
    assert document(moved["shielded_instance_config"]) == document(
        instance["shielded_instance_config"]
    )
    expected_subnet = provider.cloud.subnet(destination)
    assert objects(moved, "network_interfaces")[0]["subnetwork"] == expected_subnet
    provider.cleanup(False)
    provider.cleanup(True)
    assert text(provider.active(), "id") == text(moved, "id")
    provider.journal.data.pop("bootstrap")
    provider.journal.save()
    with pytest.raises(PiccoloError, match="blocked"):
        provider.bootstrap(False, False)
    print(f"Sentinel hashes preserved:\n{before}")


def test_human_iap_tunnel_and_interruption(gcp_run: "GCPProvider") -> None:
    from piccolo.providers.gcp.connection import GCloudConnection
    from piccolo.providers.gcp.provision import zone_of

    provider = gcp_run
    provider.init()
    zone = zone_of(provider.active())
    connection = GCloudConnection(provider.gcp)
    connection.ready(zone)
    verify_guest_secrets(provider, zone)
    process: subprocess.Popen[bytes] | None = None
    try:
        connection.execute(
            zone,
            "mkdir -p ~/piccolo-live-http; "
            f"printf 'piccolo tunnel {provider.config.environment}' "
            "> ~/piccolo-live-http/index.html; "
            "nohup python3 -m http.server 8080 --bind 0.0.0.0 "
            "--directory ~/piccolo-live-http > ~/piccolo-live-http/log "
            "2>&1 < /dev/null & echo $! > ~/piccolo-live-http/pid",
        )
        gate(provider.gcp.project_id)
        process = subprocess.Popen(
            [
                *connection.launcher(),
                "compute",
                "start-iap-tunnel",
                provider.gcp.name,
                "8080",
                f"--zone={zone}",
                f"--local-host-port=127.0.0.1:{provider.gcp.local_port}",
                *connection.flags(),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=connection.environment(),
            start_new_session=os.name != "nt",
        )
        deadline = time.monotonic() + 90
        while True:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{provider.gcp.local_port}/", timeout=5
                ) as response:
                    assert response.read() == (
                        f"piccolo tunnel {provider.config.environment}".encode()
                    )
                break
            except (urllib.error.URLError, TimeoutError):
                if process.poll() is not None or time.monotonic() >= deadline:
                    pytest.fail("IAP tunnel failed to become ready")
                time.sleep(1)
        assert connection.execute(zone, "printf simultaneous-ssh") == "simultaneous-ssh"
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGINT)
        process.wait(timeout=15)
    finally:
        if process is not None and process.poll() is None:
            if os.name == "nt":
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=15)
        connection.execute(
            zone,
            "if test -f ~/piccolo-live-http/pid; then "
            'kill "$(cat ~/piccolo-live-http/pid)"; fi',
        )


@pytest.mark.parametrize(
    "property_name",
    [
        "access_token_file",
        "credential_file_override",
        "impersonate_service_account",
    ],
)
def test_live_gcloud_persisted_overrides_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    property_name: str,
) -> None:
    """Use real gcloud config parsing in a disposable root before any transport."""
    gate(os.environ.get("PICCOLO_GCP_LIVE_PROJECT", ""))
    base = profile(Path(os.environ["PICCOLO_GCP_LIVE_CONFIG"]))
    from piccolo.providers.gcp.connection import GCloudConnection

    root = tmp_path / "isolated-gcloud"
    configurations = root / "configurations"
    configurations.mkdir(parents=True)
    (root / "active_config").write_text("default")
    (configurations / "config_default").write_text(
        f"[auth]\n{property_name} = unauthorized-test-value\n"
    )
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(root))
    monkeypatch.delenv("CLOUDSDK_ACTIVE_CONFIG_NAME", raising=False)
    connection = GCloudConnection(base.gcp)
    with pytest.raises(PiccoloError, match=property_name):
        connection.execute(base.gcp.zones[0], "true")


def test_live_credential_guards_before_guest_access(
    gcp_run: "GCPProvider",
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify H01/H02 guards against a real run-owned VM without unsafe refresh."""
    from piccolo.providers.gcp.connection import AUTH_OVERRIDES, GCloudConnection
    from piccolo.providers.gcp.provider import GCPProvider
    from piccolo.providers.gcp.provision import zone_of

    provider = gcp_run
    provider.init()
    instance = provider.active()
    zone = zone_of(instance)
    for variable in AUTH_OVERRIDES:
        with monkeypatch.context() as injection:
            injection.setenv(variable, "unauthorized-test-value")
            connection = GCloudConnection(provider.gcp)
            with pytest.raises(PiccoloError, match=variable):
                connection.execute(zone, "true")
            with pytest.raises(PiccoloError, match=variable):
                connection.copy(zone, provider.config.path, "must-not-upload.toml")
            with pytest.raises(PiccoloError, match=variable):
                connection.tunnel(zone)
    path = tmp_path / "untrusted.json"
    for payload in (
        {
            "type": "external_account",
            "credential_source": {"url": "http://127.0.0.1/private"},
        },
        {"type": "authorized_user", "token_uri": "https://untrusted.invalid/token"},
    ):
        path.write_text(json.dumps(payload))
        for source in ("file", "adc"):
            with monkeypatch.context() as injection:
                auth_config = replace(provider.gcp.auth, impersonate_service_account="")
                if source == "file":
                    auth_config = replace(
                        auth_config, mode="file", credential_file=path
                    )
                else:
                    auth_config = replace(auth_config, mode="adc", credential_file=None)
                    injection.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(path))
                changed = replace(
                    provider.config, gcp=replace(provider.gcp, auth=auth_config)
                )
                with pytest.raises(PiccoloError):
                    GCPProvider(changed)
    assert text(provider.active(), "id") == text(instance, "id")
    assert (
        provider.connection.execute(zone, "printf approved-identity")
        == "approved-identity"
    )


@pytest.mark.parametrize(
    "workflow,interruption",
    [
        ("init", "submission"),
        ("init", "poll"),
        ("init", "staging"),
        ("move", "submission"),
        ("move", "poll"),
        ("move", "readiness"),
        ("move", "commit"),
    ],
)
def test_live_later_fallback_recovery(
    gcp_run: "GCPProvider",
    monkeypatch: pytest.MonkeyPatch,
    workflow: str,
    interruption: str,
) -> None:
    """Inject first-zone capacity failure, then interrupt genuine SDK creation.

    The first failure is synthetic; acceptance, operation lookup/polling, SSH,
    staging, and relocation use real run-owned cloud resources.
    """
    from gcp_live_support.gcp_sdk import LiveCloud

    from piccolo.providers.gcp.connection import GCloudConnection
    from piccolo.providers.gcp.provider import GCPProvider
    from piccolo.providers.gcp.provision import zone_of

    provider = gcp_run
    assert isinstance(provider.cloud, LiveCloud)
    cloud = provider.cloud
    if workflow == "move":
        if len(provider.gcp.zones) < 3:
            pytest.skip(
                "Approve three zones to test a move with two fallback candidates"
            )
        provider.init()
        source = provider.active()
        destination_zones = tuple(
            zone for zone in provider.gcp.zones if zone != zone_of(source)
        )
        failed_zone, accepted_zone = destination_zones[:2]
    else:
        failed_zone, accepted_zone = provider.gcp.zones[:2]
    original_submit, original_poll = cloud.submit, cloud.poll
    accepted_operation = ""

    def submit(
        kind: str, name: str, zone: str, resource: Document, request_id: str
    ) -> str:
        nonlocal accepted_operation
        if kind == "instance.insert" and zone == failed_zone:
            # No SDK request is sent for this deterministic capacity failure.
            raise CapacityError("Injected confirmed capacity exhaustion")
        operation = original_submit(kind, name, zone, resource, request_id)
        if kind == "instance.insert" and zone == accepted_zone:
            accepted_operation = operation
            if interruption == "submission":
                raise UncertainError("Injected lost response after real acceptance")
        return operation

    def poll(name: str, zone: str) -> Document:
        if interruption == "poll" and name == accepted_operation:
            raise UncertainError("Injected polling interruption after real acceptance")
        return original_poll(name, zone)

    def readiness(_zone: str) -> None:
        raise PiccoloError("Injected readiness interruption")

    def commit() -> None:
        raise UncertainError("Injected interruption after durable commit")

    with monkeypatch.context() as injection:
        injection.setattr(cloud, "submit", submit)
        injection.setattr(cloud, "poll", poll)
        if interruption in {"staging", "readiness"}:
            injection.setattr(provider.connection, "ready", readiness)
        if interruption == "commit":
            injection.setattr(provider, "commit_cleanup", commit)
        with pytest.raises(PiccoloError):
            if workflow == "init":
                provider.init()
            else:
                provider.move(None)
    assert accepted_operation
    creations = [
        item
        for item in cloud.manifest.entries("actions")
        if text(item, "kind").endswith(".insert")
    ]
    recovered = GCPProvider(provider.config, cloud, GCloudConnection(provider.gcp))
    recovered.resume()
    assert zone_of(recovered.active()) == accepted_zone
    assert not recovered.journal.operation
    assert len(recovered.instances()) == 1
    assert {
        text(item, "key")
        for item in cloud.manifest.entries("actions")
        if text(item, "kind").endswith(".insert")
    } == {text(item, "key") for item in creations}
    accepted = original_poll(accepted_operation, accepted_zone)
    assert text(recovered.active(), "id") == text(accepted, "target_id")
    print(f"Real {workflow} recovery verified after injected {interruption}")


def test_live_unknown_state_preserves_move_recovery(
    gcp_run: "GCPProvider",
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify H04/H05 with real labels, IDs, a stopped source, and a snapshot."""
    from piccolo.providers.gcp.provider import GCPProvider
    from piccolo.providers.gcp.provision import zone_of

    provider = gcp_run
    provider.init()
    source = provider.active()
    foreign = GCPProvider(
        replace(provider.config, environment=provider.config.environment + "-other"),
        provider.cloud,
        provider.connection,
    )
    for command in ("init", "stop", "move"):
        with pytest.raises(PiccoloError, match="ownership"):
            if command == "init":
                foreign.init(adopt=True)
            elif command == "stop":
                foreign.stop()
            else:
                foreign.move(None)
    assert provider.active()["status"] == "RUNNING"
    destination = next(zone for zone in provider.gcp.zones if zone != zone_of(source))

    def unavailable(_zone: str) -> None:
        raise PiccoloError("Injected readiness failure")

    with monkeypatch.context() as injection:
        injection.setattr(provider.connection, "ready", unavailable)
        with pytest.raises(PiccoloError, match="Injected"):
            provider.move(destination)
    operation = provider.journal.operation
    snapshot_name = text(operation, "snapshot")
    snapshot = provider.cloud.get("snapshot", snapshot_name)
    assert snapshot is not None
    with monkeypatch.context() as isolated:
        isolated.setenv("PICCOLO_STATE_DIR", str(tmp_path / "empty-state"))
        unknown = GCPProvider(provider.config, provider.cloud, provider.connection)
        assert not objects(unknown.cleanup(False), "eligible")
        unknown.cleanup(True)
    retained = provider.cloud.get("snapshot", snapshot_name)
    assert retained is not None and retained["id"] == snapshot["id"]
    assert provider.journal.operation == operation
    GCPProvider(provider.config, provider.cloud, provider.connection).resume()


def test_live_shutdown_metadata_guards(
    gcp_run: "GCPProvider",
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Attach only harmless instance hooks; project hooks use a read overlay."""
    from gcp_live_support.gcp_sdk import LiveCloud

    from piccolo.providers.gcp.provision import zone_of

    provider = gcp_run
    provider.init()
    assert isinstance(provider.cloud, LiveCloud)
    cloud = provider.cloud
    instance = provider.active()
    zone = zone_of(instance)
    metadata = document(instance.get("metadata", {}))
    for key in ("shutdown-script", "shutdown-script-url"):
        items = [
            *objects(metadata, "items"),
            {
                "key": key,
                "value": "#!/bin/bash\ntrue\n"
                if key == "shutdown-script"
                else "https://example.invalid/piccolo-harmless-shutdown.sh",
            },
        ]
        try:
            cloud.set_metadata(zone, text(instance, "id"), items)
            for command in ("stop", "move"):
                with pytest.raises(PiccoloError, match="shutdown-script"):
                    if command == "stop":
                        provider.stop()
                    else:
                        provider.move(None)
            assert provider.active()["status"] == "RUNNING"
            assert not provider.journal.operation
        finally:
            cloud.set_metadata(zone, text(instance, "id"), objects(metadata, "items"))
        with monkeypatch.context() as overlay:
            overlay.setattr(
                cloud,
                "project_metadata",
                lambda metadata_key=key: {
                    "items": [{"key": metadata_key, "value": "true"}]
                },
            )
            with pytest.raises(PiccoloError, match="shutdown-script"):
                provider.stop()
    provider.stop()
    provider.start()


if TYPE_CHECKING:
    from piccolo.providers.gcp.provider import GCPProvider
