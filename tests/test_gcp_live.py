# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_live.py — Explicitly opted-in real SDK lifecycle and human IAP checks.

Set PICCOLO_GCP_LIVE_PROJECT to the approved TOML project before live tests.
All project-qualified test account addresses use that validated project.
The Windows fixture uses the same human gcloud connector as every live profile;
the provisioner is selected independently through SDK credentials and the
existing VM account is supplied by gcp.instance.service_account.
The shared profile requires a human gcp.ssh.account for connections,
independently of whether the SDK impersonation case is selected.
The impersonation case also requires PICCOLO_GCP_LIVE_HUMAN_ADC.

Before running, label every existing secret listed in gcp.iam.secrets with
piccolo-live-dummy=true on the secret resource in GCP (for example, through
the Google Cloud console). Listing a secret in TOML does not set this label.
Each secret must contain TEST_thisisadummytestsecret_TEST, and the provisioner
must have permission to read its payload. The harness checks both the label
and the payload before granting the guest service account access, to avoid
exposing real secrets to test VMs. Arrange these prerequisites out of band;
the harness does not add the label or replace existing secret contents.
"""

import json
import os
import shlex
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Generator
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from gcp_live_support.deadline import (
    ACTIVE,
    bind_client,
    check_work,
    fixture_time_available,
    timeout,
)
from gcp_live_support.gcp_live import (
    approval_digest,
    local_preflight,
    preflight,
    profile,
    provisioner_identity,
    run_config,
)
from gcp_live_support.manifest import Manifest, cleanup, gate

from piccolo.data import Document, document, objects, text
from piccolo.errors import CapacityError, PiccoloError, UncertainError
from piccolo.logger import emit, log
from piccolo.privacy import sanitize_text

pytestmark = [
    pytest.mark.gcp_live,
    pytest.mark.skipif(
        sys.platform == "win32", reason="Native Windows live tests use --gcp-win-live"
    ),
]


@pytest.fixture(
    params=[False, True], ids=["existing-vm-account", "piccolo-created-account"]
)
def gcp_run(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    isolated_state: None,
) -> Generator["GCPProvider"]:
    del isolated_state
    gcp_win_live = request.config.getoption("--gcp-win-live")
    if not (request.config.getoption("--gcp-live") or gcp_win_live):
        pytest.skip("requires an explicit provider/platform live selection")
    gate(os.environ.get("PICCOLO_GCP_LIVE_PROJECT", ""))
    path = os.environ.get("PICCOLO_GCP_LIVE_CONFIG")
    if not path:
        pytest.fail("Set PICCOLO_GCP_LIVE_CONFIG to the approved local TOML profile")
    base = profile(Path(path))
    if gcp_win_live and not os.environ.get("PICCOLO_GCP_LIVE_BUDGET_FILE"):
        pytest.fail("Windows live tests require an explicitly reviewed spending ledger")
    if request.node.callspec.params.get("workflow") == "init" and (
        initial_zone := os.environ.get("PICCOLO_GCP_LIVE_INIT_ZONE")
    ):
        # Reject the other west zone synthetically; create only in the approved zone.
        failed_zone = next(z for z in base.gcp.zones if z != initial_zone)
        base = replace(
            base,
            gcp=replace(
                base.gcp,
                zones=(
                    failed_zone,
                    initial_zone,
                    *(
                        z
                        for z in base.gcp.zones
                        if z not in {failed_zone, initial_zone}
                    ),
                ),
            ),
        )
    local_preflight(base)
    if not fixture_time_available():
        pytest.skip("Less than two minutes of work time remain for a new VM fixture")
    from gcp_live_support.gcp_sdk import LiveCloud
    from gcp_live_support.gcp_sdk import LiveProvider as GCPProvider
    from google.cloud import service_usage_v1

    from piccolo.providers.gcp.auth import credentials
    from piccolo.providers.gcp.clients import Clients
    from piccolo.providers.gcp.connection import GCloudConnection
    from piccolo.state.lock import environment_lock

    run = f"plive-{uuid.uuid4().hex[:16]}"
    directory = Path(".test_runs").resolve() / run
    config = run_config(
        base,
        directory,
        run,
        create_account=bool(request.param),
        bootstrap=bool(request.node.callspec.params.get("bootstrap", not gcp_win_live)),
    )
    manifest = Manifest.create(
        directory / "manifest.json", config.path, run, project=config.gcp.project_id
    )
    manifest.data["approval_sha256"] = approval_digest(base)
    manifest.data["run_settings_fingerprint"] = config.fingerprint
    manifest.data["test"] = request.node.nodeid
    manifest.data["guest_account_variant"] = "created" if request.param else "existing"
    deadline = ACTIVE.get()
    manifest.data["deadline_seconds"] = deadline.total_seconds if deadline else 2700
    manifest.data["cleanup_command"] = (
        f"just janitor-gcp-live {shlex.quote(str(manifest.path))} 1"
    )
    manifest.save()
    log(f"Durable cleanup manifest: {manifest.path}")
    log(f"Independent cleanup: {text(manifest.data, 'cleanup_command')}")
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
        provider = GCPProvider(config, cloud)
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
            emit(
                {
                    "manifest": str(manifest.path),
                    "residual_cost_exposure": manifest.data.get(
                        "residual_cost_exposure"
                    ),
                }
            )
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
    from piccolo.state.storage import private_file

    descriptor = private_file(source_path, create=True, exclusive=True)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(source, stream)
        config = replace(
            base.gcp,
            auth=replace(
                base.gcp.auth,
                mode="file",
                credentials_file=source_path,
                impersonate_service_account=target,
            ),
        )
        impersonated = credentials(config)
        assert isinstance(impersonated, impersonated_credentials.Credentials)
        assert provisioner_identity(impersonated, base) == target
        client = resourcemanager_v3.ProjectsClient(credentials=impersonated)
        bind_client(client)
        project = client.get_project(
            name=f"projects/{base.gcp.project_id}", timeout=timeout()
        )
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
        from gcp_live_support.gcp_sdk import LiveCloud

        assert isinstance(provider.cloud, LiveCloud)
        entry = provider.cloud.manifest.lookup("secret", secret)
        assert entry is not None
        version = text(entry, "dummy_version")
        assert version
        command = (
            "python3 - <<'PY'\n"
            "import json, urllib.request, hashlib\n"
            "import base64\n"
            "r = urllib.request.Request('http://metadata.google.internal/"
            "computeMetadata/v1/instance/service-accounts/default/token', "
            "headers={'Metadata-Flavor': 'Google'})\n"
            "token = json.load(urllib.request.urlopen(r))['access_token']\n"
            f"url = 'https://secretmanager.googleapis.com/v1/projects/"
            f"{version.removeprefix('projects/')}:access'\n"
            "r = urllib.request.Request(url, "
            "headers={'Authorization': 'Bearer ' + token})\n"
            "payload = json.load(urllib.request.urlopen(r))['payload']['data']\n"
            "print(hashlib.sha256(base64.b64decode(payload)).hexdigest())\nPY"
        )
        digest = connection.execute(zone, command)
        import hashlib

        assert digest == hashlib.sha256(b"TEST_thisisadummytestsecret_TEST").hexdigest()
        print(f"Guest account accessed {secret}; payload verified without logging it")


def test_live_move_settings_and_data(gcp_run: "GCPProvider") -> None:
    """Exercise relocation settings, guest identity, and disk data."""
    from piccolo.providers.gcp.provision import zone_of

    provider = gcp_run
    provider.init()
    source = provider.active()
    zone = zone_of(source)
    assert provider.connection.execute(
        zone,
        "printf piccolo-move-sentinel > ~/piccolo-live-sentinel; "
        "sha256sum ~/piccolo-live-sentinel",
    )
    before = provider.connection.execute(zone, "sha256sum ~/piccolo-live-sentinel")
    destination = next(z for z in provider.gcp.zones if z != zone)
    provider.move(destination)
    moved = provider.active()
    assert zone_of(moved) == destination
    assert text(moved, "id") != text(source, "id")
    assert (
        provider.connection.execute(destination, "sha256sum ~/piccolo-live-sentinel")
        == before
    )
    assert objects(moved, "service_accounts") == objects(source, "service_accounts")
    assert moved["shielded_instance_config"] == source["shielded_instance_config"]
    provider.cleanup(True)


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
    scopes = objects(instance, "service_accounts")[0]["scopes"]
    assert isinstance(scopes, list)
    assert "https://www.googleapis.com/auth/cloud-platform" in scopes
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
    original = script.read_bytes()
    script.write_bytes(original + b"# changed content\n")
    with pytest.raises(PiccoloError, match="changed"):
        provider.bootstrap(False, False)
    script.write_bytes(original)
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
    destination = zone
    perform_move = not (
        os.environ.get("PICCOLO_GCP_LIVE_MOVE_CASES") == "existing"
        and provider.gcp.create_service_account
    )
    if perform_move:
        for target in provider.gcp.zones:
            if target != zone:
                provider.move(target)
                destination = target
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


@pytest.mark.parametrize("mode", ["oslogin", "metadata"])
@pytest.mark.parametrize("transport", ["ssh", "scp"])
def test_live_ssh_key_expire_and_reconnect(
    gcp_run: "GCPProvider", mode: str, transport: str
) -> None:
    """Prove expired-key rejection, then gcloud renewal on SSH and SCP reconnect."""
    from gcp_live_support.gcp_sdk import LiveCloud
    from gcp_live_support.gcp_sdk import LiveProvider as GCPProvider
    from gcp_live_support.ssh_expiry import SSHExpiryProbe

    assert isinstance(gcp_run.cloud, LiveCloud)
    gcp_run.cloud.ssh_login_mode = mode
    provider = GCPProvider(replace(gcp_run.config, bootstrap=None), gcp_run.cloud)
    provider.init()
    probe = SSHExpiryProbe(provider, mode, transport)
    initial = probe.establish()
    probe.wait_until_rejected(initial[1])
    probe.reconnect(initial)
    print(
        f"Verified {mode}/{transport}: key rejected after expiry, "
        "then reauthorized with the same public key"
    )


def test_human_iap_tunnel_and_interruption(gcp_run: "GCPProvider") -> None:
    from piccolo.providers.gcp.connection import GCloudConnection
    from piccolo.providers.gcp.provision import zone_of

    provider = gcp_run
    provider.init()
    zone = zone_of(provider.active())
    connection = GCloudConnection(
        provider.gcp, provider.connection_target, provider.cloud.host_keys
    )
    connection.ready(zone)
    verify_guest_secrets(provider, zone)
    process: subprocess.Popen[bytes] | None = None
    containment = ExitStack()
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
        check_work()
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
        if os.name == "nt":
            from piccolo.win32process import process_job

            containment.enter_context(process_job(process.pid))
        deadline = time.monotonic() + 90
        while True:
            check_work()
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{provider.gcp.local_port}/", timeout=timeout(5)
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
        containment.close()
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
        connection.environment()


def test_live_credential_guards_before_guest_access(
    gcp_run: "GCPProvider",
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify H01/H02 guards against a real run-owned VM without unsafe refresh."""
    from gcp_live_support.gcp_sdk import LiveProvider as GCPProvider

    from piccolo.providers.gcp.connection import AUTH_OVERRIDES, GCloudConnection
    from piccolo.providers.gcp.provision import zone_of

    provider = gcp_run
    provider.init()
    instance = provider.active()
    zone = zone_of(instance)
    for variable in AUTH_OVERRIDES:
        with monkeypatch.context() as injection:
            injection.setenv(variable, "unauthorized-test-value")
            connection = GCloudConnection(
                provider.gcp, provider.connection_target, provider.cloud.host_keys
            )
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
                        auth_config, mode="file", credentials_file=path
                    )
                else:
                    auth_config = replace(
                        auth_config, mode="adc", credentials_file=None
                    )
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
    from gcp_live_support.gcp_sdk import LiveProvider as GCPProvider

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
    original_created = provider.created
    accepted_operation = {"name": ""}

    def submit(
        kind: str, name: str, zone: str, resource: Document, request_id: str
    ) -> str:
        if zone == failed_zone and (
            kind == "instance.insert" or (workflow == "init" and kind == "disk.insert")
        ):
            # No SDK request is sent for this deterministic capacity failure.
            raise CapacityError("Injected confirmed capacity exhaustion")
        operation = original_submit(kind, name, zone, resource, request_id)
        if kind == "instance.insert" and zone == accepted_zone:
            accepted_operation["name"] = operation
            if interruption == "submission":
                raise UncertainError("Injected lost response after real acceptance")
        return operation

    def poll(name: str, zone: str) -> Document:
        if interruption == "poll" and name == accepted_operation["name"]:
            raise UncertainError("Injected polling interruption after real acceptance")
        return original_poll(name, zone)

    def created(kind: str, name: str, zone: str, resource: Document) -> Document:
        if workflow == "init" and kind == "disk" and zone == failed_zone:
            provider.operations.run(
                f"disk.insert:{zone}:{name}", "disk.insert", name, zone, resource
            )
            raise PiccoloError("Synthetic failure unexpectedly accepted a disk")
        return original_created(kind, name, zone, resource)

    def readiness(_zone: str) -> None:
        raise PiccoloError("Injected readiness interruption")

    def commit() -> None:
        raise UncertainError("Injected interruption after durable commit")

    with monkeypatch.context() as injection:
        injection.setattr(cloud, "submit", submit)
        injection.setattr(cloud, "poll", poll)
        injection.setattr(provider, "created", created)
        if interruption in {"staging", "readiness"}:
            injection.setattr(provider.connection, "ready", readiness)
        if interruption == "commit":
            injection.setattr(provider, "commit_cleanup", commit)
        with pytest.raises(PiccoloError) as interrupted:
            if workflow == "init":
                provider.init()
            else:
                provider.move(None)
    assert accepted_operation["name"], sanitize_text(str(interrupted.value))
    creations = [
        item
        for item in cloud.manifest.entries("actions")
        if text(item, "kind").endswith(".insert")
    ]
    recovered = GCPProvider(provider.config, cloud)
    recovered.resume()
    assert zone_of(recovered.active()) == accepted_zone
    assert not recovered.journal.operation
    assert len(recovered.instances()) == 1
    assert {
        text(item, "key")
        for item in cloud.manifest.entries("actions")
        if text(item, "kind").endswith(".insert")
    } == {text(item, "key") for item in creations}
    accepted = original_poll(accepted_operation["name"], accepted_zone)
    assert text(recovered.active(), "id") == text(accepted, "target_id")
    print(f"Real {workflow} recovery verified after injected {interruption}")


def test_live_unknown_state_preserves_move_recovery(
    gcp_run: "GCPProvider",
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify H04/H05 with real labels, IDs, a stopped source, and a snapshot."""
    from gcp_live_support.gcp_sdk import LiveProvider as GCPProvider

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
    *,
    exercise_power: bool = True,
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
        items: list[Document] = [
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
    if exercise_power:
        provider.stop()
        provider.start()


def test_live_security_iap_and_recovery_sequence(
    gcp_run: "GCPProvider",
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reuse one guest for credential, shutdown, tunnel, and recovery assertions."""
    test_live_credential_guards_before_guest_access(gcp_run, tmp_path, monkeypatch)
    print("Live credential guards passed", flush=True)
    test_live_shutdown_metadata_guards(gcp_run, monkeypatch, exercise_power=False)
    print("Live shutdown-hook guards passed", flush=True)
    test_human_iap_tunnel_and_interruption(gcp_run)
    print("Live IAP forwarding and interruption passed", flush=True)
    test_live_unknown_state_preserves_move_recovery(gcp_run, tmp_path, monkeypatch)
    print("Live ownership, retained recovery, and resume checks passed", flush=True)


@pytest.mark.parametrize("mode", ["oslogin", "metadata"])
def test_live_ssh_expiry_transport_sequence(gcp_run: "GCPProvider", mode: str) -> None:
    """Observe SSH and SCP expiration independently on one guest per login mode."""
    from gcp_live_support.gcp_sdk import LiveCloud
    from gcp_live_support.gcp_sdk import LiveProvider as GCPProvider
    from gcp_live_support.ssh_expiry import SSHExpiryProbe

    assert isinstance(gcp_run.cloud, LiveCloud)
    gcp_run.cloud.ssh_login_mode = mode
    provider = GCPProvider(replace(gcp_run.config, bootstrap=None), gcp_run.cloud)
    provider.init()
    for transport in ("ssh", "scp"):
        probe = SSHExpiryProbe(provider, mode, transport)
        initial = probe.establish()
        probe.wait_until_rejected(initial[1])
        probe.reconnect(initial)
        print(
            f"Verified {mode}/{transport}: expired-key rejection and same-key renewal"
        )


if TYPE_CHECKING:
    from piccolo.providers.gcp.provider import GCPProvider
