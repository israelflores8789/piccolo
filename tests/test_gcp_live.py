# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_live.py — Explicitly opted-in real SDK lifecycle and human IAP checks.

Set PICCOLO_GCP_LIVE_PROJECT to the approved TOML project before live tests.
"""

import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from gcp_live_support.gcp_live import preflight, profile, run_config
from gcp_live_support.manifest import Manifest, cleanup, gate

from piccolo.data import document, objects, text
from piccolo.errors import PiccoloError

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
    from gcp_live_support.gcp_sdk import LiveCloud

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
    for variable in (
        "CLOUDSDK_AUTH_ACCESS_TOKEN",
        "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
        "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
    ):
        if os.environ.get(variable):
            pytest.fail(f"Unset {variable} so gcloud uses the approved human account")
    with environment_lock(config):
        cloud = LiveCloud(config, Clients(credentials(config.gcp)), manifest)
        provider = GCPProvider(config, cloud, GCloudConnection(config.gcp))
        try:
            preflight(config, cloud, GCloudConnection(config.gcp))
            existing = cloud.get("account", base.gcp.service_account)
            if existing is None or existing.get("disabled") is True:
                pytest.fail("Precreate and enable the approved VM service account")
            cloud.create_secret(f"{run}-dummy")
            yield provider
        finally:
            failures = cleanup(manifest, cloud, apply=True)
            if failures:
                pytest.fail(
                    "Teardown incomplete; resources may incur costs. "
                    f"Retained manifest: {manifest.path}\n" + "\n".join(failures)
                )
            print(f"Zero leftovers verified: {manifest.path}", flush=True)


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
    provider.move(destination)
    moved = provider.active()
    assert zone_of(moved) == destination
    assert text(moved, "id") != text(instance, "id")
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


if TYPE_CHECKING:
    from piccolo.providers.gcp.provider import GCPProvider
