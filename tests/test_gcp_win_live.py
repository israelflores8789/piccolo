# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_win_live.py — Separately gated native Windows expiration and renewal.

Set PICCOLO_GCP_LIVE_PROJECT to the exact project in the approved TOML profile.
The shared Windows fixture requires a human gcloud connector, independent
provisioner SDK credentials, and a reviewed spending ledger in
PICCOLO_GCP_LIVE_BUDGET_FILE.
"""

import os
import sys
import time
from pathlib import Path

import pytest
from gcp_live_support.deadline import check_work, timeout
from gcp_live_support.ssh_expiry import SSHExpiryProbe, remove_test_key
from test_gcp_live import gcp_run as gcp_run
from test_gcp_live import (
    test_human_source_provisioner_impersonation as impersonation_check,
)
from test_gcp_live import (
    test_live_gcloud_persisted_overrides_are_rejected as persisted_override_check,
)
from test_gcp_live import (
    test_live_security_iap_and_recovery_sequence as security_check,
)
from test_gcp_live import (
    test_sdk_lifecycle_bootstrap_and_cross_region_move as lifecycle_check,
)

from piccolo.providers.gcp.provider import GCPProvider
from piccolo.providers.gcp.provision import zone_of
from piccolo.state.storage import private_file

pytestmark = [
    pytest.mark.gcp_win_live,
    pytest.mark.skipif(sys.platform != "win32", reason="Native Windows only"),
]


def test_native_windows_human_source_impersonation(tmp_path: Path) -> None:
    """Validate the approved human ADC source with provisioner-only SDK access."""
    impersonation_check(tmp_path)


@pytest.mark.parametrize(
    "property_name",
    ["access_token_file", "credential_file_override", "impersonate_service_account"],
)
def test_native_windows_persisted_credential_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, property_name: str
) -> None:
    """Inspect real SDK parsing using only disposable private configurations."""
    persisted_override_check(tmp_path, monkeypatch, property_name)


@pytest.mark.parametrize("bootstrap", [True])
def test_native_windows_lifecycle_bootstrap_and_move(
    gcp_run: GCPProvider, bootstrap: bool
) -> None:
    """Validate native transfers, bootstrap receipts, and ordered relocation."""
    assert bootstrap
    lifecycle_check(gcp_run)
    terminal_acceptance(gcp_run)


def terminal_acceptance(gcp_run: GCPProvider) -> None:
    """Keep a manifest-owned guest available for bounded operator feedback."""
    handoff = os.environ.get("PICCOLO_GCP_LIVE_TERMINAL_FILE")
    if handoff:
        from gcp_live_support.gcp_sdk import LiveCloud

        assert isinstance(gcp_run.cloud, LiveCloud)
        manifest = gcp_run.cloud.manifest
        ready = Path(handoff).with_suffix(".ready")
        with os.fdopen(private_file(ready, create=True, exclusive=True), "w") as stream:
            stream.write(str(manifest.path))
        print(f"Windows Terminal acceptance ready: {manifest.path}", flush=True)
        until = time.monotonic() + 240
        while not Path(handoff).exists():
            check_work()
            if time.monotonic() >= until:
                pytest.fail("Interactive acceptance feedback was not received")
            time.sleep(timeout(2))


@pytest.mark.parametrize("gcp_run", [False], indirect=True, ids=["existing-vm-account"])
def test_native_windows_ordered_move_and_terminal(gcp_run: GCPProvider) -> None:
    """Verify both approved relocations without restaging the validated bootstrap."""
    from test_gcp_live import verify_guest_secrets

    gcp_run.init()
    original = gcp_run.active()
    assert zone_of(original) == gcp_run.gcp.zones[0]
    gcp_run.connection.ready(zone_of(original))
    verify_guest_secrets(gcp_run, zone_of(original))
    checksum = gcp_run.connection.execute(
        zone_of(original),
        "printf 'Windows relocation sentinel' > ~/piccolo-live-sentinel; "
        "sha256sum ~/piccolo-live-sentinel",
    )
    for zone in gcp_run.gcp.zones[1:]:
        gcp_run.move(zone)
        moved = gcp_run.active()
        assert zone_of(moved) == zone
        assert moved["id"] != original["id"]
    assert (
        gcp_run.connection.execute(
            zone_of(gcp_run.active()), "sha256sum ~/piccolo-live-sentinel"
        )
        == checksum
    )
    print("Native ordered west/west/east relocation and sentinel preservation passed")
    terminal_acceptance(gcp_run)


@pytest.mark.parametrize("gcp_run", [False], indirect=True, ids=["existing-vm-account"])
def test_native_windows_terminal_only(gcp_run: GCPProvider) -> None:
    """Provide one approved guest for operator SSH without bootstrap or relocation."""
    gcp_run.init()
    gcp_run.connection.ready(zone_of(gcp_run.active()))
    terminal_acceptance(gcp_run)


@pytest.mark.parametrize("gcp_run", [False], indirect=True, ids=["existing-vm-account"])
def test_native_windows_security_iap_and_recovery(
    gcp_run: GCPProvider, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Check identity guards, dummy access, tunnel interruption, and recovery."""
    security_check(gcp_run, tmp_path, monkeypatch)
    terminal_acceptance(gcp_run)


@pytest.mark.parametrize("gcp_run", [False], indirect=True, ids=["existing-vm-account"])
@pytest.mark.parametrize("mode", ["oslogin", "metadata"])
@pytest.mark.parametrize("transport", ["ssh", "scp"])
def test_native_windows_key_expiration_and_renewal(
    gcp_run: GCPProvider, mode: str, transport: str
) -> None:
    """Exercise native Windows SSH/SCP with only disposable manifest-backed keys."""
    assert gcp_run.config.bootstrap is None
    gcp_run.init()
    probe = SSHExpiryProbe(gcp_run, mode, transport)
    try:
        initial = probe.establish()
        probe.wait_until_rejected(initial[1])
        probe.reconnect(initial)
    finally:
        remove_test_key(gcp_run.config, probe.manifest, probe.entry)
