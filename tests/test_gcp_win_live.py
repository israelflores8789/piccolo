# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_gcp_win_live.py — Separately gated native Windows expiration and renewal."""

import sys

import pytest
from gcp_live_support.ssh_expiry import SSHExpiryProbe, remove_test_key
from test_gcp_live import gcp_run as gcp_run

from piccolo.providers.gcp.provider import GCPProvider

pytestmark = [
    pytest.mark.gcp_win_live,
    pytest.mark.skipif(sys.platform != "win32", reason="Native Windows only"),
]


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
