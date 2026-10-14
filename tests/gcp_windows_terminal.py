# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""gcp_windows_terminal.py — Bounded Git Bash/native OpenSSH live acceptance."""

import argparse
import os
from pathlib import Path

from gcp_live_support.deadline import live_session
from gcp_live_support.gcp_live import provisioner_identity
from gcp_live_support.gcp_sdk import LiveCloud, LiveProvider
from gcp_live_support.manifest import Manifest, gate

from piccolo.config import load
from piccolo.data import text
from piccolo.errors import PiccoloError
from piccolo.providers.gcp.auth import credentials
from piccolo.providers.gcp.clients import Clients
from piccolo.providers.gcp.provision import zone_of


def main() -> None:
    """Connect only to the unchanged active VM recorded in the approved manifest."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    manifest = Manifest.open(args.manifest)
    gate(text(manifest.data, "project"))
    config = load(Path(text(manifest.data, "config")))
    gate(config.gcp.project_id)
    if config.fingerprint != text(manifest.data, "run_settings_fingerprint"):
        raise PiccoloError("Terminal acceptance settings changed")
    os.environ["PICCOLO_STATE_DIR"] = str(manifest.directory / "state")
    with live_session():
        auth = credentials(config.gcp)
        identity = provisioner_identity(auth, config)
        expected = (
            f"piccolo-test-provisioner@{config.gcp.project_id}.iam.gserviceaccount.com"
        )
        if identity != expected:
            raise PiccoloError(
                "Terminal SDK credentials must be the approved provisioner"
            )
        cloud = LiveCloud(config, Clients(auth), manifest, provisioner=identity)
        provider = LiveProvider(config, cloud)
        instance = provider.active()
        zone = zone_of(instance)
        entry = manifest.lookup("instance", config.gcp.name, zone)
        if entry is None or not cloud.owns(entry, instance):
            raise PiccoloError("Terminal VM identity is unproven")
        provider.connection.shell(zone)


if __name__ == "__main__":
    try:
        main()
    except PiccoloError as exc:
        print(f"Terminal acceptance failed: {exc}")
        raise SystemExit(1) from None
