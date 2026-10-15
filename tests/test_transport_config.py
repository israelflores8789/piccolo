# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_transport_config.py — IAP and SSH configuration policy."""

from pathlib import Path

import pytest

from piccolo.config import Config, load
from piccolo.errors import PiccoloError


def test_private_defaults_and_finite_ssh_lifetime(config: Config) -> None:
    assert config.gcp.external_ip is False
    assert config.gcp.expire_after == "24h"
    assert config.gcp.require_passphrase is False


@pytest.mark.parametrize("source", ["0.0.0.0/0", "10.0.0.0/8", "::/0"])
def test_iap_source_ranges_cannot_widen(config_path: Path, source: str) -> None:
    config_path.write_text(
        config_path.read_text() + f'[gcp.iap]\nsource_ranges=["{source}"]\n'
    )
    with pytest.raises(PiccoloError, match="IAP source ranges"):
        load(config_path)


@pytest.mark.parametrize(
    "snippet",
    [
        "via_iap=false\n",
        "internal_ip=true\n",
        'expire-after="0h"\n',
        'expire-after="never"\n',
    ],
)
def test_invalid_transport_policy(config_path: Path, snippet: str) -> None:
    config_path.write_text(config_path.read_text() + snippet)
    with pytest.raises(PiccoloError, match=r"gcp\.ssh"):
        load(config_path)


def test_internal_transport_is_explicit(config_path: Path) -> None:
    config_path.write_text(
        config_path.read_text() + "via_iap=false\ninternal_ip=true\n"
        'expire-after="12h"\nrequire_passphrase=true\n'
    )
    gcp = load(config_path).gcp
    assert gcp.internal_ip and gcp.require_passphrase
    assert gcp.expire_after == "12h"
