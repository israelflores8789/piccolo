# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_windows_storage.py — Actual ACL creation, repair, replacement, and redirects."""

import os
import sys
from pathlib import Path

import pytest
from platform_support import assert_private, redirect

from piccolo.config import Config
from piccolo.errors import PiccoloError
from piccolo.state.journal import Journal
from piccolo.state.storage import private_directory, private_file, temporary_directory

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="Native Windows filesystem"
)


def descriptor_bytes(path: Path) -> str:
    import win32security

    descriptor = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION,
    )
    return win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
        descriptor,
        win32security.SDDL_REVISION_1,
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION,
    )


def broaden(path: Path) -> None:
    import ntsecuritycon
    import win32security

    acl = win32security.ACL()
    acl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        ntsecuritycon.FILE_ALL_ACCESS,
        win32security.ConvertStringSidToSid("S-1-1-0"),
    )
    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.UNPROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        acl,
        None,
    )


def test_created_file_is_private_before_first_write(tmp_path: Path) -> None:
    directory = tmp_path / "private"
    private_directory(directory)
    path = directory / "key"
    descriptor = private_file(path, create=True, exclusive=True)
    try:
        assert_private(path)
        os.write(descriptor, b"private bytes")
    finally:
        os.close(descriptor)
    assert_private(path)


def test_repair_owned_dacl_and_atomic_journal_replacement(config: Config) -> None:
    journal = Journal(config)
    journal.begin({"kind": "init", "id": "original"})
    for path in (journal.directory.parent, journal.directory, journal.path):
        broaden(path)
    restored = Journal(config)
    assert_private(restored.directory.parent, directory=True)
    assert_private(restored.directory, directory=True)
    assert_private(restored.path)
    restored.update({"kind": "init", "id": "replacement"})
    assert_private(restored.path)
    assert Journal(config).operation["id"] == "replacement"


def test_leaf_directory_does_not_restrict_shared_ancestors(tmp_path: Path) -> None:
    before = descriptor_bytes(tmp_path)
    private_directory(tmp_path / "new-parent" / "leaf")
    assert descriptor_bytes(tmp_path) == before
    assert_private(tmp_path / "new-parent", directory=True)
    assert_private(tmp_path / "new-parent" / "leaf", directory=True)


def test_hardlink_is_rejected_without_repairing_victim(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"unchanged")
    alias = tmp_path / "alias"
    os.link(victim, alias)
    before = descriptor_bytes(victim)
    with pytest.raises(PiccoloError, match="one link"):
        private_file(alias)
    assert victim.read_bytes() == b"unchanged"
    assert descriptor_bytes(victim) == before


@pytest.mark.parametrize("leaf", [True, False])
def test_directory_junction_is_rejected_without_touching_target(
    tmp_path: Path, leaf: bool
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"unchanged")
    alias = tmp_path / "alias"
    redirect(alias, outside, directory=True)
    before = descriptor_bytes(outside)
    with pytest.raises(PiccoloError, match="unredirected"):
        if leaf:
            private_directory(alias)
        else:
            private_file(alias / "secret")
    assert descriptor_bytes(outside) == before
    assert (outside / "secret").read_bytes() == b"unchanged"


def test_parents_remain_pinned_during_leaf_open(tmp_path: Path) -> None:
    from piccolo.state.windows import parents

    parent = tmp_path / "parent"
    parent.mkdir()
    with parents(parent / "file"), pytest.raises(PermissionError):
        os.rename(parent, tmp_path / "replacement")
    os.rename(parent, tmp_path / "replacement")


def test_private_temporary_directory_cleans_on_exception() -> None:
    path: Path | None = None
    with pytest.raises(RuntimeError), temporary_directory("piccolo-test-") as directory:
        path = directory
        assert_private(directory, directory=True)
        with os.fdopen(
            private_file(directory / "artifact", create=True), "wb"
        ) as stream:
            stream.write(b"private")
        assert_private(directory / "artifact")
        raise RuntimeError("injected failure")
    assert path is not None and not path.exists()
