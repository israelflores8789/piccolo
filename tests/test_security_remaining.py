# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""test_security_remaining.py — Offline privacy, retention, and recovery regressions."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest
from conftest import FakeCloud, GuestConnection
from platform_support import assert_private, redirect

from piccolo.config import Config, load
from piccolo.data import document, text
from piccolo.errors import PiccoloError, UncertainError
from piccolo.logger import emit, log, reporter
from piccolo.privacy import REDACTED, remember_secrets, sanitize, sanitize_text
from piccolo.providers.gcp.provider import GCPProvider
from piccolo.state.journal import Journal
from piccolo.state.lock import environment_lock


@pytest.mark.parametrize(
    "field",
    [
        "private_key",
        "privateKey",
        "refresh_token",
        "accessToken",
        "client_secret",
        "password",
        "authorization",
        "api-key",
        "disk_encryption_key",
        "token",
        "secret",
    ],
)
def test_recursive_credential_redaction(field: str) -> None:
    original = document(
        {"id": "resource-42", "nested": [{field: "confidential-value"}]}
    )
    assert "confidential-value" not in json.dumps(sanitize(original))
    assert document(sanitize(original))["id"] == "resource-42"
    assert "confidential-value" in json.dumps(original)


@pytest.mark.parametrize(
    "message,secret",
    [
        ('{"private_key":"abc\\ndef", "name":"vm"}', "abc"),
        ('password="words with spaces"', "words with spaces"),
        ("access_token='opaque value'", "opaque value"),
        ("Authorization: Bearer fake-token-material", "fake-token-material"),
        ("Authorization=opaque-token", "opaque-token"),
        ("https://user:password@example.com/", "user:password"),
        ("https://example.com/?X-Goog-Signature=opaque-signature", "opaque-signature"),
        (
            "-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----",
            "secret material",
        ),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntruncated sensitive material",
            "sensitive material",
        ),
        ("ya29.mocked-access-token", "mocked-access-token"),
        ("1//mocked-refresh-token", "mocked-refresh-token"),
    ],
)
def test_text_redaction(message: str, secret: str) -> None:
    result = sanitize_text(message)
    assert secret not in result
    assert REDACTED in result
    assert sanitize_text(result) == result


def test_console_errors_and_notifications_share_redaction(
    capsys: pytest.CaptureFixture[str],
) -> None:
    remember_secrets({"private_key": "registered-unique-private-key"})
    log("unlabelled registered-unique-private-key")
    emit(
        {
            "source": {
                "metadata": {"custom": "opaque-secret"},
                "description": "opaque-description",
            }
        }
    )
    log(str(PiccoloError("client_secret=secret-material")), err=True)
    output = capsys.readouterr()
    assert "registered-unique-private-key" not in output.out
    assert "opaque-secret" not in output.out
    assert "opaque-description" not in output.out
    assert "secret-material" not in output.err
    rendered_json = output.out[output.out.index("{") :]
    assert json.loads(rendered_json)["source"]["metadata"] == REDACTED
    sink = Mock()
    reporter(sink)("password=secret-material")
    assert "secret-material" not in sink.call_args.args[0]


def test_move_rereads_metadata_without_persisting_it_and_retains_recovery(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
) -> None:
    provider = GCPProvider(config, cloud, connection)
    provider.init()
    source = cloud.resources[("instance", "test-vm", "us-west1-a")]
    source["metadata"] = {"items": [{"key": "custom", "value": "opaque-secret"}]}
    source["description"] = "opaque-description"
    connection.readiness_failure = True
    with pytest.raises(PiccoloError):
        provider.move("us-east1-b")
    persisted = provider.journal.path.read_text()
    assert "opaque-secret" not in persisted
    assert "opaque-description" not in persisted
    assert "opaque-secret" not in json.dumps(provider.inspect())
    connection.readiness_failure = False
    recovered = GCPProvider(config, cloud, connection)
    recovered.resume()
    assert recovered.active()["metadata"] == source["metadata"]
    assert recovered.active()["description"] == "opaque-description"
    assert len(cloud.list("snapshot")) == 1
    assert len(cloud.list("disk")) == 2
    assert len(recovered.cleanup(False)["eligible"]) == 2
    recovered.cleanup(True)
    assert not cloud.list("snapshot")
    assert len(cloud.list("disk")) == 1


def test_state_repairs_owned_modes_and_redacts_errors(config: Config) -> None:
    journal = Journal(config)
    journal.begin(
        {"kind": "init", "id": "request", "error": "password=secret-material"}
    )
    journal.directory.parent.chmod(0o777)
    journal.directory.chmod(0o755)
    journal.path.chmod(0o644)
    restored = Journal(config)
    assert_private(restored.directory.parent, directory=True)
    assert_private(restored.directory, directory=True)
    assert_private(restored.path)
    assert "secret-material" not in restored.path.read_text()
    with environment_lock(config):
        assert_private(journal.directory / "lock")


@pytest.mark.parametrize(
    "target", ["root", "environment", "journal", "lock", "hardlink"]
)
def test_state_rejects_symlinks_and_hardlinks(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim"
    victim.write_text("must remain untouched")
    journal = Journal(config)
    if target == "root":
        root = tmp_path / "redirected-state"
        redirect(root, outside, directory=True)
        monkeypatch.setenv("PICCOLO_STATE_DIR", str(root))
    else:
        journal.directory.parent.mkdir(mode=0o700)
        if target == "environment":
            redirect(journal.directory, outside, directory=True)
        else:
            journal.directory.mkdir(mode=0o700)
            path = journal.directory / ("lock" if target == "lock" else "state.json")
            if target == "hardlink":
                os.link(victim, path)
            else:
                redirect(path, victim)
    with pytest.raises(PiccoloError):
        if target == "lock":
            with environment_lock(config):
                pytest.fail("Lock symlink was accepted")
        else:
            Journal(config)
    assert victim.read_text() == "must remain untouched"


def test_state_rejects_foreign_ownership(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = Journal(config)
    journal.begin({"kind": "init"})
    if sys.platform == "win32":
        import win32security

        monkeypatch.setattr(
            "piccolo.state.windows.current_sid",
            lambda: win32security.ConvertStringSidToSid("S-1-5-18"),
        )
    else:
        monkeypatch.setattr("piccolo.state.storage.os.getuid", lambda: -1)
    with pytest.raises(PiccoloError, match="not owned"):
        Journal(config)


def test_state_rejects_parent_traversal_after_a_symlink(
    config: Config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    redirect = tmp_path / "redirect"
    from platform_support import redirect as make_redirect

    make_redirect(redirect, outside, directory=True)
    monkeypatch.setenv("PICCOLO_STATE_DIR", str(redirect / ".." / "state"))
    with pytest.raises(PiccoloError, match="parent traversal"):
        Journal(config)


@pytest.mark.parametrize("status", ["started", "uncertain"])
def test_bootstrap_blocks_stop_and_resumed_stop(
    config: Config,
    cloud: FakeCloud,
    connection: GuestConnection,
    status: str,
) -> None:
    provider = GCPProvider(config, cloud, connection)
    provider.init()
    instance_id = text(provider.active(), "id")
    provider.journal.data["bootstrap"] = {"status": status}
    provider.journal.save()
    count = len(cloud.calls)
    with pytest.raises(PiccoloError, match="Bootstrap may still be running"):
        provider.stop()
    assert not provider.journal.operation
    provider.journal.begin(
        {
            "kind": "stop",
            "id": "request",
            "zone": "us-west1-a",
            "instance_id": instance_id,
        }
    )
    with pytest.raises(PiccoloError, match="Bootstrap may still be running"):
        GCPProvider(config, cloud, connection).resume()
    assert len(cloud.calls) == count


def test_status_exposes_process_and_repairs_cancelled_receipt(
    config_path: Path,
    cloud: FakeCloud,
    connection: GuestConnection,
) -> None:
    (config_path.parent / "setup.sh").write_text("#!/bin/bash\ntrue\n")
    config_path.write_text(
        config_path.read_text()
        + '[bootstrap]\nscript="setup.sh"\nexecution_user="researcher"\n'
    )
    provider = GCPProvider(load(config_path), cloud, connection)
    provider.init()
    record = document(provider.journal.data["bootstrap"])
    record["status"] = "started"
    provider.journal.data["bootstrap"] = record
    provider.journal.save()
    receipt = connection.directory / text(record, "receipt")
    receipt.mkdir()
    (receipt / "process-id").write_text("12345\n")
    observed = provider.bootstrap(False, True)
    assert observed["process_id"] == observed["process_group_id"] == 12345
    (receipt / "exit-code").write_text("130\n")
    assert provider.bootstrap(False, True)["status"] == "failed"
    provider.stop()
    with pytest.raises(PiccoloError, match="blocked"):
        provider.bootstrap(False, False)


def test_bootstrap_deadline_keeps_detached_process_until_observed_completion(
    config_path: Path,
    cloud: FakeCloud,
    connection: GuestConnection,
) -> None:
    script = config_path.parent / "slow.sh"
    script.write_text(
        "#!/bin/bash\n# Copyright 2026 Israel Flores-Arbolay\n"
        "# SPDX-License-Identifier: Apache-2.0\nsleep 2\n"
        'printf completed > "$HOME/slow-completed"\n'
    )
    config_path.write_text(
        config_path.read_text() + '[bootstrap]\nscript="slow.sh"\n'
        'execution_user="researcher"\ntimeout=1\n'
    )
    provider = GCPProvider(load(config_path), cloud, connection)
    provider.init()
    with pytest.raises(UncertainError, match="not cancelled"):
        provider.bootstrap(False, False)
    observed = provider.bootstrap(False, True)
    assert observed["status"] == "started"
    assert observed["process_id"] == observed["process_group_id"]
    with pytest.raises(PiccoloError, match="Bootstrap may still be running"):
        provider.stop()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if provider.bootstrap(False, True)["status"] == "completed":
            break
        time.sleep(0.05)
    assert provider.bootstrap(False, True)["status"] == "completed"
    assert (connection.directory / "slow-completed").read_text() == "completed"
    assert any("nohup setsid bash" in command for command in connection.commands)


def test_canonical_fingerprint_accepts_formatting_defaults_and_key_order(
    config: Config,
) -> None:
    journal = Journal(config)
    journal.begin({"kind": "init"})
    source = config.path.read_text()
    source = source.replace(
        'schema_version = 1\nenvironment = "test-env"\nprovider = "gcp"',
        'provider="gcp"\n# reviewed comment\nenvironment="test-env"',
    )
    source = source.replace(
        'name = "test-vm"\nmachine_type = "n2-standard-4"',
        'machine_type="n2-standard-4"\nname="test-vm"',
    )
    config.path.write_text(source)
    equivalent = load(config.path)
    assert equivalent.fingerprint == config.fingerprint
    Journal(equivalent).check_fingerprint()
    config.path.write_text(source.replace("n2-standard-4", "n2-standard-8"))
    with pytest.raises(PiccoloError, match="Configuration changed"):
        Journal(load(config.path)).check_fingerprint()


def test_operator_credential_filenames_are_ignored() -> None:
    paths = [
        ".credentials/key.json",
        "application_default_credentials.json",
        "dev-service-account.json",
        "user-credentials.json",
        "private.pem",
    ]
    result = subprocess.run(
        ["git", "check-ignore", "-z", "--stdin"],
        input="\0".join(paths) + "\0",
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.rstrip("\0").split("\0") == paths
