# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""loader.py — Strict TOML parsing, field paths, and cross-field validation."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import tomllib
from pathlib import Path, PurePosixPath

from piccolo.config.discovery import discover
from piccolo.config.models import GCP, Auth, Bootstrap, Config
from piccolo.data import Document, Value, document
from piccolo.errors import PiccoloError


class Section:
    """Read typed fields and reject every unconsumed configuration key."""

    def __init__(self, data: Document, path: str = "") -> None:
        """Record a table and its diagnostic prefix."""
        self.data = data.copy()
        self.path = path

    def field(self, name: str) -> str:
        """Return a qualified diagnostic field name."""
        return f"{self.path}.{name}" if self.path else name

    def take(self, name: str, default: Value = None) -> Value:
        """Consume a value or its default."""
        return self.data.pop(name, default)

    def string(self, name: str, default: str | None = None) -> str:
        """Consume a nonempty string, except explicitly optional strings."""
        result = self.take(name, default)
        if not isinstance(result, str) or (not result and default != ""):
            raise PiccoloError(f"{self.field(name)}: expected a nonempty string")
        return result

    def integer(self, name: str, default: int, maximum: int = 2**31) -> int:
        """Consume a positive bounded integer, excluding booleans."""
        result = self.take(name, default)
        if type(result) is not int or not 1 <= result <= maximum:
            raise PiccoloError(f"{self.field(name)}: expected integer 1..{maximum}")
        return result

    def boolean(self, name: str, default: bool) -> bool:
        """Consume a boolean without coercion."""
        result = self.take(name, default)
        if not isinstance(result, bool):
            raise PiccoloError(f"{self.field(name)}: expected a boolean")
        return result

    def strings(self, name: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
        """Consume a unique array of nonempty strings."""
        result = self.take(name, list(default))
        if not isinstance(result, list):
            raise PiccoloError(f"{self.field(name)}: expected an array")
        items: list[str] = []
        for item in result:
            if not isinstance(item, str) or not item or item in items:
                raise PiccoloError(f"{self.field(name)}: expected unique strings")
            items.append(item)
        return tuple(items)

    def section(self, name: str) -> Section:
        """Consume a nested table."""
        raw = self.take(name, {})
        if not isinstance(raw, dict):
            raise PiccoloError(f"{self.field(name)}: expected a table")
        return Section(raw, self.field(name))

    def finish(self) -> None:
        """Reject unknown fields after all supported fields were consumed."""
        if self.data:
            raise PiccoloError(f"Unknown field: {self.field(next(iter(self.data)))}")


def named(
    raw: str,
    field: str,
    pattern: str = r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?",
) -> str:
    """Validate an identifier with a diagnostic field path."""
    if not re.fullmatch(pattern, raw):
        raise PiccoloError(f"{field}: invalid identifier {raw!r}")
    return raw


def local_file(base: Path, raw: str, field: str) -> Path:
    """Resolve a referenced file relative to its configuration."""
    path = (base / raw).resolve()
    if not path.is_file():
        raise PiccoloError(f"{field}: file not found: {path}")
    return path


def load(path: Path | None = None) -> Config:
    """Load a strict schema-v1 configuration without contacting Google Cloud."""
    selected = discover(path)
    try:
        source = selected.read_bytes()
        root = Section(document(tomllib.loads(source.decode("utf-8"))))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise PiccoloError(f"{selected}: {exc}") from exc
    if root.integer("schema_version", 1, 1) != 1:
        raise PiccoloError("schema_version: only version 1 is supported")
    environment = named(root.string("environment"), "environment")
    provider = root.string("provider", "gcp")
    if provider != "gcp":
        raise PiccoloError(f"provider: unsupported provider {provider!r}")
    cloud = root.section("gcp")
    project = named(
        cloud.string("project_id"), "gcp.project_id", r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
    )
    auth = cloud.section("auth")
    mode = auth.string("mode", "adc")
    credential = auth.string("credential_file", "")
    impersonate = auth.string("impersonate_service_account", "")
    if mode not in {"adc", "file"} or (mode == "file") != bool(credential):
        raise PiccoloError(
            "gcp.auth: use mode='file' with credential_file, or mode='adc'"
        )
    credential_path = (
        local_file(selected.parent, credential, "gcp.auth.credential_file")
        if credential
        else None
    )
    instance = cloud.section("instance")
    name = named(instance.string("name"), "gcp.instance.name")
    machine = named(
        instance.string("machine_type", "n2-standard-4"), "gcp.instance.machine_type"
    )
    account = instance.string("service_account")
    if not re.fullmatch(
        r"[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]+\.iam\.gserviceaccount\.com",
        account,
    ):
        raise PiccoloError(
            "gcp.instance.service_account: expected a service-account email"
        )
    placement = cloud.section("placement")
    zones = placement.strings("zones")
    if not zones:
        raise PiccoloError("gcp.placement.zones: at least one zone is required")
    for zone in zones:
        named(zone, "gcp.placement.zones", r"[a-z]+-[a-z]+[0-9]+-[a-z]")
    location = named(
        placement.string("snapshot_location", "us"), "gcp.placement.snapshot_location"
    )
    disk = cloud.section("disk")
    size = disk.integer("size_gb", 30, 65536)
    disk_type = named(disk.string("type", "pd-standard"), "gcp.disk.type")
    image = disk.string("image")
    if not re.fullmatch(r"projects/[a-z0-9-]+/global/images/[a-z0-9-]+", image):
        raise PiccoloError(
            "gcp.disk.image: expected projects/PROJECT/global/images/IMAGE"
        )
    network = cloud.section("network")
    network_name = named(network.string("name", "default"), "gcp.network.name")
    subnet = named(network.string("subnet", "default"), "gcp.network.subnet")
    mapping = document(network.take("subnets", {}))
    subnets: dict[str, str] = {}
    for region, subnet_name in mapping.items():
        if not isinstance(subnet_name, str):
            raise PiccoloError("gcp.network.subnets: expected region-to-name strings")
        subnets[named(region, "gcp.network.subnets")] = named(
            subnet_name, "gcp.network.subnets"
        )
    external = network.boolean("external_ip", True)
    iap = cloud.section("iap")
    firewall = named(
        iap.string("firewall_name", f"{environment[:49]}-iap"), "gcp.iap.firewall_name"
    )
    port_values = iap.take("ports", [22, 8080])
    if not isinstance(port_values, list) or not port_values:
        raise PiccoloError("gcp.iap.ports: expected a nonempty port array")
    ports: list[int] = []
    for port in port_values:
        if type(port) is not int or not 1 <= port <= 65535 or port in ports:
            raise PiccoloError("gcp.iap.ports: expected unique integers 1..65535")
        ports.append(port)
    ranges = iap.strings("source_ranges", ("35.235.240.0/20",))
    if not ranges:
        raise PiccoloError("gcp.iap.source_ranges: at least one CIDR is required")
    for cidr in ranges:
        try:
            if ipaddress.ip_network(cidr).version != 4:
                raise ValueError("IPv4 required")
        except ValueError as exc:
            raise PiccoloError(f"gcp.iap.source_ranges: {exc}") from exc
    iam = cloud.section("iam")
    create_sa = iam.boolean("create_service_account", False)
    if create_sa and not account.endswith(f"@{project}.iam.gserviceaccount.com"):
        raise PiccoloError(
            "gcp.iam: account creation requires an account in gcp.project_id"
        )
    secrets = iam.strings("secrets")
    for secret in secrets:
        named(secret, "gcp.iam.secrets", r"[A-Za-z0-9_-]+")
    roles = iam.strings("project_roles")
    for role in roles:
        if not re.fullmatch(
            r"roles/[A-Za-z0-9_.]+|projects/[a-z0-9-]+/roles/[A-Za-z0-9_.]+", role
        ):
            raise PiccoloError("gcp.iam.project_roles: expected an IAM role name")
    enable_apis = cloud.boolean("enable_apis", False)
    operation_timeout = cloud.integer("operation_timeout", 600)
    ssh = cloud.section("ssh")
    user = named(ssh.string("user"), "gcp.ssh.user", r"[a-z_][a-z0-9_-]{0,31}")
    via_iap = ssh.boolean("via_iap", True)
    connection_account = ssh.string("account", "")
    connection_impersonate = ssh.string("impersonate_service_account", "")
    readiness_timeout = ssh.integer("readiness_timeout", 300)
    readiness_command = ssh.string("readiness_command", "")
    tunnel = cloud.section("tunnel")
    remote_port = tunnel.integer("remote_port", 8080, 65535)
    local_port = tunnel.integer("local_port", 8080, 65535)
    if via_iap and (22 not in ports or remote_port not in ports):
        raise PiccoloError("gcp.iap.ports: must include SSH 22 and tunnel.remote_port")
    bootstrap: Bootstrap | None = None
    if "bootstrap" in root.data:
        setup = root.section("bootstrap")
        script = local_file(selected.parent, setup.string("script"), "bootstrap.script")
        remote = setup.string("remote_path", ".piccolo/bootstrap/setup.sh")
        remote_parts = PurePosixPath(remote)
        if (
            remote_parts.is_absolute()
            or ".." in remote_parts.parts
            or not re.fullmatch(r"[A-Za-z0-9_./-]+", remote)
            or remote in {".", ""}
        ):
            raise PiccoloError(
                "bootstrap.remote_path: expected a safe path "
                "relative to the user's home"
            )
        execution_user = setup.string("execution_user")
        if execution_user != user:
            raise PiccoloError("bootstrap.execution_user must equal gcp.ssh.user")
        bootstrap = Bootstrap(
            script, remote, execution_user, setup.integer("timeout", 1800)
        )
        setup.finish()
    for section in (
        auth,
        instance,
        placement,
        disk,
        network,
        iap,
        iam,
        ssh,
        tunnel,
        cloud,
        root,
    ):
        section.finish()
    return Config(
        selected,
        environment,
        provider,
        GCP(
            project,
            Auth(mode, credential_path, impersonate),
            name,
            machine,
            account,
            zones,
            location,
            size,
            disk_type,
            image,
            network_name,
            subnet,
            subnets,
            external,
            firewall,
            tuple(ports),
            ranges,
            create_sa,
            secrets,
            roles,
            enable_apis,
            user,
            via_iap,
            connection_account,
            connection_impersonate,
            readiness_timeout,
            readiness_command,
            remote_port,
            local_port,
            operation_timeout,
        ),
        bootstrap,
        hashlib.sha256(source).hexdigest(),
    )
