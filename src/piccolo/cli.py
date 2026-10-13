# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""cli.py — Declarative environment commands and predictable config selection."""

import sys
from contextlib import nullcontext
from pathlib import Path
from typing import Annotated

import typer
from yaspin import yaspin

from piccolo.config import load
from piccolo.data import text
from piccolo.errors import PiccoloError
from piccolo.logger import emit, log
from piccolo.providers.registry import create
from piccolo.state.lock import environment_lock

app = typer.Typer(
    no_args_is_help=True,
    help="Manage development infrastructure without implicit bootstrap execution.",
)


@app.callback()
def options(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
) -> None:
    """Accept a configuration path before the subcommand."""
    ctx.obj = config


def selected(ctx: typer.Context, config: Path | None) -> Path | None:
    """Resolve global and command-local options and reject conflicting choices."""
    global_config: object = ctx.find_root().obj
    if global_config is not None and not isinstance(global_config, Path):
        raise PiccoloError("Invalid global configuration option")
    if (
        config is not None
        and global_config is not None
        and config.resolve() != global_config.resolve()
    ):
        raise PiccoloError("Conflicting global and command-local --config paths")
    return config if config is not None else global_config


def invoke(
    ctx: typer.Context,
    path: Path | None,
    action: str,
    *,
    apply: bool = False,
    dry_run: bool = False,
    status: bool = False,
    destination: str | None = None,
    rollback: bool = False,
    adopt: bool = False,
) -> None:
    """Dispatch commands through provider contracts with local mutation locks."""
    try:
        config = load(selected(ctx, path))
        log(
            f"Config: {config.path}\nProject: "
            f"{config.gcp.project_id}\nEnvironment: "
            f"{config.environment}"
        )
        if action == "validate":
            log("Configuration valid")
            return
        match action:
            case "status":
                emit(create(config).inspect())
            case "plan":
                emit(create(config).plan())
            case "connect":
                with environment_lock(config):
                    provider = create(config)
                    zone = provider.start()
                    provider.connection.ready(zone)
                provider.connection.shell(zone)
            case "tunnel":
                with environment_lock(config):
                    provider = create(config)
                    zone = text(provider.active(), "zone").split("/")[-1]
                provider.connection.tunnel(zone)
            case _:
                with (
                    environment_lock(config),
                    yaspin(
                        text=f"Piccolo {action}",
                        stream=sys.stderr,
                    )
                    if sys.stderr.isatty()
                    else nullcontext(),
                ):
                    provider = create(config)
                    if action not in provider.capabilities:
                        raise PiccoloError(f"Provider does not support {action}")
                    match action:
                        case "init":
                            provider.init(adopt=adopt)
                        case "start":
                            provider.start()
                        case "stop":
                            provider.stop()
                        case "move":
                            provider.move(destination)
                        case "resume":
                            if rollback:
                                provider.rollback()
                            else:
                                provider.resume()
                        case "cleanup":
                            emit(provider.cleanup(apply))
                        case "bootstrap":
                            if dry_run and status:
                                raise PiccoloError("Choose --dry-run or --status")
                            emit(provider.bootstrap(dry_run, status))
    except (PiccoloError, OSError, ValueError) as exc:
        log(f"Error: {exc}", err=True)
        raise typer.Exit(1) from exc


@app.command()
def validate(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
) -> None:
    """Validate local configuration and referenced paths without cloud access."""
    invoke(ctx, config, "validate")


@app.command()
def plan(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
) -> None:
    """Inspect supported infrastructure drift without applying changes."""
    invoke(ctx, config, "plan")


@app.command()
def init(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
    adopt: Annotated[
        bool, typer.Option(help="Adopt a reviewed unlabeled legacy VM by immutable ID.")
    ] = False,
) -> None:
    """Provision infrastructure and stage a script without executing bootstrap."""
    invoke(ctx, config, "init", adopt=adopt)


@app.command()
def bootstrap(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option(help="Show script identity and eligibility.")
    ] = False,
    status: Annotated[
        bool, typer.Option(help="Inspect prior attempt and guest receipt.")
    ] = False,
) -> None:
    """Explicitly execute the staged script once on its recorded fresh disk."""
    invoke(ctx, config, "bootstrap", dry_run=dry_run, status=status)


@app.command()
def status(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
) -> None:
    """Show observed instances, recorded bootstrap history, and recovery state."""
    invoke(ctx, config, "status")


@app.command()
def start(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
) -> None:
    """Start an existing VM and await operation completion."""
    invoke(ctx, config, "start")


@app.command()
def stop(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
) -> None:
    """Stop the existing VM and retain its boot disk."""
    invoke(ctx, config, "stop")


@app.command()
def connect(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
) -> None:
    """Start an existing VM, wait for authenticated SSH, and open a shell."""
    invoke(ctx, config, "connect")


@app.command()
def tunnel(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
) -> None:
    """Open an IAP tunnel on localhost in the foreground."""
    invoke(ctx, config, "tunnel")


@app.command()
def move(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
    to: Annotated[
        str | None, typer.Option("--to", help="Target exactly this zone.")
    ] = None,
) -> None:
    """Relocate the stopped source disk and verify SSH before committing."""
    invoke(ctx, config, "move", destination=to)


@app.command()
def resume(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
    rollback: Annotated[
        bool,
        typer.Option(
            help="Restart a source only after confirmed absence of replacements."
        ),
    ] = False,
) -> None:
    """Reconcile an interrupted operation using recorded identities and requests."""
    invoke(ctx, config, "resume", rollback=rollback)


@app.command()
def cleanup(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration path; defaults to ./piccolo.toml."
        ),
    ] = None,
    apply: Annotated[
        bool, typer.Option(help="Delete verified eligible resources; default previews.")
    ] = False,
) -> None:
    """Preview owned, unattached recovery artifacts or explicitly delete them."""
    invoke(ctx, config, "cleanup", apply=apply)


def main() -> None:
    """Run the installed CLI entry point."""
    app()
