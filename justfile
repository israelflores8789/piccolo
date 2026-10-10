# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0
# Piccolo development commands

set shell := ["bash", "-euo", "pipefail", "-c"]

pytest := "uv run pytest"
src_dir := "src"

install-dev:
    @echo "Installing development dependencies..."
    @uv sync --all-groups

test *args:
    {{pytest}} -v -s {{args}}

coverage *args:
    uv run --with pytest-cov pytest --cov=src/piccolo --cov-report=term-missing {{args}}

lint:
    #!/usr/bin/env bash
    set -u
    status=0

    uv run ruff check {{src_dir}} || status=1
    uv run ruff format --check {{src_dir}} || status=1

    exit "$status"

lint-yaml:
    #!/usr/bin/env bash
    set -u
    status=0

    uv run pre-commit run --all-files actionlint || status=1
    uv run pre-commit run --all-files check-yaml || status=1

    exit "$status"

lint-fix:
    uv run ruff format {{src_dir}}
    uv run ruff check --fix {{src_dir}}
    uv run ruff format {{src_dir}}

typecheck:
    uv run pyrefly check {{src_dir}}

spell-diff:
    uvx --from typos typos --diff

ci: test lint typecheck

build:
    @echo "Building the project..."
    rm -rf dist/
    uv build --no-sources

check-dist: build
    uvx --from twine twine check dist/*

clean:
    rm -rf dist/ build/ .pytest_cache/ .mypy_cache/ .ruff_cache/ .pyrefly/
    find . -type d -name __pycache__ -prune -exec rm -rf {} +

# Additional local helpers.

install: install-dev

format:
    uv run ruff format {{src_dir}}

format-check:
    uv run ruff format --check {{src_dir}}

pre-commit-install:
    uv run pre-commit install

pre-commit:
    uv run pre-commit run --all-files
