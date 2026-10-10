# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0
# Piccolo development commands

set shell := ["bash", "-euo", "pipefail", "-c"]

src_dir := "src"

install:
    uv sync

build:
    uv build --no-sources

lint:
    uv run ruff check {{src_dir}}

format:
    uv run ruff format {{src_dir}}

format-check:
    uv run ruff format --check {{src_dir}}

lint-fix:
    uv run ruff check --fix {{src_dir}}
    uv run ruff format {{src_dir}}

typecheck:
    uv run pyrefly check {{src_dir}}

pre-commit-install:
    uv run pre-commit install

pre-commit:
    uv run pre-commit run --all-files

check-license:
    uvx --from 'reuse[charset-normalizer]' reuse lint

ci: lint format-check typecheck check-license
