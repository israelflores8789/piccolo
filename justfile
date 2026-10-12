# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0
# Piccolo development commands

set shell := ["bash", "-euo", "pipefail", "-c"]

pytest := "uv run --locked pytest"
src_dir := "src"
check_dirs := "src tests"

lock:
    uv lock

lock-check:
    uv lock --check

install-dev:
    @echo "Installing development dependencies..."
    @uv sync --locked --all-groups --all-extras

test *args:
    {{pytest}} -v -s {{args}}

# Set PICCOLO_GCP_LIVE_PROJECT directly or load it with --dotenv-path.
approval-gcp-live config:
    uv run --locked python tests/gcp_approval.py "{{ config }}"

test-gcp-live config test-name="tests/test_gcp_live.py":
    #!/usr/bin/env bash
    set -euo pipefail
    : "${PICCOLO_GCP_LIVE_PROJECT:?Set PICCOLO_GCP_LIVE_PROJECT to the approved project}"
    : "${PICCOLO_GCP_LIVE_APPROVAL_SHA256:?Pin the reviewed digest from just approval-gcp-live}"
    uv run --locked python -c 'import os; from pathlib import Path; from piccolo.state.storage import private_directory, private_file; private_directory(Path(".test_logs")); private_directory(Path(".test_runs")); os.close(private_file(Path(".test_logs/pytest-gcp-live.log"), create=True))'
    PYTHONUNBUFFERED=1 PICCOLO_GCP_LIVE=1 PICCOLO_GCP_LIVE_CONFIG="{{ config }}" \
        {{pytest}} --gcp-live -vv -s --durations=0 --tb=short --color=no "{{ test-name }}" < /dev/null \
        2>&1 | tee .test_logs/pytest-gcp-live.log

# Recovery is preview-only unless apply=1; uses the retained run manifest.
janitor-gcp-live manifest apply="0":
    #!/usr/bin/env bash
    set -euo pipefail
    : "${PICCOLO_GCP_LIVE_PROJECT:?Set PICCOLO_GCP_LIVE_PROJECT to the approved project}"
    args=()
    case "{{ apply }}" in
        0) ;;
        1) args+=(--apply) ;;
        *) echo "apply must be 0 or 1" >&2; exit 2 ;;
    esac
    PICCOLO_GCP_LIVE=1 \
        uv run --locked python tests/gcp_janitor.py --manifest "{{ manifest }}" "${args[@]}"

coverage *args:
    uv run --locked pytest --cov=src/piccolo --cov-report=term-missing {{args}}

lint:
    #!/usr/bin/env bash
    set -u
    status=0

    uv run --locked ruff check {{check_dirs}} || status=1
    uv run --locked ruff format --check {{check_dirs}} || status=1

    exit "$status"

lint-yaml:
    #!/usr/bin/env bash
    set -u
    status=0

    uv run --locked pre-commit run --all-files actionlint || status=1
    uv run --locked pre-commit run --all-files check-yaml || status=1

    exit "$status"

lint-fix:
    uv run --locked ruff format {{check_dirs}}
    uv run --locked ruff check --fix {{check_dirs}}
    uv run --locked ruff format {{check_dirs}}

typecheck:
    uv run --locked pyrefly check {{src_dir}} tests/gcp_live_support

spell-diff:
    uvx --from typos typos --diff

ci: test lint typecheck

build: lock-check
    @echo "Building the project..."
    rm -rf dist/
    uv build --no-sources

check-dist: build
    uv run --locked twine check --strict dist/*

# Local command checks without cloud credentials or API requests.
smoke:
    uv run --locked piccolo --help
    uv run --locked piccolo validate --config examples/gcp/piccolo.toml

# Verify the wheel works without the optional GCP SDK dependencies.
package-smoke:
    uv run --isolated --no-project --with ./dist/piccolo-0.1.0-py3-none-any.whl piccolo validate --config examples/gcp/piccolo.toml

clean:
    rm -rf dist/ build/ .pytest_cache/ .mypy_cache/ .ruff_cache/ .pyrefly/
    find . -type d -name __pycache__ -prune -exec rm -rf {} +

# Additional local helpers.

install: install-dev

format:
    uv run --locked ruff format {{src_dir}}

format-check:
    uv run --locked ruff format --check {{src_dir}}

pre-commit-install:
    uv run --locked pre-commit install

pre-commit:
    uv run --locked pre-commit run --all-files
