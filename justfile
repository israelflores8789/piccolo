# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0
# Piccolo development commands

set shell := ["bash", "-euo", "pipefail", "-c"]

pytest := "uv run pytest"
src_dir := "src"
check_dirs := "src tests"

install-dev:
    @echo "Installing development dependencies..."
    @uv sync --all-groups --all-extras

test *args:
    {{pytest}} -v -s {{args}}

# Set PICCOLO_GCP_LIVE_PROJECT directly or load it with --dotenv-path.
test-gcp-live config test-name="tests/test_gcp_live.py":
    #!/usr/bin/env bash
    set -euo pipefail
    : "${PICCOLO_GCP_LIVE_PROJECT:?Set PICCOLO_GCP_LIVE_PROJECT to the approved project}"
    mkdir -p .test_logs .test_runs
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
        uv run python tests/gcp_janitor.py --manifest "{{ manifest }}" "${args[@]}"

coverage *args:
    uv run --with pytest-cov pytest --cov=src/piccolo --cov-report=term-missing {{args}}

lint:
    #!/usr/bin/env bash
    set -u
    status=0

    uv run ruff check {{check_dirs}} || status=1
    uv run ruff format --check {{check_dirs}} || status=1

    exit "$status"

lint-yaml:
    #!/usr/bin/env bash
    set -u
    status=0

    uv run pre-commit run --all-files actionlint || status=1
    uv run pre-commit run --all-files check-yaml || status=1

    exit "$status"

lint-fix:
    uv run ruff format {{check_dirs}}
    uv run ruff check --fix {{check_dirs}}
    uv run ruff format {{check_dirs}}

typecheck:
    uv run pyrefly check {{src_dir}} tests/gcp_live_support

spell-diff:
    uvx --from typos typos --diff

ci: test lint typecheck

build:
    @echo "Building the project..."
    rm -rf dist/
    uv build --no-sources

check-dist: build
    uv run twine check --strict dist/*

# Local command checks without cloud credentials or API requests.
smoke:
    uv run piccolo --help
    uv run piccolo validate --config examples/gcp/piccolo.toml

# Verify the wheel works without the optional GCP SDK dependencies.
package-smoke:
    uv run --isolated --no-project --with ./dist/piccolo-0.1.0-py3-none-any.whl piccolo validate --config examples/gcp/piccolo.toml

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
