<!--
Copyright 2026 Israel Flores-Arbolay
SPDX-License-Identifier: Apache-2.0
-->

# Piccolo — Agent Context

## Purpose

A Python CLI utility that provisions and helps manage remote infrastructure with declarative TOML configuration.

## Repository Structure

```
piccolo/
├── pyproject.toml            # Hatchling packaging; Python >= 3.12
├── src/piccolo/
│   ├── __init__.py
```

## Architecture

- **Dependencies**: `typer`, `yaspin`.
  - **GCS**: `google-cloud-compute`, `google-cloud-secret-manager`, `google-cloud-resource-manager`, `google-cloud-iam`, `google-cloud-service-usage`, `google-auth`.
- **Dev Environment**: `uv`, `hatchling`, `twine`, `pyrefly`, `ruff`, `pytest`, `just`, `pre-commit`.

## Commands

Run all project tasks via `just` from the repository root. Use `just --list` to inspect available recipes.

- USE `just install-dev` to synchronize all uv dependency groups.
- USE `just test` to run the test suite; pass pytest arguments with `just test <args>`.
- USE `just coverage` to run test suite with terminal coverage reporting.
- USE `just lint` for Python Ruff linting and formatting checks; USE `just lint-yaml` for GitHub Actions and YAML checks.
- USE `just lint-fix` to apply Ruff lint and formatting corrections.
- USE `just typecheck` to perform Pyrefly type checks.
- USE `just spell-diff` to run typos spelling checker.
- PREFER `just ci` for unit/local tests, Python lint, and type checks; run SQL parity, YAML checks, and live tests separately when relevant.
- USE `just build` to clean `dist/` and build an sdist and wheel with Hatchling.
- USE `just check-dist` to clean, build, and validate artifacts with Twine.
- USE `just clean` to remove build artifacts and local caches.

## Rules

- ALL Python code should target Python 3.12+ syntax only.
- ALL generated/edited Python source MUST pass Ruff and Pyrefly; RUN `just lint` and `just typecheck` after editing *any* Python code.
- Do NOT suppress diagnostics to make checks pass. Do NOT introduce implicit `Any` or use bare generic types.
- Do NOT suppress diagnostics to make checks pass. Do NOT introduce implicit `Any` or use bare generic types.
- PREFER PEP 695 syntax for **all** new generic declarations and type aliases. USE modern built-in generic and union syntax.
- USE Google-style docstrings for **all** source code.
- KEEP comments concise yet clear. Do NOT use numbered headers (e.g. "1." or "(1)" etc).
- FOR module-level docstrings, ADD the name of the module to the start of the docstring (e.g. """my_module.py — ...).
- EVERY applicable file, including ALL source code files, REQUIRES a license header consistent with Apache-2.0 standards.
- Do NOT wrap lines when generating markdown text.
- USE Keep a Changelog standards in `CHANGELOG.md`; preserve release heading and bullet formatting because `just release` and the GitHub release workflow extract release notes from it.

### Prohibitions

The following actions are **prohibited** and are reserved exclusively for the user. When encountering a task that involves a prohibited action, you MUST **stop** and **report** to the user the conflict:

- NEVER remove comments marked with the `AGENT: do not remove` preamble or their explanatory continuation lines.
- NEVER attempt to publish to PyPI or invoke any publishing command; consequently, NEVER use `just publish` or `just release`.
- NEVER attempt to perform a release to GitHub or invoke any release command.
- NEVER attempt to push git changes to GitHub.
