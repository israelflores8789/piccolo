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
├── .github/                   # GitHub configuration
├── .vscode/                   # Editor configuration
├── audits/                    # Security audit reports
├── examples/gcp/              # GCP configuration examples
├── src/piccolo/
│   ├── __main__.py            # Python module entrypoint
│   ├── cli.py                 # Typer command-line interface
│   ├── bootstrap/             # Remote bootstrap support
│   │   ├── execution.py       # Bootstrap execution and receipts
│   │   └── staging.py         # Remote bootstrap file staging
│   ├── config/                # TOML configuration parsing
│   │   ├── discovery.py       # Configuration file discovery
│   │   ├── loader.py          # Configuration loading and validation
│   │   └── models.py          # Configuration data models
│   ├── providers/             # Provider interfaces and registry
│   │   ├── base.py            # Provider abstractions
│   │   ├── registry.py        # Provider registration
│   │   └── gcp/               # Google Cloud provider
│   │       ├── access.py      # IAM and firewall management
│   │       ├── auth.py        # GCP credential resolution
│   │       ├── clients.py     # Google Cloud client collection
│   │       ├── connection.py  # gcloud and SSH connections
│   │       ├── operations.py  # Cloud operation interfaces
│   │       ├── permissions.py # Permission error formatting
│   │       ├── provider.py    # GCP lifecycle operations
│   │       ├── provision.py   # Resource construction and validation
│   │       └── resources.py   # Google Cloud resource API
│   └── state/                 # Local state and journal
│       ├── journal.py         # Operation journal persistence
│       ├── lock.py            # Environment file locking
│       └── storage.py         # Private state file handling
├── tests/
│   ├── conftest.py            # Shared pytest fixtures
│   └── gcp_live_support/      # Shared live-test helpers
├── config.schema.json         # Configuration schema
├── justfile                   # Development task recipes
├── lean-bootstrap.sh          # Minimal bootstrap script
├── lean-gcp-infrastructure.sh # Minimal GCP provisioning script
├── lean-local-start.sh        # Local startup script
└── pyproject.toml             # Hatchling packaging; Python >= 3.12
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

### Security Audits

The following are to be followed strictly WHEN performing a security audit:

- MAKE an assessment of all dependency versions for known vulnerabilities.
- INCLUDE an assessment of risks associated with runtime function, especially those without established or ambiguous policy.
- Do NOT resurface concerns from previously remediated findings or concerns that have established policy.

#### Writing the Audit Document

- PUT findings in the `audits/` directory in an audit document with the following file scheme using the date the audit was performed, not remediated: `YYYY-MM-DD-security.md`.
- WRITE a small abstract at the very start of the audit document that includes the audit date, reviewed commit hash, and the model identifier that performed the audit (e.g. "gpt-6.1-sol") with a subsequent brief 2-3 sentence description of the audit with a bullet point list of critical findings.
- KEEP a simple table at the start of the audit document called "Remediation Status" that enumerates each finding by its ID, Concern, and Status.
- RANK findings by severity using "H##", "M##", and "L##" for high, medium, and low priority findings, respectively, where "##" is the identifying number of the finding.
- FOR each finding's section, WRITE a heading in the form "$## - ...concern title...", where "$" is the severity rank and "##" is the identifying number, and WRITE the body with the following paragraphs:
  - "**Evidence:**" -- that clearly points to the file(s) and code line(s) of the finding;
  - a paragraph that describes the finding;
  - "**Impact and Conditions:**";
  - "**Reproduction:**;
  - "**Recommendation:**".
- LIST all checks and verifications performed at the end of the audit document.

#### Remediation

WHEN the user asks to remediate a finding, adhere to the following rules:

- UPDATE the status table with the state of the respective finding.
- UPDATE the respective finding section of the audit document by:
  - MODIFYING the heading with a status suffix (e.g. "— RESOLVED")
  - ADDING a subsection to the finding with a subheading with the date of remediation called "Remediation — YYYY-MM-DD" and has the following paragraphs:
    - a paragraph describing the remediation that was implemented;
    - "**Regression Coverage:**" -- (if applicable) describing the regression tests implemented.

### Live Testing

When the USER explicitly requests live testing against GCP (or any other live provider), you WILL follow the following rules:

- You will **NEVER** perform live testing unless the USER explicitly asks for live tests to be performed AND gives the following information:
  - a target provider (required),
  - the target project ID (required),
  - an explicit spending budget that you will NEVER exceed (required),
  - an explicit cumulative test duration maximum (optional; default to the implemented test suite deadline of 45 minutes).
  - IF the user does not offer this information, you WILL STOP and ASK the USER before performing the live tests; you are PROHIBITED from continuing until the USER gives the required information.
- UNLESS otherwise given by the USER, you will ALWAYS use a service account called `piccolo-test-provisioner` for Piccolo and Piccolo test actions.
- UNLESS otherwise given by the USER, you will ALWAYS use a service account called `piccolo-test-vm` for "existing VM" tests.
- You **MUST** REQUIRE the USER's explicit permission to use the human account for provisioner impersonation tests. You will **NEVER** run impersonation tests or otherwise interact with the human account for ANY purpose UNLESS you have EXPLICIT permission from the USER, and your actions with the human account will be CONSTRAINED to the defined scope of the test OR the USER's explicit request. IF you do NOT have EXPLICIT permission for a required action, **STOP** and ASK the USER for direction.

- You will ALWAYS implement live tests such that they are specific to a given provider and explicitly selectable.
- You will KEEP or UPDATE a just recipe specific to the live test for a given provider (e.g. `just test-gcp-live`) including related recipes (e.g. `just janitor-gcp-live`).
- ALL tests, including purely helper source code, belong in the `tests/` directory.

- USE the following rates for estimation of charges associated with live GCP testing:
  - Compute Engine VM Instance `e2-small`: $0.016752855 per hour.
  - Disk Standard: $0.000054795 per gigabyte-hour.
  - Snapshot Standard Storage: $0.000068493 per gigabyte-hour (note: make sure to remove the snapshot from the Snapshot Recycle Bin when tests are completed!).
  - Disk recreated from a Snapshot in a different **region** (not zone) than the snapshot incurs Data Transfer rates: $0.02 per gigabyte for North America to North America transfers.
  - Ephemeral/Static Public IPv4: $0.005 per hour.
  - Reserved Static Public IPv4: $0.01 per hour.
  - Networking charges:
    - Ingress, Internet --> VM instance: free.
    - VM <--> VM intra-zone, intra-region: free.
    - VM <--> VM inter-zone, intra-region: $0.01 per gigabyte.
    - VM <--> VM inter-zone, inter-region: $0.02 per gigabyte.
    - Egress, VM --> Internet: $0.12 per gigabyte.
  - Standard VPC Firewall: free.

### Prohibitions

The following actions are **prohibited** and are reserved exclusively for the user. When encountering a task that involves a prohibited action, you MUST **stop** and **report** to the user the conflict:

- NEVER remove comments marked with the `AGENT: do not remove` preamble or their explanatory continuation lines.
- NEVER attempt to publish to PyPI or invoke any publishing command; consequently, NEVER use `just publish` or `just release`.
- NEVER attempt to perform a release to GitHub or invoke any release command.
- NEVER attempt to push git changes to GitHub.
