<!--
Copyright 2026 Israel Flores-Arbolay
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes to this project will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Strict TOML configuration discovery and validation, a Typer CLI, and an optional Google Cloud SDK provider.
- Additive access reconciliation, zone capacity fallback, durable operation recovery, disk-preserving relocation, and ownership-aware cleanup previews.
- Explicit opaque bootstrap staging and invocation with fresh-disk eligibility, durable guest receipts, and repeat-execution protection.
- SSH readiness checks and foreground SSH/IAP connections through gcloud.
- Offline lifecycle, SDK contract, bootstrap, and lock tests, plus a proposed live GCP validation plan.
- Explicitly gated GCP lifecycle and human IAP tests for the Piccolo GCP project, durable run manifests, an independent scoped janitor, and offline interruption/cleanup safety tests.
- Configurable live-test project approval through `PICCOLO_GCP_LIVE_PROJECT`, explicit dotenv loading, and manifests that retain their original project for recovery.
- Scoped live grants on approved existing secrets, conditional account-creation permission checks, and guest verification of dummy secret access.
- Local security regressions and gated live credential, fallback recovery, state-loss cleanup, ownership, and shutdown metadata regressions remediating H01 and H06 of the 2026-10-11 security audit.

### Fixed

- Reject inherited and persisted gcloud authentication overrides on all connection paths, including receipt reads and live tunnels.
- Validate supported SDK credential JSON before type-specific loading, including environment and well-known ADC files.
- Resume accepted creations in later capacity-fallback zones without duplicate submissions.
- Retain recovery artifacts unless completed operation history positively authorizes cleanup.
- Reject VM ownership from another environment before access or lifecycle mutations.
- Block automatic shutdown metadata before stop, relocation, resumed power operations, and retired-source deletion.
- Correct noninteractive CLI spinner handling so mutating commands, including legacy adoption, reach their provider.

- Accept direct provisioner credentials in live profiles, test human-source impersonation separately, and use the authenticated provisioner for temporary attachment grants.
- Check local gcloud and OpenSSH prerequisites before live provisioning.

- Decode Compute enum values as names for resource inspection and operation recovery.
- Fail SSH readiness promptly when local SSH support is missing.
- Reconcile eventual service-account visibility through bounded reads without resubmitting mutations.
