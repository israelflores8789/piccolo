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
