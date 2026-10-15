<!--
Copyright 2026 Israel Flores-Arbolay
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes to this project will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.0] - 2026-10-15

### Added

- Native Windows OpenSSH transport with explicit expiring metadata/OS Login authorization, immutable host trust, protected shared-key preparation, and binary IAP proxy execution.
- Pywin32-backed private Windows storage, handle-based ownership and DACL verification, safe file-descriptor transfer, and job-based connection process-tree cleanup.
- Native Windows offline ACL, key, locking, proxy, and process tests; Linux/Windows/macOS local CI on Python 3.12 and 3.14; separately selectable `gcp_win_live` transport, lifecycle, impersonation, and recovery checks with bounded terminal acceptance.
- Top-level `spinner` configuration in `piccolo.toml` and `config.schema.json`, supporting all built-in yaspin spinners with validated names and a default of `dots`.

### Changed

- Separate provider-neutral OpenSSH key, trust-file, command, and transfer mechanics from GCP authorization and session preparation; split state and Cloud SDK path ownership and rename the Win32 process helper.
- Run shared OpenSSH regression tests independently of GCP, with actual local key preparation on each supported platform and separately selectable Windows-specific checks.
- Use platformdirs' user-state directory as the state-root standard; preserve explicit `PICCOLO_STATE_DIR` overrides without legacy migration tooling.
- Centralize Cloud SDK configuration paths and prefer the Windows SDK's bundled interpreter when present; retain separate SDK and connection identities.
- Extract shared GCP SSH behavior behind one transport interface.
- Centralize spinner selection, loading messages, and terminal detection in `config/spinner.py`; display progress during `status`, `plan`, and preparation for `connect` and `tunnel`, stopping before foreground SSH or tunnel sessions and disabling animation for redirected output.

### Fixed

- Restore per-test CI summaries by removing pytest's default quiet mode and running CI through `just test`, which now explicitly excludes live tests.
- Preserve the human gcloud connector in the Windows live harness, independently of provisioner SDK credentials and the attached guest service account.
- Select the configured project's primary OS Login account; reuse connector tokens only within bounded native operations and allow readiness preparation to use its configured deadline.
- Protect temporary human impersonation credentials with native private storage and allow Windows disposable-key probes enough initial lifetime for SDK preparation.
- Restore mutated live bootstrap fixtures byte-for-byte so Windows newline translation cannot change the staged script digest.
- Stop the Windows IAP SDK proxy on OpenSSH input closure, preserve binary bytes and genuine transport errors, and accept interactive Ctrl+C exit status 130.
- Reuse an existing OS Login key only while its finite remaining lifetime satisfies the configured expiration policy.
- Derive live-session test account and dummy-secret identities from the explicitly approved project environment variable; use a project-specific baseline path without a default project.
- Contain all native Windows gcloud helper processes in cleanup jobs so timeouts and interruption terminate descendants as well as SSH/IAP processes. Resolves M01 of the 2026-10-13 security audit.
- Replace selector-based pipe capture with bounded reader-thread capture and preserve foreground terminal handles.
- Create private journal replacements and upload files before writing their contents; generate bootstrap runners with LF endings on Windows.
- Preserve pytest argument boundaries and make live spending-ledger locking portable without running live tests.

## [0.2.0] - 2026-10-13

### Added

- Strict TOML configuration discovery and validation, a Typer CLI, and an optional Google Cloud SDK provider.
- Additive access reconciliation, zone capacity fallback, durable operation recovery, disk-preserving relocation, and ownership-aware cleanup previews.
- Explicit opaque bootstrap staging and invocation with fresh-disk eligibility, durable guest receipts, and repeat-execution protection.
- SSH readiness checks and foreground SSH/IAP connections through gcloud.
- Offline lifecycle, SDK contract, bootstrap, and lock tests, plus a proposed live GCP validation plan.
- Explicitly gated GCP lifecycle and human IAP tests for the Piccolo GCP project, durable run manifests, an independent scoped janitor, and offline interruption/cleanup safety tests.
- Configurable live-test project approval through `PICCOLO_GCP_LIVE_PROJECT`, explicit dotenv loading, and manifests that retain their original project for recovery.
- Scoped live grants on approved existing secrets, conditional account-creation permission checks, and guest verification of dummy secret access.
- Private GCP networking defaults, effective firewall inspection, explicit internal-IP connections, and provider-qualified permission guidance.
- Verified SSH host enrollment through authenticated guest attributes, finite key lifetimes, and optional interactive gcloud passphrase prompts.
- Per-resource access reconciliation journals, exact dependency pins, and Dependabot configuration.
- Gated expire-and-reconnect regressions for SSH/SCP under OS Login and instance metadata, with disposable keys, observed expired-key rejection, renewal evidence, and scoped janitor recovery.
- Shared privacy and console logging modules, owned private state storage, and bootstrap process-group observation and receipt recovery instructions.
- A cooperative 45-minute live-test deadline with reserved cleanup/inventory time, reviewed profile digests, verified dummy-secret versions, and residual-resource reports without a dollar limit.
- Selectable live security/recovery and SSH/SCP expiration sequences that share fixtures to reduce repeated VM setup within a cumulative testing allowance.

### Fixed

- Remediate 2026-10-11 security audit findings H01-H06 with local security regressions and gated live credential, fallback recovery, state-loss cleanup, ownership, and shutdown metadata regressions.
- Remediate 2026-10-11 security audit findings M01–M08 with guest IAM safeguards, immutable creation and recovery identities, strict relocation settings, and private verified bootstrap uploads and runners.
- Remediate 2026-10-11 security audit findings M09–M12 and L01–L02 with bootstrap interruption guards, credential redaction, explicit recovery-copy finalization, canonical settings fingerprints, corrected live instructions, and runtime-only wheel contents.
- Inspect the pinned Compute SDK's `firewall_policys` response field so inherited non-IAP ingress remains blocked.
- Wait for a proven newly created service account to become visible to IAM grant APIs, preserving its recorded identity and rereading policies after rejected grants.
- Allow bounded SCP reconnection after an expiring OS Login key is renewed but its authorization has not yet propagated; preserve errors for other transfer failures.
- Share a persisted live-session start across setup, selections, reruns, and cleanup, bind approved duration extensions into the review digest, and retain separate selection logs.
- Journal synthetic capacity failures before live fallback recovery and distinguish stale deleted-account listings from replacement identities during scoped cleanup.
- Accept output-only Compute VM and disk resource status during relocation without copying it into replacement requests.
- Omit source integrity-baseline update actions from replacement creation while preserving Shielded VM settings.
- Preserve approved guest project roles in live tests and remove only test-added IAM members during teardown.
- Verify live fixture SSH metadata on creation and recovery, support shorter run deadlines and ordered case selection with preserved argument boundaries, and pace Service Usage attempts alongside bounded transient-read retries.
- Preserve public secret resource and IAM binding identifiers during credential redaction so independent cleanup can reopen live manifests.
- Wait for authenticated guest host-key publication before starting SSH expiration observations.
- Permanently purge manifest-proven test snapshots from the GCP recycle bin, include recoverable copies in residual inventories, and retain uncertain purge requests without resubmission.

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
