<!--
Copyright 2026 Israel Flores-Arbolay
SPDX-License-Identifier: Apache-2.0
-->

# Piccolo

Piccolo provisions and manages one development VM per TOML configuration. Google Cloud infrastructure uses Google's Python SDKs; SSH, script transfer, and IAP tunnels use `gcloud`. Python 3.12 or newer is required; this repository develops with Python 3.13.

Infrastructure provisioning, explicit project setup, and daily connections are separate commands. Piccolo treats bootstrap as an opaque, project-owned Bash script. It never interprets the script or manages containers, repositories, development tools, or credentials inside it.

## Install

```bash
pip install 'piccolo[gcp]'
piccolo --help
```

Install the Google Cloud CLI and its SSH/SCP prerequisites for connection commands. Configure SDK ADC and the `gcloud` connection login independently. Piccolo does not log in, activate credential files in `gcloud`, or create service-account keys. See [NEXTSTEPS.md](NEXTSTEPS.md) for cloud prerequisites and the proposed live validation plan.

For local development:

```bash
just install-dev
just ci
```

## Configure an environment

Keep `piccolo.toml` and its bootstrap script in the project that consumes Piccolo. Start with [examples/gcp/piccolo.toml](examples/gcp/piccolo.toml), which includes a harmless example script. Replace the project, VM account, SSH user, pinned image, and placement policy before provisioning. The example is a configuration template; it does not guarantee image availability or capacity in your project.

```toml
schema_version = 1
environment = "research-dev"
provider = "gcp"

[bootstrap]
script = "./scripts/bootstrap.sh"
remote_path = ".piccolo/bootstrap/setup.sh"
execution_user = "researcher"

[gcp]
project_id = "my-gcp-project"

[gcp.instance]
name = "research-dev"
machine_type = "n2-standard-4"
service_account = "research-dev@my-gcp-project.iam.gserviceaccount.com"

[gcp.placement]
zones = ["us-west1-c", "us-west1-a", "us-east1-b"]
snapshot_location = "us"

[gcp.disk]
size_gb = 30
type = "pd-standard"
image = "projects/debian-cloud/global/images/debian-13-trixie-v20260727"

[gcp.ssh]
user = "researcher"
via_iap = true
```

An explicit `-c`/`--config` path is exact. Otherwise Piccolo loads only `piccolo.toml` in the current working directory, without searching parents or arbitrary TOML files. An invalid explicit path never falls back. Both option positions work:

```bash
piccolo --config environments/dev.toml init
piccolo init --config environments/dev.toml
```

Bootstrap and credential-file paths resolve relative to the TOML file. `bootstrap.remote_path` resolves inside the execution user's home directory and must be a safe relative POSIX path without `..`. `bootstrap.execution_user` must match `gcp.ssh.user`; this keeps transfer, readiness, and invocation under one explicit identity. Unknown fields, invalid types, duplicate zones or ports, incompatible authentication modes, and cross-field inconsistencies fail before cloud mutations. The observed zone is never written into TOML.

### Configuration fields

| Table | Fields and defaults |
| --- | --- |
| Root | `schema_version = 1`, `provider = "gcp"`, required `environment` |
| `bootstrap` (optional) | Required `script` and `execution_user`; `remote_path = ".piccolo/bootstrap/setup.sh"`, `timeout = 1800` seconds |
| `gcp` | Required `project_id`; `enable_apis = false`, `operation_timeout = 600` seconds |
| `gcp.auth` | `mode = "adc"`; `mode = "file"` requires `credential_file`; optional `impersonate_service_account` |
| `gcp.instance` | Required `name` and full `service_account` email; `machine_type = "n2-standard-4"` |
| `gcp.placement` | Required nonempty ordered `zones`; `snapshot_location = "us"` |
| `gcp.disk` | Required pinned `image` resource path; `size_gb = 30`, `type = "pd-standard"` |
| `gcp.network` | `name = "default"`, `subnet = "default"`, optional region-to-subnet `subnets` mapping, `external_ip = false` |
| `gcp.iap` | `firewall_name` defaults to the environment name plus `-iap`; `ports = [22, 8080]`, `source_ranges = ["35.235.240.0/20"]` |
| `gcp.iam` | `create_service_account = false`, `secrets = []` (existing secret IDs), `project_roles = []` |
| `gcp.ssh` | Required `user`; `via_iap = true`, optional `account` and `impersonate_service_account`, `readiness_timeout = 300` seconds, optional opaque `readiness_command`, `internal_ip = false`, `require_passphrase = false`, `expire-after = "24h"` |
| `gcp.tunnel` | `remote_port = 8080`, `local_port = 8080`; foreground tunnel binds to localhost |

The IAP firewall targets the configured VM service account. Use a dedicated VM account for each environment. Its allowed ports must include SSH and the configured tunnel port when `via_iap` is enabled. Piccolo checks its own rule and the effective VPC and inherited firewall policies. For IAP connections it rejects allow rules that could admit non-IAP traffic to the configured ports, including broad rules for other tags that might apply later. Sources must fall within the IAP IPv4 range `35.235.240.0/20`. Connection attempts recheck effective ingress for the selected interface. These checks are conservative and do not evaluate every deny/allow priority interaction or inspect guest firewalls. Cross-region moves resolve the configured subnet in each candidate region and verify its VPC. V1 supports subnets, networks, and VM service accounts in the selected project; it does not manage VPC creation or Shared VPC.

New VMs have no public IP by default. Private guests need Cloud NAT, a package mirror, or another outbound route before bootstrap can download packages; IAP provides ingress only. Piccolo reports this prerequisite in planning and does not provision NAT. Setting `external_ip = true` explicitly opts into public addressing, whose exposure also depends on ports outside Piccolo's configured set. For direct private connections use `gcp.ssh.via_iap = false` with `internal_ip = true` and provide a route from the workstation to the VPC. Direct external connections require `external_ip = true`. Applications reached through the tunnel must enforce their own authentication.

Piccolo refuses to attach the SDK provisioner service account to the guest. Configured Owner, Editor, administrative, and credential-delegation guest roles are rejected; privileged custom-role permissions are inspected before granting. Planning reports direct guest grants inherited from projects, folders, and organizations, and provisioning rejects known privileged grants. Group membership and condition evaluation require operator review. Guest project roles and individual secret grants remain additive and apply only to the configured VM service account. An existing conditional-only grant for that member and role blocks an unconditional addition. IAM writes require an etag and preserve unrelated grants and conditions. Missing permissions for Piccolo's own SDK actions report the provider role, acting identity when available, and binding scope, for example `[Piccolo] Permission denied. Please bind the required IAM permission GCP:roles/compute.instanceAdmin.v1 to Piccolo's service account provisioner@PROJECT.iam.gserviceaccount.com on projects/PROJECT`. User ADC without an exposed account email is identified as the configured ADC/file provisioner; Piccolo does not infer a service-account email from the guest account.

SDK authentication resolves once per invocation with cloud-platform scopes and passes those credentials to every SDK client. The configured project always selects the target, regardless of credential discovery. For SDK file or impersonation credentials, connection commands require an explicit `gcp.ssh.account` or `gcp.ssh.impersonate_service_account`. Piccolo reports the selected `gcloud` identity separately; it cannot infer that independently configured ADC and `gcloud` logins are identical.

SDK credential files must be operator-controlled Google `service_account` or `authorized_user` JSON. Piccolo validates the type, Google OAuth token endpoint, and `googleapis.com` universe before using a type-specific loader. This policy also applies to `GOOGLE_APPLICATION_CREDENTIALS` and the well-known gcloud ADC file. External-account/federation, GDCH, and embedded impersonation credential JSON are unsupported; use `gcp.auth.impersonate_service_account` with a supported source. Without a local ADC file, SDK authentication uses Google metadata credentials. `validate` checks TOML and referenced paths; credential validation happens before SDK construction. TOML, credentials, readiness commands, and bootstrap scripts must come from trusted operators.

Every gcloud transport checks inherited authentication overrides and active configuration properties before proceeding, including SCP and bootstrap receipt reads. Unset `CLOUDSDK_AUTH_ACCESS_TOKEN`, `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`, `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE`, `CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT`, and `CLOUDSDK_AUTH_DISABLE_CREDENTIALS`. Persisted `auth/access_token_file`, `auth/credential_file_override`, `auth/impersonate_service_account`, and enabled `auth/disable_credentials` also block connections. Configure intended connection impersonation explicitly in TOML; Piccolo reports both the source account and target.

SSH host trust uses host public keys published by Google's guest agent under the `hostkeys/` guest-attribute namespace and fetched through the authenticated Compute API. New VMs enable guest attributes; existing and relocated VMs must have a working guest agent and effective `enable-guest-attributes` metadata. Piccolo waits for publication within the readiness deadline and refuses connections when no trusted key is available. It binds enrollment to the recorded instance and boot-disk IDs, uses a private temporary gcloud home containing only the enrolled known-hosts file, and requires strict host checking for SSH and SCP. The actual gcloud configuration directory and its normal user SSH key path remain explicit. Inherited OpenSSH configuration, global known-hosts files, host-key commands, DNS trust, and automatic host-key updates are disabled for these connections. Automated SSH commands also verify that the actual POSIX login user equals `gcp.ssh.user`. The trusted guest image, guest account, workstation, and GCP administrators remain part of this trust boundary. This verified transport currently supports OpenSSH on Linux/macOS; Windows SSH/SCP is rejected rather than using unverified PuTTY enrollment.

`gcp.ssh.expire-after = "24h"` requests finite published-key access on both SSH and SCP through gcloud's `--ssh-key-expire-after`; shorter or longer positive durations may use `s`, `m`, `h`, or `d`. Expiration bounds published access and does not end an established session or delete the private key. The default suits daily connections to long-lived development VMs. Piccolo never inspects, replaces, changes permissions on, or stores passphrases for existing SSH authentication keys. gcloud creates, stores, and publishes its keys. OS Login and metadata-key policy remain governed by GCP and the user. With `require_passphrase = true`, Piccolo omits `--quiet`, forwards gcloud prompts through an interactive subprocess, and refuses disabled prompts or a missing terminal. Existing encrypted keys used by automated commands must be unlocked through the user's SSH agent because remote commands and SCP use batch mode. This option requests gcloud's prompts and does not certify the protection of an existing key. See the official [SSH](https://docs.cloud.google.com/sdk/gcloud/reference/compute/ssh) and [SCP](https://docs.cloud.google.com/sdk/gcloud/reference/compute/scp) expiration options.

## Commands

| Command | Behavior |
| --- | --- |
| `validate` | Validate local TOML and referenced files without cloud access |
| `plan` | Inspect VM drift, API enablement, service-account state, missing unconditional IAM grants, and firewall reconciliation; no cloud writes |
| `init` | Ensure required APIs, account, additive grants, and firewall; create a fresh VM if absent and stage its script; never execute bootstrap |
| `init --adopt` | Adopt a reviewed legacy VM without Piccolo ownership labels, recording its immutable ID before access reconciliation; no bootstrap eligibility |
| `bootstrap --dry-run` | Show script, execution identity, staging state, and eligibility without invoking setup |
| `bootstrap` | Explicitly authorize and launch the first staged-script attempt on its recorded fresh disk |
| `bootstrap --status` | Read local history and the guest's execution receipt without authorizing another attempt |
| `status` | Report instances, locations, operation journal, and bootstrap history |
| `start` / `stop` | Change power state of an existing VM and await Compute completion |
| `connect` | Start an existing VM if stopped, wait for authenticated SSH readiness, then open a foreground shell |
| `tunnel` | Open a foreground IAP tunnel to the configured port; does not start an application |
| `move [--to ZONE]` | Stop the source, snapshot its boot disk, create and verify a replacement, commit it, then clean up |
| `resume` | Reconcile an interrupted infrastructure operation from journaled requests and cloud observations |
| `resume --rollback` | Restart an uncommitted move's source only after every request is settled and no replacement exists |
| `cleanup [--apply]` | Preview eligible owned artifacts by default; `--apply` deletes reverified eligible disks and snapshots |

Every environment command accepts `-c`/`--config`. Conflicting paths supplied in both positions are rejected. Mutating commands report config path, project, and environment before contacting the provider. There is no `--force` bootstrap bypass, implicit container startup, or destructive environment reset command.

### Daily workflow

```bash
# First-time infrastructure and explicit project setup
piccolo validate
piccolo plan
piccolo init
piccolo bootstrap --dry-run
piccolo bootstrap

# Daily access: start if needed, wait for SSH, and enter the VM
piccolo connect
# Run your own development-environment commands in the VM, then exit.

# Keep the tunnel running in one terminal and reconnect in another.
piccolo tunnel
piccolo connect
```

`connect` requires an existing VM and never provisions infrastructure. SSH probes have bounded retries; permission/configuration failures stop promptly. The optional `readiness_command` is project-owned and runs only as a readiness check; it must be nondestructive. Container and application startup remain your responsibility.

Repeated `init` inspects the existing boot disk and VM. Differences in managed machine type, service account, image, disk size/type, or networking produce an explicit report; Piccolo has no automatic rebuild/update policy. An existing environment with missing state has unknown bootstrap history and cannot become eligible merely by running `init`.

VMs positively labeled for another Piccolo environment are rejected before lifecycle, access, or connection work, including when `--adopt` is supplied. An unrecorded legacy VM requires deliberate `init --adopt` after reviewing its settings and automatic guest hooks. Adoption binds the immutable instance ID locally and preserves its existing disk and labels. Local locks also serialize configurations selecting the same project/VM name within one state root.

## Bootstrap safety

On fresh provisioning, Piccolo records the boot disk's immutable cloud ID, copies the script through the configured development user's SSH session, verifies SHA-256, and stores the artifact's path, digest, and user. It does not attach script metadata, modify startup hooks, or execute setup. Repeated `init` never copies a replacement script onto an existing environment.

`bootstrap` verifies both local and remote script digests and the recorded disk identity. Before launch it flushes authorization and attempt state to the local journal. A guest-side atomic directory claim prevents duplicate launches, and a detached Bash wrapper writes an exit-code receipt and protected log under `~/.piccolo/bootstrap/attempt-DISK_ID/`. Successful completion, script failure, interruption, missing receipts, or an uncertain SSH outcome all block another attempt. Script content changes never authorize execution. Inspect `bootstrap --status` and the recorded `log_path` to recover deliberately; V1 does not offer repeat execution or artifact replacement.

Every staging parent is checked for symlinks and ownership and secured to mode 0700 before transfer. Upload and runner destinations are regular files owned by the execution user, have one hard link, and exist with mode 0600 before SCP; local transfer snapshots also use mode 0600 so SCP cannot request broader permissions. Piccolo verifies script and runner digests, rechecks paths at launch, and executes through the same open file descriptors it hashes. Paths containing reserved `attempt-` receipt components, upload names, or runner suffixes cannot be configured as scripts. Scripts should use `$HOME` or explicit paths for their resources; `BASH_SOURCE` reflects the verified file descriptor rather than the staged pathname. These measures assume the development user and guest kernel are trusted: they cannot isolate bootstrap from another process with that same user's full authority. Keep secrets out of staged scripts.

Moving a disk preserves the staged artifact and guest receipt. It does not grant bootstrap eligibility to the replacement disk. A running or uncertain bootstrap attempt blocks a move until its status is resolved. Guest utilities required for staging/execution are Bash, `sha256sum`, `cut`, `mkdir`, `chmod`, `mv`, `rm`, `cat`, and `nohup`; the image must have a functioning SSH server and Google guest environment. Bootstrap-specific dependencies remain the project's responsibility. Staging and execution additionally require `stat`, `id`, and Linux `/proc/self/fd`.

Piccolo rejects known instance and project startup/shutdown metadata, including script URLs, sysprep, and user-data, before lifecycle and access mutations. Stop, resumed power operations, and retired-source deletion recheck these guards. Existing guest services, cron jobs, and arbitrary hooks installed by an image or a project script remain outside Piccolo's knowledge. Review those hooks before adopting an existing environment; opaque scripts can install their own automatic behavior.

## Relocation and recovery

Move inspects the source and its sole persistent boot disk, rejects unsupported configurations, records their immutable IDs and supported settings, and protects the source disk from auto-deletion. It confirms the source has stopped before taking a snapshot, then confirms the snapshot is ready before trying destination zones. Metadata, tags, supported security settings, service-account scopes, scheduling, disk interface, and custom labels are preserved. Subnet placement and ephemeral IPs are regenerated for the destination. Metadata fingerprints, resource IDs, and read-only API fields are not replayed as creation settings.

`--to` targets exactly one distinct zone. Without it, Piccolo uses the configured order excluding the source. Only structured terminal zone-capacity errors allow another candidate. Quota/permission/configuration errors stop. Transport failures, operation timeouts, and an unknown submission outcome preserve the journal and block alternate-zone creation. Request UUIDs are recorded before submission; operation IDs are recorded afterward. `resume` polls known operations or locates them by their client request ID, without blindly resubmitting a create.

Successful creation operations record Compute's immutable `target_id`, which must match every adopted creation observation. Requested settings are checked against the created resource; disk IDs are recorded independently of their VM attachments, and snapshot/disk source IDs must match the recorded recovery chain. Snapshot cleanup also requires its recorded immutable ID. Relocation rejects unrecognized nondefault settings and separately attached instance/disk tag bindings before stopping the source; inherited project tags remain project policy. Resource names remain the API mutation target, so reads and mutations cannot eliminate races with another administrator or independent state root. Coordinate destructive work externally and retain recovery resources when identity or settings checks fail.

Access reconciliation records API enablement, account creation, IAM additions, and firewall creation separately in the operation's `access_actions`, including intent, preexistence, observed identity, request UUID, returned operation ID, and outcome. `status` exposes partial results. Resume observes existing resources and reconciles pending firewall operations by recorded operation or request UUID before proceeding. Uncertain account/API creation that remains unobservable blocks a new submission and requires manual inspection. IAM merges remain protected by etags. Cleanup retains access resources and grants; review a recorded action's scope, identity, preexistence, and current users manually before any external removal. Never revoke a preexisting or shared grant solely because it appears in this journal.

The source remains stopped until the replacement passes authenticated SSH and any configured readiness check. Piccolo then durably designates the replacement active before deleting the source. The source boot disk is deleted only if Piccolo owns it and confirms its immutable ID and absence of attachments; disks inherited from the historical scripts are retained for manual review. Once committed cleanup succeeds, the recovery snapshot is removed. Failed candidate disks can be previewed and removed with `cleanup` after the operation is resolved.

Exactly one VM is selected by daily commands. Source/replacement overlap is expected only inside the journaled move; unexpected same-name instances block further creation. Unsupported moves include extra disks, regional disks, local SSDs, GPU/reservation-bound or Spot VMs, complex/IPv6 networking, customer-managed encryption, resource policies, and other source settings the adapter cannot preserve. Existing static-IP reservations remain external resources; moves use new ephemeral addresses and do not migrate reserved addresses.

Local state defaults to `~/.piccolo/PROJECT_ENVIRONMENT_HASH/state.json`; `PICCOLO_STATE_DIR` can override the root. Files use atomic replacement, flushes, and operation history. Mutation locks are kernel-held and release on process exit on Linux/macOS and Windows. Keep state on one durable workstation: local locks do not coordinate independent machines. Back up this directory; missing history blocks setup rather than authorizing it. An unresolved operation requires the original TOML bytes, including comments, before `resume`; restore the original config if it changed. If an operation is no longer queryable, preserve state and cloud resources for manual inspection.

Cleanup is deliberately narrower than environment destruction. It requires environment/operation ownership labels, an exact artifact manifest in positively completed init/move history, immutable IDs, settled cloud operation results, and an unambiguous recorded active VM. It excludes attached disks, protects all environment artifacts while any operation is unresolved, and rechecks history, topology, IDs, and attachments before deletion. Missing state, unknown operations, old history without artifact manifests, or expired/unavailable Compute operations retain artifacts for manual recovery; `init` does not authorize their deletion. It never revokes additive IAM grants, deletes accounts/networks, or removes the active VM/firewall. Do not use it as a live-test teardown substitute.

## Providers and package layout

Shared `config`, `state`, `bootstrap`, and CLI layers depend on provider/connection protocols. `providers/registry.py` imports the optional GCP implementation lazily. GCP owns credential resolution, SDK requests, structured failure classification, orchestration, and recovery. AWS/Azure can implement their own provider workflows and declare capabilities without copying GCP's snapshot sequence. SDK extras can be added per provider; external plugin distribution is deferred until needed.

```
src/piccolo/
├── cli.py, errors.py, data.py
├── config/       # discovery, strict TOML, typed models
├── state/        # atomic journal and local environment lock
├── bootstrap/    # opaque staging and explicit invocation policy
└── providers/
    ├── base.py, registry.py
    └── gcp/      # auth, clients, requests, access, lifecycle, connections
tests/            # offline fakes, SDK contracts, local guest, locks
examples/gcp/     # sanitized configuration and harmless project script
```

The historical lean scripts and design transcript are reference material only and are excluded from wheels and source distributions. They are not runtime dependencies.

## Development and packaging

Runtime dependencies, their resolved transitive dependencies, development tools, coverage tools, and the isolated build backend requirements are pinned to exact versions in package metadata. Downstream pip installations receive the same runtime pins as the lock. Controlled recipes use `--locked` to reject a stale lock instead of silently selecting other versions; `just lock` explicitly refreshes lock metadata after an intentional version change. Pre-commit repositories use immutable commit revisions. Dependabot is configured for Python dependency and security updates; enable repository Dependabot alerts/security updates in GitHub and review grouped updates with the local checks. External gcloud, OpenSSH, guest packages, and container dependencies remain operator-managed. Current local validation covers Linux with Python 3.13; Python 3.12 and Windows compatibility have not been newly established by this remediation.

Use `just --list` for recipes. `just install-dev` installs every dependency group and provider extra. `just ci` runs the offline pytest suite, Ruff checks/format verification, and Pyrefly. Tests use fake cloud adapters, anonymous SDK clients with mocked methods, temporary local guest directories, and independent local processes for locks. They do not call GCP or use the reference bootstrap. No live integration suite runs automatically.

```bash
just test
just lint
just typecheck
just coverage
just check-dist
```

Hatchling builds the `src/piccolo` wheel and an explicitly selected source distribution. `just check-dist` builds both and validates their metadata with Twine. Publishing and GitHub release/push operations are reserved for the repository owner. Release notes follow Keep a Changelog in [CHANGELOG.md](CHANGELOG.md).

Live behavior, IAM propagation, SSH key provisioning, cross-region capacity, Windows terminal interruption, and complete real-resource teardown still require the separately approved validation described in [NEXTSTEPS.md](NEXTSTEPS.md).

## Gated live GCP tests

Ordinary `just test` and `just ci` are cloud-free, including when live opt-in variables are present. Live cases require pytest's explicit `--gcp-live` option, `PICCOLO_GCP_LIVE=1`, and `PICCOLO_GCP_LIVE_PROJECT` set to the exact project ID in the TOML. No project is approved by default. SDK writes and the independent janitor recheck the project gate. The historical lean scripts are never executed by the suite.

All live cases and recovery helpers live under `tests/` and are excluded from the wheel. `just typecheck` checks application code and recovery helpers. Offline safety tests use anonymous SDK credentials, injected operations, and local subprocesses for interruptions, lost responses, cleanup failures, changed IDs, attached disks, incomplete inventories, IAM preservation, and default live-test exclusion. Capacity/quota failures are simulated locally; real quota exhaustion is never a test strategy.

Before a live run, copy `examples/gcp/live-approved.toml` to `.test_runs/approved.toml` and replace its placeholders. Approve billing/spending limits, maximum duration, zones in two regions, machine type, disk size, snapshot location, pinned Linux image, VPC/subnets, provisioner account, existing VM account, human owner connection account, and actual OS Login POSIX username. The example's zones and sizes are proposals, not approval. The image needs SSH, Bash, the Google guest agent, and Python 3 for the harmless HTTP listener. No research bootstrap or real secret payload is used.

Set `PICCOLO_GCP_LIVE_PROJECT` in your shell or copy `examples/gcp-live.env.example` to `.env.gcp-live` and replace its value with the same approved project ID. The local dotenv file is ignored by Git. Load it explicitly with `just --dotenv-path .env.gcp-live`; there is no automatic parent-directory dotenv discovery and no dotenv file is required for ordinary tests or CI. Existing shell variables take precedence over dotenv values, so unset a stale shell approval when switching files. The dotenv example supplies the project approval only; the explicit live recipes still supply execution opt-in. [Just dotenv documentation](https://github.com/casey/just/blob/master/README.md#dotenv-settings).

Enable `serviceusage.googleapis.com`, `cloudresourcemanager.googleapis.com`, `compute.googleapis.com`, `iam.googleapis.com`, `secretmanager.googleapis.com`, `iamcredentials.googleapis.com`, `iap.googleapis.com`, and `oslogin.googleapis.com` out of band. The test adapter enables OS Login only on run-owned VMs; it preserves project metadata. Install local OpenSSH client tools (`ssh`, `scp`, and `ssh-keygen`) before running. The suite preserves API state, project metadata/IAM, networks, and existing resources; it fails for missing APIs instead of enabling/disabling them. Disabled-API behavior remains an offline check. Ensure regional subnet coverage and sufficient quotas for temporary source/replacement overlap.

SDK provisioning accepts direct provisioner credentials through ADC or `gcp.auth.credential_file`, or optional provisioner impersonation. Direct service-account keys need no self-impersonation grant. The separate read-only impersonation case loads the authorized human source from `PICCOLO_GCP_LIVE_HUMAN_ADC` (a human ADC JSON file, including one saved with impersonation), then exercises Piccolo's human-to-provisioner token path. That source needs `roles/iam.serviceAccountTokenCreator` on the provisioner. `GOOGLE_APPLICATION_CREDENTIALS` does not select the human `gcloud` account. Authenticate the human owner separately, specify its account and POSIX username, and unset connection credential/access-token/impersonation overrides. The runner rejects inherited access-token/impersonation overrides and configured `gcloud` impersonation. [Impersonation documentation](https://github.com/googleapis/google-auth-library-python/blob/main/docs/user-guide.rst).

The provisioner needs instance/disk/snapshot lifecycle and operation reads, firewall create/get/list/delete, project/subnet reads and subnet use, service-account get/list/create/delete/getIamPolicy/setIamPolicy/testIamPermissions, Secret Manager create/get/list/delete/getIamPolicy/setIamPolicy, and Service Usage discovery/consumption. A practical disposable-project bundle is `roles/compute.instanceAdmin.v1`, `roles/compute.securityAdmin`, `roles/compute.viewer`, `roles/iam.serviceAccountAdmin`, `roles/secretmanager.admin`, and `roles/serviceusage.serviceUsageConsumer`, plus `resourcemanager.projects.get`. Provisioner and connector both need `roles/iam.serviceAccountUser` on the pre-existing VM account, configured out of band. The human owner needs effective IAP TCP forwarding and OS Login permissions. Account attachment's `iam.serviceAccounts.actAs` is separate from impersonation's Token Creator permission. [Service account access documentation](https://docs.cloud.google.com/iam/docs/manage-access-service-accounts).

Each lifecycle/tunnel case runs with both the existing guest account and a unique account created through Piccolo. For the created account, the adapter persists creation intent, then records and adds temporary account-scoped `roles/iam.serviceAccountUser` members for the provisioner and human. It checks provisioner `actAs` before VM creation. Cleanup removes only those added unconditional members from fresh policies with etags after compute resources are gone, preserving unrelated members/conditions. The pre-existing guest account's policy is never changed. Explicit `gcp.iam.secrets` entries may name existing dummy secrets; their immutable IDs are recorded separately, only missing access members are added and later removed with fresh etags, and the secrets themselves are preserved. Synthetic run-scoped dummy secrets are also exercised.

After explicit authorization for creation, harmless guest execution/SSH/IAP, relocation, and scoped teardown, run exactly:

```bash
PICCOLO_GCP_LIVE_HUMAN_ADC=/path/to/human/application_default_credentials.json just --dotenv-path .env.gcp-live test-gcp-live .test_runs/approved.toml
```

For CI or shell-only use, supply the variable directly: `PICCOLO_GCP_LIVE_PROJECT=my-disposable-test-project just test-gcp-live .test_runs/approved.toml`. The recipe reads the approval without replacing it with the TOML's target project.

The recipe streams output to `.test_logs/pytest-gcp-live.log`, preserves pytest's exit status, and retains per-run `.test_runs/plive-RUN/` directories containing generated sanitized TOML, harmless marker script, isolated Piccolo state, baseline inventory/API state, and `manifest.json`. Credentials and secret payloads are not logged. Keep these files for recovery and evidence.

Live assertions cover repeated-init identities, explicit bootstrap and repeat/change/missing-history guards, sentinel hashes across regions, security/account/subnet preservation, cleanup previews, human SSH/IAP traffic, and tunnel interruption. H01 through H06 regressions add real gcloud override parsing, invalid credential rejection before SDK construction, injected interruptions after genuine later-zone acceptance, preservation of an unresolved move snapshot under a fresh state root, foreign-environment rejection, and harmless instance shutdown-hook checks. Project shutdown metadata is tested through a read overlay. Move fallback requires three approved zones and reports a skip with fewer; init fallback requires two. Failed/uncertain bootstrap launches remain deterministic offline checks. These live cases are implemented but have not been executed; Windows/Git Bash outcomes, IAM propagation, and actual spend still require authorized live validation.

The gated `test_live_ssh_key_expire_and_reconnect` regression exercises SSH and SCP with OS Login and instance metadata, using both guest-account fixture variants. Each case creates a fresh VM with its login mode selected before first access and disables bootstrap staging. A disposable Ed25519 test key is generated in the private run directory, given a 45-second published lifetime, and observed authenticating successfully. The test waits for the actual API expiration and a direct OpenSSH `Permission denied (publickey)` result. That probe uses only the test key, disables the SSH agent, and uses an IAP tunnel without invoking gcloud SSH/SCP or republishing a key. Network, host-key, and IAP authorization errors fail the test and are never counted as key expiry. The next Piccolo SSH or SCP invocation requests five minutes of access; the test checks successful reconnection, unchanged public-key identity, a later expiration, and intact SCP probe bytes. Its expiration/rejection wait is bounded to three minutes; each case also includes provisioning and propagation time.

Metadata-mode cases require the connector to have `compute.instances.setMetadata` on the run-owned VM, and the approved disposable project must allow instance-level OS Login overrides. Project SSH metadata is preserved: metadata-mode VMs block project SSH keys and publish only the disposable key at the instance scope. OS Login cases require the existing connector's OS Login and service-account attachment rights. These test prerequisites do not change Piccolo's policy of leaving login-mode selection to GCP and the user. Expiration cases create and inspect only their disposable local keys; the application continues to leave authentication-key management to gcloud.

Run only these cases after approving the usual fixture provisioning, SSH/IAP, metadata, and teardown operations:

```bash
PICCOLO_GCP_LIVE_PROJECT=my-disposable-test-project just test-gcp-live .test_runs/approved.toml tests/test_gcp_live.py::test_live_ssh_key_expire_and_reconnect
```

The manifest records the disposable key, connector account, public-key proof, VM ID, publication intent, observed expiration/rejection, and renewed expiration. Teardown and the independent janitor remove only that proven test key from the matching OS Login profile after compute cleanup, verify removal, and delete the disposable private file. Public evidence is retained. Metadata authorization disappears with its run-owned VM. If the connector login is unavailable or key/VM identities change, cleanup fails visibly and retains the manifest for recovery. Previously existing local and profile keys are preserved. The live expiration cases are implemented and skipped by ordinary local checks; they have not yet been executed against GCP.

Fixture teardown runs in `finally`, including ordinary interruption and setup/assertion failures. It reconciles persisted requests before deleting dependencies, removes proven run-owned VMs, checks disk identities/detachments, then removes disks/snapshots/firewalls, added IAM members, dummy secrets, and created accounts. Unknown creates without observable operations are retained rather than retried or declared absent. Cleanup refuses changed IDs, untracked attachments, auto-delete disks, foreign ownership, and unsafe IAM targets. Prefix inventory detects strays but never authorizes deletion by prefix alone. Unresolved operations, failed deletions, and incomplete inventories fail teardown; leftovers may continue to incur costs.

After a hard kill or workstation loss, run the independent janitor against the durable files. It shares the fixture's environment lock. Preview first, then apply within the approved deletion scope:

```bash
just --dotenv-path .env.gcp-live janitor-gcp-live .test_runs/plive-RUN/manifest.json
just --dotenv-path .env.gcp-live janitor-gcp-live .test_runs/plive-RUN/manifest.json 1
```

Replace `plive-RUN` with the exact directory printed by the runner. The janitor needs neither pytest nor the original fixture process. Preserve unresolved manifests and arrange a follow-up inventory/second janitor invocation; `finally` cannot handle workstation loss. Successful manifests retain the zero-leftover result. No janitor action deletes the project or disables APIs. Project deletion requires separate owner action and approval.

Each manifest stores the resolved project ID at creation, and resource URLs use that recorded ID. Editing or removing a dotenv file does not retarget an existing manifest. Janitor execution requires the environment approval, manifest project, and recovery TOML project to agree before credentials are loaded; mismatches fail instead of redirecting cleanup.

Live validation can require fixes for SDK wire formats, IAM propagation, and workstation tools. A failed run is not proof of guest readiness or successful relocation, even if resource provisioning and teardown succeed. Preserve the final inventory and compare permanent account policies before reporting completion.
