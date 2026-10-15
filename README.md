<!--
Copyright 2026 Israel Flores-Arbolay
SPDX-License-Identifier: Apache-2.0
-->

<h1 align="center">Piccolo</h1>

<p align="center">
  <img src="https://raw.githubusercontent.com/israelflores8789/piccolo/main/media/piccolo-readme-banner-1200px.png" alt="Banner" width=1200 />
</p>

<p align="center"><strong>A simple tool for setting up remote research environments</strong></p>

<p align="center">
  <a href="https://github.com/israelflores8789/piccolo/actions/workflows/ci.yml"><img src="https://github.com/israelflores8789/piccolo/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://pypi.org/project/piccolo-stack/"><img src="https://img.shields.io/pypi/v/piccolo-stack.svg" alt="PyPI version"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-%E2%89%A53.12-blue.svg" alt="Python >=3.12"></a>
  <a href="https://github.com/israelflores8789/piccolo/blob/main/LICENSE"><img src="https://img.shields.io/github/license/israelflores8789/piccolo.svg" alt="License - Apache-2.0"></a>
</p>


Piccolo provisions and manages one development VM per TOML configuration. Google Cloud infrastructure uses Google's Python SDKs. Linux/macOS SSH and file transfer use `gcloud`; native Windows uses Windows OpenSSH with explicit GCP key authorization. IAP tunnels and connection credentials use `gcloud` on all platforms. Python 3.12 or newer is required.

Infrastructure provisioning, explicit project setup, and daily connections are separate commands. Piccolo treats bootstrap as an opaque, project-owned Bash script. It never interprets the script or manages containers, repositories, development tools, or credentials inside it.

## Install

```bash
pip install 'piccolo-stack[gcp]'
piccolo --help
```

Install the Google Cloud CLI and its SSH/SCP prerequisites for connection commands. Configure SDK ADC and the `gcloud` connection login independently. Piccolo does not log in, activate credential files in `gcloud`, or create service-account keys. This README is the operational source for cloud prerequisites, approval, and recovery. Native Windows live validation is a separate, opt-in task.

For local development:

```bash
just install-dev
just ci
```

Shared OpenSSH mechanics live in `piccolo.openssh`; GCP authorization, host-key retrieval, address selection, and IAP setup remain in the GCP provider. State-root paths belong to `piccolo.state.paths`, Cloud SDK paths to `piccolo.providers.gcp.paths`, and Windows process containment to `piccolo.win32process`. Run the provider-independent client tests with `just test tests/test_openssh.py`, provider session tests with `just test tests/test_native_ssh.py`, and native ACL checks with `just test tests/test_windows_storage.py`. Platform-specific cases skip on other operating systems; `just test` excludes both live suites.

### Native Windows

Install the Windows OpenSSH Client optional feature, version 9.0 or newer, and the full Google Cloud CLI. Native Windows Python selects `ssh.exe`, `scp.exe`, and `ssh-keygen.exe` under the Windows system OpenSSH directory even when Git Bash tools appear first on PATH. Windows Terminal with Git Bash and PowerShell use the same native implementation. Python inside WSL uses the Linux implementation and Linux paths. Keep private state and keys on a local ACL-capable filesystem; network shares, junctions, reparse points, and multiply linked private files are refused.

`piccolo connect` and `piccolo tunnel` retain their existing CLI. Native SSH inherits terminal input/output, requests a remote PTY, and isolates user/global SSH configuration through private internally generated files. The separate application tunnel remains a foreground localhost IAP tunnel. Windows SCP uses SFTP and requires the Linux guest's SFTP subsystem. The terminal theme/query exchange, resizing, Unicode, and interruption behavior still need the separately approved Windows Terminal/UsageBassoon acceptance exercise described in [WIN-PROPOSAL.md](WIN-PROPOSAL.md); offline process checks cannot establish those terminal properties.

Piccolo reuses `%USERPROFILE%\.ssh\google_compute_engine`, repairs its current-user DACL before reuse, and creates a new RSA key only when both halves are absent. A missing public half can be recovered without replacing the private key; mismatched or broken pairs require deliberate operator repair. Existing `.ssh` directory permissions and unrelated configuration are not reset. A shared key lock coordinates Piccolo processes across environments and state-root overrides. Encrypted existing keys can use the native Windows SSH agent with the default BatchMode behavior. `require_passphrase = true` requires an encrypted key and an interactive terminal for prompts; Piccolo never supplies a passphrase on the command line.

Native Windows registration uses only the selected gcloud connection identity. Instance metadata updates merge unrelated entries, require the current fingerprint, retry only rejected fingerprint conflicts, and attach the configured expiration. OS Login checks the primary POSIX username before importing a key with TTL; `gcp.ssh.user` must match it. OS Login certificate and two-factor modes are explicitly unsupported by this native transport. Guest-attribute host keys remain authenticated and bound to the immutable VM ID, with strict host-key checking. Google Cloud SDK paths follow `CLOUDSDK_CONFIG` or `%APPDATA%\gcloud` on Windows and `~/.config/gcloud` on POSIX; an empty override uses the platform default, and missing Windows APPDATA fails explicitly.

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
| `gcp.auth` | `mode = "adc"`; `mode = "file"` requires `credentials_file`; optional `impersonate_service_account` |
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
| `move [--to ZONE]` | Stop and snapshot the source, verify and commit a replacement, retire the source VM, and retain recovery copies until explicit cleanup |
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

Moving a disk preserves the staged artifact and guest receipt. It does not grant bootstrap eligibility to the replacement disk. A running or uncertain bootstrap attempt blocks stop, resumed stop, and relocation until its status is resolved. Guest utilities required for staging/execution are Bash, `sha256sum`, `cut`, `mkdir`, `chmod`, `mv`, `rm`, `cat`, `nohup`, and `setsid`; the image must have a functioning SSH server and Google guest environment. Bootstrap-specific dependencies remain the project's responsibility. Staging and execution additionally require `stat`, `id`, and Linux `/proc/self/fd`.

`bootstrap.timeout` is an observation deadline. The detached script keeps running after that deadline or a local disconnect; Piccolo does not cancel or replay it. The wrapper starts a separate process group, writes its PID to the receipt's `process-id`, and reports `process_id`, `process_group_id`, `process_path`, and `log_path` through status when available. Completion can be repaired by restoring the original trustworthy guest receipt and running `bootstrap --status`; never invent a successful exit code. Readiness commands may run repeatedly and must be nondestructive and safe to repeat.

For deliberate cancellation, connect as the recorded execution user, locate the exact recorded receipt, and inspect its PID, process group, start time, and command with `ps`. A PID alone is insufficient because it may have been reused. After confirming the group belongs to this attempt, send `kill -TERM -- -PGID`; inspect and terminate any remaining members deliberately if necessary. Scripts can create processes outside that group, so also inspect their workload-specific jobs. Only after verifying all attempt processes have stopped, atomically write a nonzero cancellation receipt, for example `printf '130\n' > "$receipt/exit-code.tmp"` followed by `mv "$receipt/exit-code.tmp" "$receipt/exit-code"`, with `receipt` set to the exact private attempt directory. Then run `bootstrap --status` to record failure and unblock power/relocation commands. If identity, completion, or receipt authenticity cannot be verified, retain uncertainty and inspect manually. Cancellation can leave partially applied setup; it never authorizes another bootstrap attempt.

Guest `output.log` inherits everything the opaque script prints. Its private permissions protect access; it is not automatically scrubbed or fetched into diagnostics. Keep credentials out of scripts and logs, and review files before sharing them. Interactive SSH sessions also display the guest's own output directly.

Piccolo rejects known instance and project startup/shutdown metadata, including script URLs, sysprep, and user-data, before lifecycle and access mutations. Stop, resumed power operations, and retired-source deletion recheck these guards. Existing guest services, cron jobs, and arbitrary hooks installed by an image or a project script remain outside Piccolo's knowledge. Review those hooks before adopting an existing environment; opaque scripts can install their own automatic behavior.

## Relocation and recovery

Move inspects the source and its sole persistent boot disk, rejects unsupported configurations, records their immutable IDs and supported settings, and protects the source disk from auto-deletion. It confirms the source has stopped before taking a snapshot, then confirms the snapshot is ready before trying destination zones. Metadata, tags, supported security settings, service-account scopes, scheduling, disk interface, and custom labels are preserved. Subnet placement and ephemeral IPs are regenerated for the destination. Metadata fingerprints, resource IDs, and read-only API fields are not replayed as creation settings.

`--to` targets exactly one distinct zone. Without it, Piccolo uses the configured order excluding the source. Only structured terminal zone-capacity errors allow another candidate. Quota/permission/configuration errors stop. Transport failures, operation timeouts, and an unknown submission outcome preserve the journal and block alternate-zone creation. Request UUIDs are recorded before submission; operation IDs are recorded afterward. `resume` polls known operations or locates them by their client request ID, without blindly resubmitting a create.

Successful creation operations record Compute's immutable `target_id`, which must match every adopted creation observation. Requested settings are checked against the created resource; disk IDs are recorded independently of their VM attachments, and snapshot/disk source IDs must match the recorded recovery chain. Snapshot cleanup also requires its recorded immutable ID. Relocation rejects unrecognized nondefault settings and separately attached instance/disk tag bindings before stopping the source; inherited project tags remain project policy. Resource names remain the API mutation target, so reads and mutations cannot eliminate races with another administrator or independent state root. Coordinate destructive work externally and retain recovery resources when identity or settings checks fail.

Access reconciliation records API enablement, account creation, IAM additions, and firewall creation separately in the operation's `access_actions`, including intent, preexistence, observed identity, request UUID, returned operation ID, and outcome. `status` exposes partial results. Resume observes existing resources and reconciles pending firewall operations by recorded operation or request UUID before proceeding. Uncertain account/API creation that remains unobservable blocks a new submission and requires manual inspection. IAM merges remain protected by etags. Cleanup retains access resources and grants; review a recorded action's scope, identity, preexistence, and current users manually before any external removal. Never revoke a preexisting or shared grant solely because it appears in this journal.

The source remains stopped until the replacement passes authenticated SSH and any configured readiness check. Piccolo durably designates the replacement active before deleting the stopped source VM, after rechecking its protected boot disk and the recovery snapshot. The source disk and snapshot remain available and billable indefinitely until explicit finalization. Inspect workload health, repository/data hashes, and writable application/container state on the replacement before previewing `piccolo cleanup` and deliberately running `piccolo cleanup --apply`. Only eligible Piccolo-owned, detached resources with recorded identities can be removed; preexisting source disks remain for manual review. Generic SSH or a `true` readiness probe does not validate application or data integrity. Maintain independent backups; Piccolo cannot automatically roll back after commitment. Failed candidate disks can also appear in the cleanup preview after the operation is resolved.

Exactly one VM is selected by daily commands. Source/replacement overlap is expected only inside the journaled move; unexpected same-name instances block further creation. Unsupported moves include extra disks, regional disks, local SSDs, GPU/reservation-bound or Spot VMs, complex/IPv6 networking, customer-managed encryption, resource policies, and other source settings the adapter cannot preserve. Existing static-IP reservations remain external resources; moves use new ephemeral addresses and do not migrate reserved addresses.

Local state uses platformdirs' user-state directory: `$XDG_STATE_HOME/piccolo` or `~/.local/state/piccolo` on Linux, `%LOCALAPPDATA%\piccolo` on Windows, and `~/Library/Application Support/piccolo` on macOS. `PICCOLO_STATE_DIR` overrides the root and must be nonempty. Environment and same-VM hashes identify journal directories and resource locks. Files use atomic replacement, flushes, and retained operation history. POSIX storage checks ownership and repairs private modes; Windows storage verifies opened handles, current-user ownership, protected DACLs, reparse attributes, and single-link regular files. Windows temporary/replacement files are private before their first write. Shared profile ancestors are checked without resetting their ACLs.

Keep state on one durable workstation and back it up: local locks do not coordinate independent machines, and missing history blocks setup rather than authorizing it. Recovery hashes a canonical representation of effective parsed settings, including defaults and resolved file paths. Comments, whitespace, and table/key order do not change that hash; significant array order or actual setting changes do. Restore the original settings before resuming a changed operation. If an operation is no longer queryable, preserve state and cloud resources for manual inspection.

`privacy.py` centralizes credential-field and sensitive-text redaction; `logger.py` centralizes console JSON, errors, and notifications. Diagnostics hide arbitrary metadata, descriptions, and label values. Journals omit source metadata/descriptions and scrub credential fields and messages; relocation rereads the live source to preserve its metadata without retaining a confidential copy locally. Baseline live inventories retain identifiers and statuses only. Credential JSON values are registered for later diagnostic redaction without being copied into state. Keep operator credentials outside the repository, preferably under an ignored `.credentials/` directory; common credential JSON, PEM, and key filenames are also ignored. Pattern-based redaction cannot recognize every unlabelled secret a project script might print.

Cleanup is deliberately narrower than environment destruction. It requires environment/operation ownership labels, an exact artifact manifest in positively completed init/move history, immutable IDs, settled cloud operation results, and an unambiguous recorded active VM. It excludes attached disks, protects all environment artifacts while any operation is unresolved, and rechecks history, topology, IDs, and attachments before deletion. Missing state, unknown operations, old history without artifact manifests, or expired/unavailable Compute operations retain artifacts for manual recovery; `init` does not authorize their deletion. It never revokes additive IAM grants, deletes accounts/networks, or removes the active VM/firewall. Do not use it as a live-test teardown substitute.

## Providers and package layout

Shared `config`, `state`, `bootstrap`, and CLI layers depend on provider/connection protocols. `providers/registry.py` imports the optional GCP implementation lazily. GCP owns credential resolution, SDK requests, structured failure classification, orchestration, and recovery. AWS/Azure can implement their own provider workflows and declare capabilities without copying GCP's snapshot sequence. SDK extras can be added per provider; external plugin distribution is deferred until needed.

```
src/piccolo/
├── cli.py, errors.py, data.py, privacy.py, logger.py
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

Runtime dependencies, their resolved transitive dependencies, development tools, coverage tools, and the isolated build backend requirements are pinned to exact versions in package metadata. Downstream pip installations receive the same runtime pins as the lock. Controlled recipes use `--locked` to reject a stale lock instead of silently selecting other versions; `just lock` explicitly refreshes lock metadata after an intentional version change. Platformdirs is a runtime dependency; pywin32 installs only on native Windows, and its type stubs are development-only. Pre-commit repositories use immutable commit revisions. Dependabot is configured for Python dependency and security updates; enable repository Dependabot alerts/security updates in GitHub and review grouped updates with the local checks. External gcloud, OpenSSH, guest packages, and container dependencies remain operator-managed. CI runs local tests on Linux, Windows, and macOS with Python 3.12 and 3.14. Linux guest process-group and POSIX filesystem integration checks remain platform-specific; native Windows has actual ACL, locking, key, process, and proxy tests.

Use `just --list` for recipes. `just install-dev` installs every dependency group and provider extra. `just ci` runs the offline pytest suite, Ruff checks/format verification, and Pyrefly. Tests use fake cloud adapters, anonymous SDK clients with mocked methods, temporary local guest directories, and independent local processes for locks. They do not call GCP or use the reference bootstrap. No live integration suite runs automatically.

```bash
just test
just lint
just typecheck
just coverage
just check-dist
```

Hatchling builds a wheel containing runtime Python modules and required package/license metadata, plus an explicitly selected source distribution. Schema JSON, audits, examples, tests, and reference/design files do not ship in the wheel; schema and audit documents are also excluded from the selected source distribution. Clone the repository to inspect those materials. `just check-dist` builds both and validates their metadata with Twine. Publishing and GitHub release/push operations are reserved for the repository owner. Release notes follow Keep a Changelog in [CHANGELOG.md](CHANGELOG.md).

Native Windows live behavior and terminal acceptance require the separately approved validation described below. Offline validation does not establish Windows provisioning, bootstrap, relocation, recovery, or terminal behavior against real GCP resources.

### Windows test prerequisites

Run Windows tests with native Windows Python and Git for Windows. Git's `usr\bin` directory must be on `PATH` so the test helpers can discover `cygpath.exe` and use the matching Git Bash executable. Having `bash.exe` on `PATH` alone is insufficient. This is a development/test prerequisite; using the installed Piccolo CLI from PowerShell does not require `cygpath`.

For a standard Git for Windows installation, run the following in PowerShell to add the directory to your user `PATH` and update the current session. Adjust `$gitTools` if Git is installed elsewhere.

```powershell
$gitTools = 'C:\Program Files\Git\usr\bin'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $gitTools) {
    [Environment]::SetEnvironmentVariable(
        'Path', "$gitTools;$userPath".TrimEnd(';'), 'User'
    )
}
$env:Path = "$gitTools;$env:Path"
Get-Command cygpath
cygpath -u $env:USERPROFILE
```

`Get-Command` should resolve to the Git installation's `usr\bin\cygpath.exe`, and `cygpath` should print your home directory as a POSIX path. Restart Windows Terminal and any editor or Codex instance that launches tests so future sessions inherit the saved user `PATH`. The commands above update the current PowerShell session immediately. See Microsoft's [PowerShell environment-variable documentation](https://github.com/MicrosoftDocs/PowerShell-Docs/blob/main/reference/7.6/Microsoft.PowerShell.Core/About/about_Environment_Variables.md) for process and persistent environment scopes.

### GCP Windows live selection

The native Windows GCP suite is `tests/test_gcp_win_live.py`, marked `gcp_win_live` and selected with `--gcp-win-live` through `just test-gcp-win-live PROFILE`. It is excluded from `just test`, `just ci`, and CI, and cannot be combined with the POSIX `--gcp-live` selection. The same project approval digest, cumulative duration, spending ledger, manifests, and scoped janitor apply. The Windows recipe requires `PICCOLO_GCP_LIVE_BUDGET_FILE`; no live validation is authorized merely by installing Piccolo or selecting a marker.

Automated GCP Windows cases use the explicitly logged-in `piccolo-test-provisioner` connection account, the approved existing test VM account, and disposable manifest-recorded keys. They cover SSH/SCP expiration and renewal in metadata and OS Login modes without reading or replacing the workstation's ordinary SSH key. Human-account terminal/theme acceptance needs separate explicit authorization and is not part of these automated cases. The Windows suite has been authored and checked offline but has not been run against GCP as part of this implementation.

## Gated live GCP tests

Ordinary `just test` and `just ci` are cloud-free, including when live opt-in variables are present. Live cases require pytest's explicit `--gcp-live` option, `PICCOLO_GCP_LIVE=1`, and `PICCOLO_GCP_LIVE_PROJECT` set to the exact project ID in the TOML. No project is approved by default. SDK writes and the independent janitor recheck the project gate. The historical lean scripts are never executed by the suite.

All live cases and recovery helpers live under `tests/` and are excluded from the wheel. `just typecheck` checks application code and recovery helpers. Offline safety tests use anonymous SDK credentials, injected operations, and local subprocesses for interruptions, lost responses, cleanup failures, changed IDs, attached disks, incomplete inventories, IAM preservation, and default live-test exclusion. Capacity/quota failures are simulated locally; real quota exhaustion is never a test strategy.

Before a live run, copy `examples/gcp/live-approved.toml` to `.test_runs/approved.toml` and replace its placeholders. Review the 45-minute duration, zones in two regions, machine type, disk size, snapshot location, pinned Linux image, VPC/subnets, provisioner account, existing VM account, human owner connection account, allowed dummy-secret IDs, and actual OS Login POSIX username. The example's zones and sizes are proposals, not approval. The image needs SSH, Bash, `setsid`, the Google guest agent, and Python 3 for the harmless HTTP listener. No research bootstrap or real secret payload is used.

Run `just approval-gcp-live .test_runs/approved.toml` locally to display the proposed settings and approval digest. After reviewing them, pin the displayed `approval_sha256` in `PICCOLO_GCP_LIVE_APPROVAL_SHA256`; the runner rejects missing or changed digests before loading credentials. This pins canonical profile settings, the selected `PICCOLO_GCP_LIVE_MOVE_CASES` variant, dummy-payload hash, and deadline policy. A formatting-only edit preserves approval. Changing actual settings or variant selection requires a newly reviewed digest. The review command does not grant execution authorization.

Set `PICCOLO_GCP_LIVE_PROJECT` and `PICCOLO_GCP_LIVE_APPROVAL_SHA256` in your shell or copy `examples/gcp/gcp-live.env.example` to `.env.gcp-live` and replace its placeholders with the approved project ID and reviewed digest. The local dotenv file is ignored by Git. Load it explicitly with `just --dotenv-path .env.gcp-live`; there is no automatic parent-directory dotenv discovery and no dotenv file is required for ordinary tests or CI. Existing shell variables take precedence over dotenv values, so unset stale shell approvals when switching files. Explicit live recipes still supply execution opt-in. [Just dotenv documentation](https://github.com/casey/just/blob/master/README.md#dotenv-settings).

Enable `serviceusage.googleapis.com`, `cloudresourcemanager.googleapis.com`, `compute.googleapis.com`, `iam.googleapis.com`, `secretmanager.googleapis.com`, `iamcredentials.googleapis.com`, `iap.googleapis.com`, and `oslogin.googleapis.com` out of band. The test adapter enables OS Login only on run-owned VMs; it preserves project metadata. Install local OpenSSH client tools (`ssh`, `scp`, and `ssh-keygen`) before running. The suite preserves API state, project metadata, networks, and existing resources; it fails for missing APIs instead of enabling/disabling them. Explicitly approved `gcp.iam.project_roles` are applied only to the fixture's guest service account. The manifest records the project and guest identities and each previously absent unconditional member before writing; teardown removes only those added members from freshly read policies with etags and verifies removal. Existing bindings and unrelated policy changes are preserved. The provisioner needs `resourcemanager.projects.getIamPolicy` and `resourcemanager.projects.setIamPolicy` when project roles are configured. Conditional-only access is rejected instead of widened. Disabled-API behavior remains an offline check. Ensure regional subnet coverage and sufficient quotas for temporary source/replacement overlap.

SDK provisioning accepts direct provisioner credentials through ADC or `gcp.auth.credentials_file`, or optional provisioner impersonation. Direct service-account keys need no self-impersonation grant. The separate read-only impersonation case loads the authorized human source from `PICCOLO_GCP_LIVE_HUMAN_ADC` (a human ADC JSON file, including one saved with impersonation), then exercises Piccolo's human-to-provisioner token path. That source needs `roles/iam.serviceAccountTokenCreator` on the provisioner. `GOOGLE_APPLICATION_CREDENTIALS` does not select the human `gcloud` account. Authenticate the human owner separately, specify its account and POSIX username, and unset connection credential/access-token/impersonation overrides. The runner rejects inherited access-token/impersonation overrides and configured `gcloud` impersonation. [Impersonation documentation](https://github.com/googleapis/google-auth-library-python/blob/main/docs/user-guide.rst).

The provisioner needs instance/disk/snapshot lifecycle and operation reads, firewall create/get/list/delete, project/subnet reads and subnet use, service-account get/list/create/delete/getIamPolicy/setIamPolicy/testIamPermissions, Secret Manager create/get/list/delete/getIamPolicy/setIamPolicy, and Service Usage discovery/consumption. A practical disposable-project bundle is `roles/compute.instanceAdmin.v1`, `roles/compute.securityAdmin`, `roles/compute.viewer`, `roles/iam.serviceAccountAdmin`, `roles/secretmanager.admin`, and `roles/serviceusage.serviceUsageConsumer`, plus `resourcemanager.projects.get`. Provisioner and connector both need `roles/iam.serviceAccountUser` on the pre-existing VM account, configured out of band. The human owner needs effective IAP TCP forwarding and OS Login permissions. Account attachment's `iam.serviceAccounts.actAs` is separate from impersonation's Token Creator permission. [Service account access documentation](https://docs.cloud.google.com/iam/docs/manage-access-service-accounts).

Each lifecycle/tunnel case runs with both the existing guest account and a unique account created through Piccolo. For the created account, the adapter persists creation intent, then records and adds temporary account-scoped `roles/iam.serviceAccountUser` members for the provisioner and human. It checks provisioner `actAs` before VM creation. Cleanup removes only those added unconditional members from fresh policies with etags after compute resources are gone, preserving unrelated members/conditions. The pre-existing guest account's policy is never changed. Explicit `gcp.iam.secrets` entries must name reviewed dummy secrets labelled `piccolo-live-dummy=true`. Before any guest IAM grant, the provisioner must read their payload and verify the fixed harmless bytes `TEST_thisisadummytestsecret_TEST`; grant Secret Manager version access to the provisioner on those dummy secrets out of band. The manifest records immutable secret IDs and validated numeric version names, and guest verification uses those pinned versions rather than `latest`. Only missing access members are added and later removed with fresh etags, and existing secrets are preserved. Maintain these targets as dummy-only; the guest account's secret-level IAM grant is not restricted to one version. Synthetic run-scoped dummy secrets are also exercised.

After explicit authorization for creation, harmless guest execution/SSH/IAP, relocation, and scoped teardown, run exactly:

```bash
PICCOLO_GCP_LIVE_HUMAN_ADC=/path/to/human/application_default_credentials.json just --dotenv-path .env.gcp-live test-gcp-live .test_runs/approved.toml
```

For CI or shell-only use, supply both variables directly: `PICCOLO_GCP_LIVE_PROJECT=my-disposable-test-project PICCOLO_GCP_LIVE_APPROVAL_SHA256=REVIEWED_DIGEST just test-gcp-live .test_runs/approved.toml`. The recipe reads the approvals without deriving execution approval from the TOML's target project.

The recipe streams sanitized diagnostics to a private `.test_logs/pytest-gcp-live.log`, preserves pytest's exit status, and retains per-run `.test_runs/plive-RUN/` directories containing generated TOML, harmless marker script, isolated Piccolo state, a baseline inventory of identifiers/statuses, and `manifest.json`. Set `PICCOLO_GCP_LIVE_LOG` to a distinct private log path when retaining separate selections. Each manifest records the reviewed digest, test/account/login variant, recovery-config fingerprint, cleanup command, and final residual-resource report. Credentials and secret payloads are not deliberately logged. Keep these files for recovery and evidence.

The live session uses one cooperative 45-minute deadline. New tests and work stop after 40 minutes; the last five minutes are reserved for scoped teardown, including a final minute for inventory. SDK RPCs, including later list pages, disable automatic retries and use at most 30 seconds or the remaining phase time. SSH/gcloud and native probes are bounded too. Cleanup failures, interrupted cleanup, and unavailable/incomplete final inventories are recorded alongside observed remaining resource IDs, locations, statuses, and recovery URLs. A failed cleanup cannot be declared zero leftovers merely because a final listing is empty. The independent janitor uses the same bounded cleanup/reporting policy on a fresh invocation.

Set `PICCOLO_GCP_LIVE_SECONDS` to the explicitly authorized total allowance before reviewing the approval digest. The default is 2700 seconds; the supported range is 301–6300 seconds, and any extension requires operator authorization and a newly reviewed digest. The five-minute cleanup reserve remains intact. Each fixture records the actual session allowance in its manifest. To share one cumulative deadline across setup, selections, reruns, and janitor invocations, record `time.monotonic()` once in `PICCOLO_GCP_LIVE_STARTED_MONOTONIC` before setup and preserve that value in every process on the same running host. An extension changes the total allowance without changing the original start. Future, nonfinite, and malformed starts are rejected. Without this shared anchor, an independent invocation starts its own allowance; the operator must account for previously spent time.

The approved-project session helper accepts `PICCOLO_GCP_LIVE_BASELINE` for a fresh account/IAM baseline, bounds setup and teardown with the shared deadline, and reports leftover networks, subnets, and recoverable snapshots alongside other test resources. For the approved regional `e2-small`, 10 GiB, private-IP continuation, `PICCOLO_GCP_LIVE_BUDGET_FILE` enables a persisted transfer reservation ledger. Reserve VM/disk/snapshot time and small request charges before execution; disk restores require a manifest-proven snapshot no larger than one GiB of stored data, and North America region transfers reserve charges before submission. Repeated request IDs are charged once. This specialized estimator is not a billing API or a general dollar-limit guarantee.

Live Service Usage RPC attempts share a 1.05-second minimum interval across SDK clients and fixtures, including retries; pacing refuses a new call when its delay would consume the phase budget. The `get_service` read may retry a transient `503` up to two times, with a newly computed phase timeout before each attempt and a bounded delay. SDK automatic retries remain disabled, and mutating methods are never retried by this wrapper. Extra arguments to `just test-gcp-live CONFIG FIRST_CASE ...` can select and order additional cases or supply pytest options when a cumulative budget requires prioritization. Fixture SSH metadata is included in expected creation settings before submission and on recovery. Optional `PICCOLO_GCP_LIVE_INIT_ZONE` restricts initial disk/VM creation to that zone before cloud access, allowing an operator to authorize a different zone solely for relocation.

For a shorter continuation, explicitly select `test_live_security_iap_and_recovery_sequence` to reuse one fixture for credential rejection, instance shutdown-hook rejection, human IAP/interruption, foreign-environment rejection, and missing-state recovery retention. The sequence restores injected metadata and stops its guest HTTP server before relocation. Ordinary stop/start is already covered by the lifecycle case and is omitted from this grouped sequence. Select `test_live_ssh_expiry_transport_sequence` to exercise SSH and SCP with distinct disposable keys on one fresh fixture per login mode and account variant. These grouped cases are additional selections; the standalone cases remain available. A partial selection or deadline-skipped group does not establish that the full live matrix passed. Set `PICCOLO_GCP_LIVE_LOGIN_MODE=metadata` for instance-scoped metadata login in other fixture selections. Serialize cases that publish OS Login keys for the same human account; the API can reject concurrent profile mutations.

This deadline does not enforce a dollar limit or guarantee a maximum bill. Accepted cloud operations may continue after a local timeout, retained resources can keep billing, and a hard process kill or workstation failure can prevent final reporting. The operator remains responsible for the project and accepts residual billing risk. Arrange independent access to the retained manifest and janitor before execution; the runner prints its cleanup command before the first mutation. Review skipped variants and failed stages in pytest's retained log before treating a run as validation. Most lifecycle fixtures use OS Login and REST Service Usage; separate SSH-expiration cases cover metadata login, and passing fixtures alone does not validate every ordinary runtime path.

Live assertions cover repeated-init identities, explicit bootstrap and repeat/change/missing-history guards, sentinel hashes across regions, security/account/subnet preservation, cleanup previews, human SSH/IAP traffic, and tunnel interruption. H01 through H06 regressions add real gcloud override parsing, invalid credential rejection before SDK construction, injected interruptions after genuine later-zone acceptance, preservation of an unresolved move snapshot under a fresh state root, foreign-environment rejection, and harmless instance shutdown-hook checks. Project shutdown metadata is tested through a read overlay. Move fallback requires three approved zones and reports a skip with fewer; init fallback requires two. Failed/uncertain bootstrap launches remain deterministic offline checks. The authorized 2026-10-12 continuation completed the assertion matrix through 26 distinct live selections, including all 14 fallback permutations and all eight account/login/transport expiration-and-renewal combinations. Grouped selections reuse the standalone assertion bodies; the 44 raw live node IDs were not all run separately. Final cleanup and original IAM preservation were verified. Windows/Git Bash outcomes remain untested; see [the audit validation record](audits/2026-10-11-security.md).

The gated `test_live_ssh_key_expire_and_reconnect` regression exercises SSH and SCP with OS Login and instance metadata, using both guest-account fixture variants. Each case creates a fresh VM with its login mode selected before first access and disables bootstrap staging. A disposable Ed25519 test key is generated in the private run directory, given a 45-second published lifetime, and observed authenticating successfully. The test waits for the actual API expiration and a direct OpenSSH `Permission denied (publickey)` result. That probe uses only the test key, disables the SSH agent, and uses an IAP tunnel without invoking gcloud SSH/SCP or republishing a key. Network, host-key, and IAP authorization errors fail the test and are never counted as key expiry. The next Piccolo SSH or SCP invocation requests five minutes of access; the test checks successful reconnection, unchanged public-key identity, a later expiration, and intact SCP probe bytes. Its expiration/rejection wait is bounded to three minutes; each case also includes provisioning and propagation time.

Metadata-mode cases require the connector to have `compute.instances.setMetadata` on the run-owned VM, and the approved disposable project must allow instance-level OS Login overrides. Project SSH metadata is preserved: metadata-mode VMs block project SSH keys and publish only the disposable key at the instance scope. OS Login cases require the existing connector's OS Login and service-account attachment rights. These test prerequisites do not change Piccolo's policy of leaving login-mode selection to GCP and the user. Expiration cases create and inspect only their disposable local keys; the application continues to leave authentication-key management to gcloud.

Run only these cases after approving the usual fixture provisioning, SSH/IAP, metadata, and teardown operations:

```bash
PICCOLO_GCP_LIVE_PROJECT=my-disposable-test-project just test-gcp-live .test_runs/approved.toml tests/test_gcp_live.py::test_live_ssh_key_expire_and_reconnect
```

The manifest records the disposable key, connector account, public-key proof, VM ID, publication intent, observed expiration/rejection, and renewed expiration. Teardown and the independent janitor remove only that proven test key from the matching OS Login profile after compute cleanup, verify removal, and delete the disposable private file. Public evidence is retained. Metadata authorization disappears with its run-owned VM. If the connector login is unavailable or key/VM identities change, cleanup fails visibly and retains the manifest for recovery. Previously existing local and profile keys are preserved. The authorized 2026-10-12 continuation verified genuine expiration, rejection, and renewal for SSH and SCP under both login modes and both account variants. It exposed an OS Login propagation race in SCP: Piccolo now retries only a public-key rejection before transfer, within the original transfer timeout. Other transfer failures remain errors without replay.

Fixture teardown runs in `finally`, including ordinary interruption and setup/assertion failures. It reconciles persisted requests before deleting dependencies, removes proven run-owned VMs, checks disk identities/detachments, then removes disks/snapshots, permanently purges manifest-proven recoverable snapshot copies, and removes firewalls, added IAM members, dummy secrets, and created accounts. Recycle-bin purges use the beta API with original snapshot IDs matched to the manifest, persisted request UUIDs and operation IDs, and verified absence. Final inventory includes recoverable snapshots because ordinary deletion can retain billable copies. Unknown creates or uncertain purges without observable operations are retained rather than retried or declared absent. Cleanup refuses changed IDs, untracked attachments, auto-delete disks, foreign ownership, and unsafe IAM targets. Prefix inventory detects strays but never authorizes deletion by prefix alone. Unresolved operations, failed deletions, and incomplete inventories fail teardown; leftovers may continue to incur costs.

After a hard kill or workstation loss, run the independent janitor against the durable files. It shares the fixture's environment lock. Preview first, then apply within the approved deletion scope:

```bash
just --dotenv-path .env.gcp-live janitor-gcp-live .test_runs/plive-RUN/manifest.json
just --dotenv-path .env.gcp-live janitor-gcp-live .test_runs/plive-RUN/manifest.json 1
```

Replace `plive-RUN` with the exact directory printed by the runner. The janitor needs neither pytest nor the original fixture process. Preserve unresolved manifests and arrange a follow-up inventory/second janitor invocation; `finally` cannot handle workstation loss. Successful manifests retain the zero-leftover result. No janitor action deletes the project or disables APIs. Project deletion requires separate owner action and approval.

Each manifest stores the resolved project ID at creation, and resource URLs use that recorded ID. Editing or removing a dotenv file does not retarget an existing manifest. Janitor execution requires the environment approval, manifest project, and recovery TOML project to agree before credentials are loaded; mismatches fail instead of redirecting cleanup.

Live validation can require fixes for SDK wire formats, IAM propagation, and workstation tools. A failed run is not proof of guest readiness or successful relocation, even if resource provisioning and teardown succeed. Preserve the final inventory and compare permanent account policies before reporting completion.
