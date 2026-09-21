# Mac validation — 2026-09-21

The local preview was built and exercised on Apple silicon, macOS 26.6.2.
Changes are isolated on `feat/local-integrated`; existing work in the original
checkout was preserved.

## Results for direct local execution

- `make test`: 432 Rust tests, 84 local Python tests, 741 Console tests and 206
  Security CVM tests passed. Seven Console tests skip without optional live/DB
  configuration; the separate real database gate passed all six tests. A subsequent
  SC connection-cleanup regression test also passed with its 25-test module.
- Real Postgres: migrations, local admission with zero Dev CVMs, hash-only bearer
  storage, SC-scoped policy feed, owner/profile authorization, traffic identity,
  renewal, membership removal and revocation passed in a disposable container.
- Native: four Swift configuration tests and release compilation passed in the
  earlier run; native source is unchanged in the direct-transport correction.
- Guest: ARM64 image with integrity-pinned Codex built successfully.
- Actual Mac VM: boot, Codex `--version`, SSH via the main CLI, subdirectory cwd,
  full project imports, guest virtualenv links, conflict preservation,
  stop/resume persistence, only-loopback networking, authenticated proxy headers,
  blocked requests, capped serial output and shutdown on failed renewal passed.
  The VM and temporary state were removed.
- Clippy with warnings denied, formatting, Python compilation, lock checks,
  workflow pins, generated skills and whitespace checks passed.
- `make check` reached the installer smoke test and stopped because the Mac's
  Bash 3.2 does not support its existing `declare -A`. Later Makefile checks were
  not run by that invocation; no unrelated installer changes were made.

The repeatable hardware smoke uses synthetic Console and attested-transport
workers confined to the test harness. Production code contains no test transport
override. Separate authorized staging checks below exercise live attestation,
policy, DLP and a model request. Desktop agent sessions, CA rotation, sleep/wake,
VPN changes and nested Docker remain unverified.

The checked-in OpenAPI file had unrelated pre-existing drift. Only API nodes
changed by this feature were regenerated, by comparing generated schemas before
and after the change; unrelated existing schema drift is preserved.

## Fixes found by running on macOS

- Canonicalize both sides of the configuration/project overlap check, including
  `/tmp` versus `/private/tmp` and symlinked parent paths.
- Check the longest Unix-socket name (`control.sock`) in both Python and Swift,
  and keep test fixtures below macOS's socket path limit.
- Validate native paths lexically: Foundation rewrites existing `/private/tmp`
  paths to `/tmp`, which disagrees with Python's canonical paths.
- Use a real writable descriptor for the serial console. Foundation's null file
  handle was rejected by Virtualization.framework. Boot output now reaches the
  private service log, with a 1 MiB per-run guest output cap.
- Correct the Dockerfile's conflicting sed delimiter and alternation syntax.
- Build the native helper before downloading/building the guest image, so native
  toolchain failures are reported earlier.
- Format the supplied Rust code, fix its Clippy warning, extend CLI integration
  coverage and include portable local tests in `make test`.

## Toolchain limitation on this Mac

The selected Xcode installation has a pending license agreement. Its separate
Command Line Tools installation also contains stale 2024 private SwiftPM
interfaces alongside Swift 6.3.3 public interfaces. No system files, selected
developer directory or license state were changed.

Validation used `DEVELOPER_DIR=/Library/Developer/CommandLineTools`, a temporary
copy of SwiftPM libraries without stale private interfaces, and explicit Command
Line Tools Testing framework/library search paths. Native tests use Swift
Testing, available with Swift 6, so XCTest is not required.

For ordinary rebuilds, use a working Swift 6+ Xcode/Command Line Tools
installation. The prebuilt local bundle is ad-hoc signed for this Mac; it is not
a release or managed installation. Python, CLI and smoke-test commands remain
as documented in the README.

## Desktop handoff follow-up

`start local --app codex|claude` now registers SSH and opens the selected app after
startup/import and guest readiness. All 91 local tests and the CLI suite passed;
14 CLI integration cases include desktop dispatch. Strict Clippy passed. A new
real-Mac smoke assertion connects through the generated desktop alias and checks
the guest login proxy/CA environment. The full smoke passed with fixture services.
No desktop UI or model session was started by the test.

The hardware check found that the guest service's umask made `/run/umbra` mode
0700, preventing the `dev` agent from reading its public CA bundle. Bootstrap now
sets that public-only directory to 0755; its files stay 0644. The guest image was
rebuilt and the real unprivileged SSH readiness check passed. Existing guest disks
need explicit migration or a newly created workspace; changing a bundle under an
existing workspace remains rejected.

Desktop app selection and authentication still require live verification; opening
an app is not evidence that a remote agent session started. SSH and Claude settings
registration preserves unrelated configuration and retains private backups.

## Live staging follow-up

The Console and Security CVM were deployed to an authorized staging environment.
The existing database was backed up and migrated through normal startup; the
previous checkout was preserved. Production was not changed.

- Strict Mac aTLS connected directly to the Security CVM with the complete
  runtime policy. No Dev CVM was used.
- A fresh guest passed HTTPS 200, denied-destination 403, DLP 403 and failed
  direct-network checks. CONNECT status and inner HTTPS status were asserted
  separately, and TLS certificate validation stayed enabled.
- Codex executed a real model request in the VM and returned the expected short
  response. The guest held only dummy authentication; the SC supplied the managed
  provider credential. Optional connector endpoints stayed policy-blocked.
- Console traffic logs attributed policy, DLP and model traffic to the distinct
  local workspace, with no Dev CVM identity.
- All 99 local Python tests passed. The complete real-Mac smoke passed with the
  version-2 guest, including host-aligned time on boot and resume.

Live testing found two defects. Postgres JSONB reordered authoritative compose
keys, so Console now retains the policy's serialized JSON and returns it without
changing attestation inputs. The real-Postgres regression and all 741 Console
tests passed; normal SC update refreshed the stored policy. Separately, the
NIC-less VM booted with a stale image clock and rejected current certificates.
Bootstrap now sets the guest clock from the trusted Mac and refreshes it at lease
renewal. Bundle version 2 rejects incompatible old guest disks explicitly.

Codex desktop SSH registration and app opening passed on this Mac. An actual
desktop-controlled agent session and Claude subscription/model authentication
remain pending. The successful model test used the CLI inside the same VM.
