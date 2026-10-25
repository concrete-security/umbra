# Sysbox early bootstrap qualification

This is a **qualification candidate**, with no product or deployment wiring.
The native renderer always holds `dstack-prepare` before any mutation. There is
no environment variable or CLI switch to enable it. The hold is a technical gate:
real transaction, complete-compose attestation, data preservation and provider
recovery evidence must pass before a reviewed source change can remove it.

The user-authorized canary work is separate from this runner fixture. CI success
does not qualify a different artifact, guest, app image, compose or disk.

## Source and binary identity

`fixtures/manifest.json` pins public upstream bytes with both Git blob IDs and
SHA-256. It records dstack 0.5.9 and 0.5.12 commits, their common units, and the
older app unit's missing `Requires=dstack-prepare.service` edge. Docker and
containerd base units are traced through the pinned Yocto recipes. The only
installation transform is containerd's `/usr/local/bin` to `/usr/bin`.
These fixtures are source evidence, not a live guest unit inventory.
The manifest must cover the complete fixture inventory. Added, missing, duplicate
and symlinked files are rejected; only checksum-validated bytes reach the renderer.

`render.py` repeats the three reviewed `0.7.1+umbra.1` hashes from
`../sysbox-build/binaries.expected.sha256`; the offline suite requires equality.
The existing Sysbox build/scan workflow remains the artifact qualification gate.
This harness builds only a small test executable. It neither builds nor scans
Sysbox and never promotes a binary by observing its hash at runtime.

The rendered hook is self-contained Bash, intended to be sourced while the native
prepare unit is still activating. Native preparation has already mounted the
encrypted data and runtime directories at that point. It:

1. Requires the native oneshot prepare process, infinite start timeout, exact
   loaded unit/drop-in bytes and no active app or runtime daemons.
2. Stops an already active Docker socket, then cancels and checks only the named
   queued runtime jobs. It never stops a running app or calls Docker.
3. Verifies all three artifacts before installation, including every cache hit.
   The persistent cache is outside `/var/lib/sysbox`. HTTPS URLs reject
   credentials, query strings, fragments, literal IPs (including curl's abbreviated,
   octal and hexadecimal aliases) and shell syntax. Curl
   disables its config file, bounds redirects, size and duration, and accepts
   only HTTPS. URLs are public artifact locations, not signed secret URLs.
4. Atomically replaces only the original `/usr/bin/sysbox-*` paths in the volatile
   overlay. Native flags, daemon timeouts, data roots, notification types and
   restart/lifecycle settings stay in the source-pinned original units.
5. Adds a readiness oneshot requiring and following prepare and both daemons.
   Docker, containerd and app-compose require and follow that gate **and prepare**.
   The extra prepare requirement covers the older weak app unit and prepare
   failures after the init script returns.
6. Reloads units, checks effective edges, enqueues new starts without blocking,
   and verifies that each expected job is queued behind prepare. Reload alone
   is insufficient. A synchronous start would deadlock the current prepare.

The gate has no `RemainAfterExit`, so a later start rechecks it. It does not impose
a new policy that kills existing app containers when a Sysbox daemon dies.
Native Sysbox aggregate `BindsTo` and `PartOf` semantics remain. Real new outer
container starts must fail with the actual manager or filesystem service absent.

Command, pipeline, nounset, TERM and bounded-command failures hold prepare active.
Traps protect both the source caller (systemd MainPID) and the worker subshell.
The source caller's original traps are restored only after worker success.
The native oneshot timeout is checked instead of assuming the manager default.
SIGKILL, host power loss and systemd failure actions cannot be caught by a shell;
provider recovery remains mandatory. No fallback to the old binary is installed.

## What readiness proves

Pinned [manager source](https://github.com/nestybox/sysbox-mgr/blob/2d45af01bcfd8641e6641f76104c6003bf501cd7/mgr.go)
and [filesystem source](https://github.com/nestybox/sysbox-fs/blob/c3d2ebc65102e32e74e383675f03b45556326888/cmd/sysbox-fs/main.go)
send `READY=1` before binding their gRPC sockets. Active notify units are therefore
insufficient. The readiness script requires:

- Both units are notify services with active, running, live MainPIDs.
- `/proc/MainPID/exe` names the installed path and hashes to the reviewed binary.
- Root-only Unix listeners for `/run/sysbox/sysmgr.sock`, `sysfs.sock` and
  `sysfs-seccomp.sock` have unique listening entries and socket descriptors owned
  by the expected MainPID. Socket existence alone cannot pass.

This probes listener ownership without sending application requests. Pinned
[IPC servers](https://github.com/nestybox/sysbox-ipc/tree/f05151f4b4c1df63d7fd241577ca032905c1bd0e)
register reflection but no gRPC health service. Manager RPCs mutate runtime state.
The fs `GetMountpoint` RPC is read-only, but no gRPC client is assumed on the guest.
The [seccomp listener](https://github.com/nestybox/sysbox-fs/blob/c3d2ebc65102e32e74e383675f03b45556326888/seccomp/tracer.go)
expects a real container handshake and file descriptor; it is not a health API.

These checks do **not** prove functional RPCs, FUSE, seccomp, kernel compatibility,
container data preservation or TDX attestation. Fresh real outer containers and
nested Docker `none`/`bridge` starts remain mandatory.

## Runner harness

Run offline checks from the repository root:

```sh
uv run --python "$(cat .python-version)" --no-project \
  python -m unittest discover -s ops/verify/sysbox-bootstrap -p 'test_*.py' -v
```

`.github/workflows/sysbox-bootstrap.yml` runs the transaction suite only on a
disposable GitHub-hosted Ubuntu runner. It uses read-only checkout permissions,
no deployment environment, secrets, registry token or cloud access.

The harness uses real PID 1 systemd, real notifications and real owned listening
sockets. Every explicit dependency is redirected to a unique `umbra-sbq-*` copy.
Executable commands are replaced through test-only drop-ins. Native
environment-file reads, app stop commands, module loading and reboot actions are
removed from those copies. Prerequisites are isolated stubs. No native Docker,
containerd, Sysbox, guest-agent or prepare unit is stopped, started or edited.
Systemd's implicit default dependencies remain present.

Test overrides sort last as `zz-qualification.conf`. After reload and before
each scenario starts, the harness checks PID 1's effective commands, environment
sources and bindings, CPU affinity, drop-in order, guest watchdog and prepare
failure action. A late vendor drop-in restoring a native command fails this gate.
Systemd 255 omits empty command/environment-file arrays from its human display;
read-only typed D-Bus queries must prove each omitted array exists and is empty.
Missing properties or failed queries remain errors. Disabled watchdog values are
accepted as either `0` or systemd's `infinity` display.
The hook likewise distinguishes the present empty `Job=` property (no job)
from absent or malformed query output before cancelling or checking queued jobs.

The suite tests both OS fixture graphs: successful handover, delayed listeners,
command/pipeline/nounset/timeout holds, TERM to the worker, MainPID and whole
prepare cgroup, altered source, altered artifact,
omitted requeue, missing notification, early daemon death, later prepare
failure, wrong executable identity and listeners owned by another PID.
It also checks the original infinite prepare timeout and unchanged
app lifecycle after a manager death. Cleanup names only the generated prefix.

Evidence contains bounded unit state, preparation journal, test events and a
hash of each rendered test hook. Mock results are never labeled as Sysbox, dstack
or hardware attestation success. A runner test against one app image also cannot
qualify a canary running a different image.

## Remaining live gates

Before removing the native technical hold:

1. Review CI evidence against this exact hook and its source fixtures. Verify the
   real guest's unit fragments/drop-ins, Bash/tools, mount ordering and permissions.
   Retain all three artifact hashes, static-ELF checks and clean security scan.
2. Prove provider-only recovery while prepare is deliberately held and guest SSH
   is unavailable. Preserve the same CVM, app, instance seed, encrypted disk and
   KMS key derivation. Retain the **raw complete** known-good compose and current
   encrypted environment binding. A normalized historical revision can differ
   from the accepted compose and cannot be treated as a rollback receipt.
   Prove operation-lock recovery, exact readback and full Atlas verification.
3. Establish a working populated baseline with the unchanged canary app image.
   Back up and verify outer writable-rootfs data, home, named volumes and inner
   Docker state. Exercise graceful cold stop and same-container-ID restart across
   the runtime change and OS-only upgrade. Manager source explicitly removes
   cloned rootfs data on daemon stop; preserve and test the actual clone mode.
4. Bind the complete measured init script into independently reviewed compose
   policy. Preserve current environment tokens and require the real old/new MRTD,
   bootchain, RTMR replay, app identity and full attestation checks. Generic
   application updates and historical rollback may drop the hook or rotate tokens.

The minimum canary sequence is runtime correction on the same old guest,
working populated baseline and tested recovery, then the OS-only migration.
Keep the app image, CVM/app/instance identity, disk and KMS binding constant.
