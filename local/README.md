# Local macOS execution through Umbra

The user-facing CLI is **`umbra`**, not `umbra-local`. The local Python package and
Swift VM helper are private runtime components. This remains a **local preview**:
Console authorizes each local workspace and the host connects directly to the
attested Security CVM. No remote Dev CVM is used. Managed installation and host
tamper protection are outside this source preview.

## Daily workflow

```bash
cd ~/projects/my-project
umbra start local --preview       # first local-preview launch only
umbra claude                     # project files are already inside the VM
umbra codex
umbra ssh

cd src
umbra ssh                        # same VM, /home/dev/workspaces/project/src
umbra code                       # or umbra cursor; opens that guest directory
umbra status                     # local state and assurance for this folder
umbra stop local                 # retains files, VM disk and folder binding
umbra start local                # resumes the same workspace; no repeated setup
```

Select assigned policies with the normal global `--profile UUID-or-alias` flags,
or configured default profiles. The profiles, bundle, CPU and memory settings
are remembered per project. `--bundle DIRECTORY`, `--cpus N` and `--memory MIB`
are advanced setup options. Console and Security CVM must run this revision
before direct local admission works; an older server fails closed.

## Folder selection

`start local` binds the canonical current directory to a private local workspace.
No name, CVM UUID or tracked project configuration is required. `--path DIRECTORY`
starts or stops a project without changing directory. A start within an already
bound project's subdirectory resumes that project rather than making a new VM.

Bindings live in `~/.umbra/local-projects.json`, outside the imported checkout.
Subsequent `ssh`, `claude`, `codex`, `code`, `cursor` and `status` resolve the nearest
registered ancestor. The relative current directory is preserved in the guest.
Local `--workspace` overrides must stay within the imported guest project.

An explicit positional remote target or `--cvm ID-or-alias` always selects that
cloud workspace:

```bash
umbra ssh --cvm my-cloud-box
```

Unbound folders retain existing cloud selection. A stopped local VM, missing
runtime, corrupt registry or failed import is **not** permission to select the
cloud default. The CLI errors with a next step. `claude connect` and `codex connect`
remain the existing cloud/Console credential workflows; they are not rerouted.
Moving a project folder does not migrate its previous binding automatically.

## What is copied

Initial startup copies the **whole selected folder**: tracked files, untracked
files, hidden files, `.git` and executable bits. It does not run Git, project hooks,
build scripts or local configuration files. `.gitignore` is not an import filter.
A project-local `.env` is included, so keep credentials that must never reach the
VM outside the selected folder. No credentials elsewhere in the Mac's home are
imported. The home directory, filesystem root and folders overlapping Umbra's
private state are rejected as import roots.

Each later session copies changed host files using a content-hash merge base.
Unchanged host files do not overwrite agent edits; guest-only files are retained.
Concurrent conflicting host/guest changes block that import. Sessions still open
the existing guest tree, with a warning, so conflicts can be resolved. The last
successful manifest is retained until a complete transfer succeeds. A change set
is checked for conflicts before writes but is not a filesystem-wide transaction;
an interrupted multi-file update may require retry.

Only regular files, directories and relative in-project symlinks are supported.
External/absolute symlinks, sockets, devices, FIFOs, control-character filenames
and unreadable directories fail explicitly rather than disappearing silently.
The preview caps manifests at 100,000 entries and 16 MiB per transfer envelope.
It hashes the tree before sessions and sends only changed file contents; very
large source trees will need further caching work.

**This is not a writable host mount or automatic write-back.** Agent edits stay
in the persistent VM and are visible through `umbra code`/`cursor`. Inspect or
export a patch explicitly, then review it before applying on the Mac:

```bash
umbra ssh --command 'git diff' > changes.patch
```

That command exports Git-tracked changes only; it is not a general all-file export.
A conflict-aware, reviewed host write-back UI is not included in this revision.

## Source-preview setup

From this branch's repository root on an Apple-silicon Mac:

```bash
# Build the main CLI from the revised source; do not use an older installed CLI.
cargo build --locked --release --bin umbra
export PATH="$PWD/target/release:$PATH"

# One-time private helper installation. It installs no umbra-local command.
./local/install-runtime.sh
./local/build-preview.sh "$HOME/.umbra/local-preview-bundle"

# Existing onboarding; skip login if already authenticated.
umbra auth login https://console.example.com

cd ~/projects/my-project
umbra --profile <PROFILE-ID-or-alias> start local --preview \
  --bundle "$HOME/.umbra/local-preview-bundle"
```

Requirements: Apple silicon, macOS 14+, Python 3.12+, OpenSSH, Xcode command-line
tools with Swift 6+, a built Umbra CLI, and Console access, an assigned profile and a running Security CVM. Docker/Buildx is
needed to build the guest bundle, not to run it. The internal runtime uses
Virtualization.framework directly, not the macOS 26-only Containerization APIs.
The installer respects `UMBRA_CONFIG_DIR` or `--config DIRECTORY`. It is a source
preview installer, not a signed managed distribution or an automatic downloader.

The VM bundle builder requires a new directory and makes a 12 GiB disk, ARM64
kernel/initrd and ad-hoc signed native helper with a drift-check manifest. Those
hashes and signatures do not establish release provenance or hostile-host safety.
The native boot and file workflow can be checked on an Apple-silicon Mac with
the opt-in smoke test below; live attestation and policy enforcement need a separately deployed integration test.

The guest includes a shell, Git, curl, Python, Node/npm, build tools, dtach and
Docker. Codex is installed from the existing reviewed, integrity-pinned package
lockfile. Claude can be installed through an assigned policy. Configure agent
credentials as non-secret placeholders for SC injection; do not copy the Mac's
provider token stores. For example, a Console profile that injects the OpenAI
credential can be used with a placeholder Codex login inside the VM:

```bash
umbra ssh --command "printf '%s' umbra-proxy-injected | codex login --with-api-key"
umbra codex
```

`--name NAME` creates or reattaches a dtach session inside the VM.
Local `--identity-file` and `--alias` are rejected; local workspaces use dedicated
keys and directory selection, not the cloud alias store.

## Execution and security boundary

```text
umbra ssh / claude / codex / code, from a project folder
    -> dedicated SSH identity and private Unix sockets
    -> local Linux VM (no NIC, no shared host directories)
    -> loopback HTTP(S) proxy -> fixed vsock port 4050
    -> host broker, with a Console-issued local-workspace bearer
    -> strict aTLS directly to Security CVM
    -> policy, DLP, credential injection, local-workspace traffic logs
```

Console authenticates the user, verifies profile membership, and issues a
five-minute authorization lease. The host renews it every minute; renewal
failure stops the VM. Stop revokes it, with expiry providing the bound when
Console is unavailable. The SC independently checks expiry on requests,
WebSockets and streamed responses. Local traffic has its own `local_workspace_id`.
The bearer never enters the VM. Provider secrets stay at the SC.

Each upstream connection verifies the SC's complete current runtime policy.
There is no local attestation bypass or inherited Dev image-policy exception.
CA rotations update the guest trust bundle; applications caching trust may need
restart. Unsupported protocols and applications ignoring the proxy fail closed.

Python workers use isolated import mode. The installed runtime, Mac kernel and
VM framework are trusted; registration is not remote attestation of the laptop.
Guest serial logs are capped at 1 MiB per run. Native process shutdown is bounded;
forced shutdown can interrupt guest writes.

Editors use a dedicated client profile and guest-loopback SSH forwarding only.
Host SSH-agent, X11, reverse tunnels, host commands and writable host directories
are not forwarded. Editor-hosted/cloud tools and MCP servers on the Mac remain
outside this boundary. Run agents, MCP servers and builds inside the guest.
Nested Docker needs the guest network namespace, explicit proxy variables and a
read-only public CA mount. Arbitrary nested-image networking is not transparent.

## Diagnostics and tests

`umbra status` reports the folder's local state, source root, guest directory and
`local-preview` assurance. `--json` works for start, stop and status. Raw/interactive
session output does not accept `--json` and may have partial stdout before failure.
The Rust CLI maps failed child sessions to its stable error exit status.

Private runtime state and logs remain under `~/.umbra/local/<derived-id>/`.
Stop never removes the guest disk or project binding. Review logs before sharing.

```bash
uv run --locked --project console python -m pytest -c local/pyproject.toml local/tests
cargo test --locked -p umbra-cli
swift test --disable-xctest --package-path local/native
bash -n local/build-preview.sh local/install-runtime.sh
```

Run the hardware smoke test after building the CLI and guest bundle:

```bash
python3 local/smoke-test.py --umbra target/debug/umbra --bundle local/bundle
```

It boots a real VM with synthetic Console/transport workers and temporary state.
It checks SSH, subdirectory selection, hidden/untracked files, executable bits,
symlinks, host updates, conflict preservation, disk persistence across restart,
no guest NIC, host-only proxy identity, Codex startup, bounded serial logging,
and shutdown after failed authorization renewal. It removes its test
state afterward. It does not use cloud credentials or verify live SC policy,
DLP, injection, a model API call or editor integration. See [Mac validation](macos-validation.md)
for the recorded run and toolchain limitations.

Portable tests cover directory resolution, complete imports, symlinks, collisions,
conflict preservation, transfer bounds, shell quoting, stop persistence and
transport failure. They do not establish real Apple VM behavior. Before rollout,
validate native compilation, guest build/boot, actual `umbra` dispatch, agent and
editor sessions, source changes, SC decisions, host packet captures, guest-root
bypass attempts, sleep/wake, network changes and outage/rotation behavior.

Managed device posture, mandatory fleet installation, tamper protection and
release-signed updates remain the
separate production gates in the [contract](../docs/specs/local-sandbox.md).
