# Umbra Quick Start

Umbra gives you a private cloud development machine, called a Dev CVM, for running code and AI agents without giving those agents open-ended network or secret access. You connect with the tools you already use, while outbound traffic from the CVM goes through your organization's Security CVM for policy enforcement, secret protection, and audit logs.

Use this guide to start your first Dev CVM and work inside it from SSH, VS Code, Cursor, Claude Code, or Codex.

## What You Need

Ask your Umbra admin for:

- The Console URL, for example `https://console.example.com`.
- Confirmation that your user has been added to Umbra.
- Confirmation that you have the `CVM_LAUNCH` permission.
- Confirmation that you have been assigned to one profile, or the profile ID to use.
- Confirmation that the entity Security CVM is already running.

Local prerequisites:

- GNU/Linux on x86-64 or ARM64, or macOS on Apple Silicon. Intel macOS does not currently have a prebuilt release; build the CLI from source there.
- OpenSSH (`ssh` and `ssh-keygen`)
- A browser for Google login, or device-flow access from another browser
- VS Code `code` or Cursor `cursor` on `PATH` if you want editor attach

## Install

The verified prebuilt path below is intentionally inactive until maintainers prove control of `concrete-security/umbra` and publish the first approved release and provenance. Before that launch gate is satisfied, build the CLI from a reviewed source checkout with `cargo build --release -p umbra-cli` and use `target/release/umbra`; the prebuilt flow will fail closed because no eligible release exists.

After the launch gate opens, the prebuilt installer is verified before it runs. You need [Go](https://go.dev/doc/install), Python 3, and `curl` for this initial bootstrap. Install the SLSA verifier from its pinned source module; Go verifies the module through its checksum database. Release discovery and downloads use GitHub's anonymous public API and require no GitHub account or token:

```bash
sh -eu <<'UMBRA_BOOTSTRAP'
verifier_bin_dir="$HOME/.local/bin"
mkdir -p "$verifier_bin_dir"
env \
  GOPRIVATE= GONOSUMDB= GONOPROXY= \
  GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
  GOBIN="$verifier_bin_dir" \
  go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.1
slsa_verifier="$verifier_bin_dir/slsa-verifier"
export PATH="$verifier_bin_dir:$PATH"
export UMBRA_SLSA_VERIFIER="$slsa_verifier"

installer_dir="$(mktemp -d)"
trap 'rm -rf "$installer_dir"' EXIT
release_json="$installer_dir/releases.json"
asset_urls="$installer_dir/asset-urls"
curl --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' \
  'https://api.github.com/repos/concrete-security/umbra/releases?per_page=100' \
  --output "$release_json"
python3 - "$release_json" > "$asset_urls" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    releases = json.load(source)

semver_re = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)

def semver_key(version):
    match = semver_re.fullmatch(version)
    if not match:
        return None
    prerelease = match.group(4)
    identifiers = []
    if prerelease is not None:
        for identifier in prerelease.split("."):
            if identifier.isdigit():
                if len(identifier) > 1 and identifier.startswith("0"):
                    return None
                identifiers.append((0, int(identifier)))
            else:
                identifiers.append((1, identifier))
    return (
        tuple(map(int, match.groups()[:3])),
        1 if prerelease is None else 0,
        tuple(identifiers),
    )

candidates = []
for release in releases:
    tag = release.get("tag_name", "")
    if release.get("draft") or not tag.startswith("umbra-cli/"):
        continue
    version = tag.split("/", 1)[1]
    key = semver_key(version)
    if key is None:
        continue
    assets = {asset["name"]: asset["browser_download_url"] for asset in release["assets"]}
    required_assets = {"umbra-install.sh", "SHA256SUMS", "umbra-cli.intoto.jsonl"}
    if required_assets <= assets.keys():
        candidates.append((key, version, assets))
if not candidates:
    raise SystemExit("no published Umbra CLI release has verified installer assets")
_, version, assets = max(candidates, key=lambda candidate: (candidate[0], candidate[1]))
print(version)
print(assets["umbra-install.sh"])
print(assets["SHA256SUMS"])
print(assets["umbra-cli.intoto.jsonl"])
PY
release_version="$(sed -n '1p' "$asset_urls")"
installer_url="$(sed -n '2p' "$asset_urls")"
checksums_url="$(sed -n '3p' "$asset_urls")"
provenance_url="$(sed -n '4p' "$asset_urls")"
curl --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' \
  "$installer_url" --output "$installer_dir/umbra-install.sh"
curl --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' \
  "$checksums_url" --output "$installer_dir/SHA256SUMS"
curl --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' \
  "$provenance_url" --output "$installer_dir/umbra-cli.intoto.jsonl"

"$slsa_verifier" verify-artifact "$installer_dir/umbra-install.sh" \
  --provenance-path "$installer_dir/umbra-cli.intoto.jsonl" \
  --source-uri github.com/concrete-security/umbra \
  --source-branch main \
  --build-workflow-input dry_run=false \
  --builder-id 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0'
"$slsa_verifier" verify-artifact "$installer_dir/SHA256SUMS" \
  --provenance-path "$installer_dir/umbra-cli.intoto.jsonl" \
  --source-uri github.com/concrete-security/umbra \
  --source-branch main \
  --build-workflow-input dry_run=false \
  --builder-id 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0'
python3 - "$installer_dir/SHA256SUMS" "$installer_dir/umbra-install.sh" "$release_version" <<'PY'
import hashlib
import re
import sys

manifest_path, installer_path, version = sys.argv[1:]
entries = {}
with open(manifest_path, encoding="utf-8") as manifest:
    for line in manifest:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\n]+)\n?", line)
        if not match or match.group(2) in entries:
            raise SystemExit("release SHA256SUMS is malformed or contains duplicate paths")
        entries[match.group(2)] = match.group(1)
with open(installer_path, "rb") as installer:
    installer_digest = hashlib.sha256(installer.read()).hexdigest()
if entries.get("umbra-install.sh") != installer_digest:
    raise SystemExit("verified installer does not match the selected release manifest")
required_targets = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin",
)
missing = [
    f"{version}/{target}/umbra"
    for target in required_targets
    if f"{version}/{target}/umbra" not in entries
]
if missing:
    raise SystemExit("selected release manifest is not bound to every CLI target")
PY
UMBRA_INSTALL_VERSION="$release_version" \
UMBRA_INSTALL_SLSA_VERIFIER="$slsa_verifier" \
  sh "$installer_dir/umbra-install.sh"
umbra --version
UMBRA_BOOTSTRAP
```

Once an approved release exists, this flow selects the highest canonical SemVer non-draft GitHub release (including eligible prereleases and excluding build metadata) and passes that exact version to the verified installer. Both the installer and the release checksum manifest are authenticated by SLSA; the manifest must bind that installer and all target binaries to the selected version. The installer then downloads the matching immutable CLI binary from the mirror, verifies the same provenance, checks the binary-reported version, and only then installs it. This rejects both a replayed mirror `latest` value and older signed assets substituted under the selected GitHub release. Do not pipe the install mirror directly to a shell: authenticating the script itself is what prevents a compromised mirror from removing these checks. For a self-hosted release, substitute the operator's repository and use the source identity they publish.

After the scoped bootstrap succeeds, make the installed commands available in your current shell:

```bash
export PATH="$HOME/.local/bin:$PATH"
export UMBRA_SLSA_VERIFIER="$HOME/.local/bin/slsa-verifier"
```

Keep that directory on `PATH` in future shells, or persist `UMBRA_SLSA_VERIFIER=$HOME/.local/bin/slsa-verifier`, because `umbra update` applies the same fixed repository, branch, workflow-input, and builder policy before replacing the running binary. SLSA authenticates the artifact but not the mirror's version-pointer freshness: normal updates refuse to downgrade below the installed version, but a mirror can suppress a newer release or replay an intermediate valid release.

## Log In

Pass the Console URL the first time. Umbra saves it in `~/.umbra/config.toml`.

```bash
umbra auth login https://console.example.com
```

If you are on a remote machine or cannot open a local browser:

```bash
umbra auth login https://console.example.com --device
```

Check that the session and saved Console URL look right:

```bash
umbra auth status
umbra config show
```

## Start A Dev CVM

```bash
umbra cvm launch
```

In the common case, that is all you need:

- If your admin assigned you to one profile, Umbra uses it automatically.
- If a registered SSH key has a remembered or discoverable local private key on this machine, Umbra installs your registered keys and remembers the matching local identity.
- If no registered key matches this machine, Umbra creates a local Ed25519 key, registers the public key, and installs it.
- When launch succeeds, Umbra saves the new CVM and SSH identity as your defaults.

If you are assigned to multiple profiles, choose one:

```bash
umbra profile list
umbra --profile <profile-id> cvm launch
```

Check state:

```bash
umbra cvm list
umbra status
```

## Set Up Personal Credentials (If Your Profile Uses Them)

Some profiles inject a **personal** credential (for example your own Slack or GitHub token) into matching outbound requests, so the token never enters the sandbox and every member's CVM uses their own identity. Such a profile references a named *user secret*, and launch fails with a message like this until you have stored yours:

```
[VALIDATION_ERROR] profiles reference user secrets that are missing or not host-authorized
(user secrets: slack-user-token; run `umbra secret set <NAME> --host <HOST>` as the CVM owner)
```

Store the secret once, bound to the hosts it may be sent to (the value is read from stdin or `--value-file`, never from the command line):

```bash
printf '%s' "$MY_SLACK_TOKEN" | umbra secret set slack-user-token --host slack.com --host "*.slack.com"
umbra secret list
```

Then launch again. Details worth knowing:

- `--host` is your consent boundary: Umbra refuses to inject this secret toward any destination outside it, even if a profile is later edited. A `*.slack.com` wildcard does **not** cover the `slack.com` apex — list both. Use `--host '*'` to opt out of binding.
- Values are write-only: `umbra secret list` shows names, host bindings, and timestamps — never values. Nobody (including admins) can read them back; to change one, run `secret set` again.
- `umbra secret remove <NAME>` removes it; running CVMs lose that injection within seconds and requests to the matching host start failing at the destination (401) until you store a new value.
- Which secret names a profile needs is visible in the profile's policy (`umbra profile show`): entries with `"value_from": {"user_secret": "<name>"}`.

## Start Working

SSH shell:

```bash
umbra ssh
```

Run one command inside the CVM:

```bash
umbra ssh --command 'mkdir -p ~/workspaces && cd ~/workspaces && git clone https://github.com/<org>/<repo>.git'
```

> Clone over **HTTPS**, not SSH. The sandbox's egress runs through an HTTP CONNECT proxy, so `git@github.com:...` (SSH-over-port-22) remotes are unreachable — use the `https://github.com/...` URL instead.

VS Code:

```bash
umbra code
```

Cursor:

```bash
umbra cursor
```

Claude Code:

```bash
umbra claude --name claude-main --workspace ~/workspaces/myrepo
```

Codex:

```bash
umbra codex --name codex-main --workspace ~/workspaces/myrepo
```

Agent and shell sessions survive disconnects. Press `Ctrl-\` to detach cleanly, or close the terminal:

```bash
umbra ps
umbra attach claude-main
umbra attach codex-main
```

## Daily Commands

```bash
umbra auth status
umbra cvm list
umbra ssh
umbra code
umbra cursor
umbra claude --name claude-main
umbra codex --name codex-main
```

To stop, start, or terminate a CVM, copy its ID from `umbra cvm list`:

```bash
umbra cvm list
CVM_ID="<cvm-id>"
umbra cvm stop "$CVM_ID"
umbra cvm start "$CVM_ID"
umbra cvm terminate "$CVM_ID"
```

## Notes

- The default launch path ensures the CVM has a key with a local private key the CLI can use. It creates an unencrypted local SSH key if no registered key matches this machine, so VS Code and Cursor do not need `ssh-agent`. It will not overwrite or delete an existing SSH key file.
- When registering an existing key manually, `umbra key add --file ~/.ssh/<key>.pub` remembers `~/.ssh/<key>` when it exists and matches. Use `--identity-file <path>` if the private key lives somewhere else.
- If launch uses an existing passphrase-protected key, `umbra ssh` resolves that key automatically and prompts for the passphrase once in an interactive terminal. For editor attach (`umbra code` / `umbra cursor`), unlock the key with `ssh-add` first.
- Work that must stay inside Umbra-controlled egress should run in the CVM through `umbra ssh`, `umbra claude`, or `umbra codex`.
- `umbra code` and `umbra cursor` connect the editor over the attested SSH path. Editor-hosted web tools or local integrations may still make network requests from your workstation or the editor provider, outside the Security CVM path.
- Do not paste real secrets into the sandbox. Umbra injects credentials at the proxy: shared service credentials are stored on the profile by an admin, and personal credentials are stored per user with `umbra secret set` (see "Set Up Personal Credentials" above).
- SSH keys are fixed at Dev CVM launch in v0. To rotate keys, launch a replacement Dev CVM with the new key.
