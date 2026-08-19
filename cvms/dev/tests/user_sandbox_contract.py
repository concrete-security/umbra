from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[3]
SANDBOX = ROOT / "cvms" / "dev" / "user-sandbox"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    dockerfile = (SANDBOX / "Dockerfile").read_text()
    compose = (ROOT / "cvms" / "dev" / "docker-compose.yml").read_text()
    entrypoint = (SANDBOX / "entrypoint.sh").read_text()
    claude_wrapper = (SANDBOX / "umbra-agent-claude.sh").read_text()
    codex_wrapper = (SANDBOX / "umbra-agent-codex.sh").read_text()
    update_agents = (SANDBOX / "umbra-update-agents.sh").read_text()
    profile = (SANDBOX / "umbra-env-profile.sh").read_text()
    forwarder = (SANDBOX / "umbra-dev-egress-forwarder.py").read_text()
    ca_refresh = (SANDBOX / "umbra-ca-refresh.py").read_text()
    sshd_config = (SANDBOX / "sshd_config").read_text().splitlines()

    require("groupadd --gid 1001 dev" in dockerfile, "dev group must use GID 1001")
    require(
        re.search(r"useradd\s+.*--uid 1001\s+.*--gid 1001", dockerfile, re.DOTALL) is not None,
        "dev user must use UID/GID 1001",
    )
    require("useradd -u 0" not in dockerfile, "dev must not be created as UID 0")
    require("passwd -d dev" not in dockerfile, "dev must not receive an empty password")
    require(
        "usermod --password '*' dev" in dockerfile,
        "dev account must be usable for SSH public-key auth without an empty password",
    )
    require(
        "usermod -aG sudo,docker dev" in dockerfile,
        "dev must be in sudo and docker groups",
    )
    require(
        "dev ALL=(ALL) NOPASSWD:ALL" in dockerfile,
        "dev must have passwordless sudo",
    )
    require(
        "env_keep += \"HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy" in dockerfile,
        "sudo must preserve proxy env for root-run tools",
    )
    require("visudo -cf /etc/sudoers.d/dev" in dockerfile, "sudoers drop-in must be validated")
    require(
        "apt-umbra-proxy.conf /etc/apt/apt.conf.d/95umbra-proxy" in dockerfile,
        "APT must be configured to use the Umbra forwarder",
    )
    apt_proxy = (SANDBOX / "apt-umbra-proxy.conf").read_text()
    require(
        'Acquire::http::Proxy "http://dev-egress-forwarder:3128";' in apt_proxy,
        "APT HTTP traffic must use the Umbra forwarder",
    )
    require(
        'Acquire::https::Proxy "http://dev-egress-forwarder:3128";' in apt_proxy,
        "APT HTTPS traffic must use the Umbra forwarder",
    )
    require(
        'Acquire::https::CaInfo "/run/umbra/ca-bundle.pem";' in apt_proxy,
        "APT HTTPS must trust the runtime Security CVM CA bundle",
    )
    require("dev:100000:65536" in dockerfile, "dev subuid/subgid range must be configured")
    require("claude.real" in dockerfile, "claude must be baked into the image")
    require("claude.version" in dockerfile, "claude version metadata must be baked into the image")
    require("@openai/codex" in dockerfile, "codex must be baked into the image")
    require(
        "cargo build --locked --release -p umbra-atls-connect" in dockerfile
        and "release/umbra-atls-connect /usr/local/bin/umbra-atls-connect" in dockerfile,
        "Umbra aTLS helper must be built and installed under its current binary identity",
    )
    require(
        '"/usr/local/bin/umbra-atls-connect"' in forwarder,
        "forwarder must default to the Umbra aTLS helper",
    )
    require("umbra-agent-claude.sh" in dockerfile, "claude wrapper must be installed")
    require(
        "printf '{}\\n' >/home/dev/.claude/.claude.json" in claude_wrapper,
        "claude wrapper must repair empty volume-backed config",
    )
    require("umbra-agent-codex.sh" in dockerfile, "codex wrapper must be installed")
    require(
        codex_wrapper.count("--dangerously-bypass-approvals-and-sandbox") == 2,
        "both updated and baked Codex launch paths must bypass Codex's inner sandbox",
    )
    require("nodejs.org/dist" in dockerfile, "node must be installed from official tarball")
    require("gh auth git-credential" in dockerfile, "gh git credential helper must be configured")
    require(
        re.search(r"^USER\s+", dockerfile, re.MULTILINE) is None,
        "entrypoint must keep running as root",
    )

    sshd = {
        line.split()[0]: " ".join(line.split()[1:])
        for line in sshd_config
        if line.strip() and not line.lstrip().startswith("#")
    }
    require(sshd.get("PasswordAuthentication") == "no", "password SSH auth must stay disabled")
    require(sshd.get("PermitRootLogin") == "no", "root SSH login must be disabled")
    require(sshd.get("AllowUsers") == "dev", "SSH login must be limited to dev")
    require(
        sshd.get("AuthorizedKeysFile") == "/run/ssh/authorized_keys/dev",
        "authorized_keys path must stay runtime material",
    )

    require("entrypoint must run as root" in entrypoint, "entrypoint must assert root startup")
    require("ensure_runtime_dev_dir 0700 /run/ssh/user-ssh" in entrypoint, "SSH user dir must be dev-owned")
    require(
        "ensure_runtime_dev_dir 0700 /run/umbra/sessions" in entrypoint,
        "session directory must be dev-owned",
    )
    require(
        "ensure_dev_dir_if_missing 0755 /home/dev/workspaces" in entrypoint,
        "workspace volume must not be recursively migrated",
    )
    require(
        "ensure_claude_config /home/dev/.claude/.claude.json" in entrypoint,
        "Claude config must be initialized as valid JSON",
    )
    require(
        "ensure_claude_native_install" in entrypoint
        and "/home/dev/.local/bin/claude" in entrypoint
        and "/home/dev/.local/share/claude/versions" in entrypoint,
        "entrypoint must seed Claude's native install path inside the persistent .local volume",
    )
    require(
        "/home/dev/.local/bin/claude update" in update_agents,
        "Claude updater must use the native install path when present",
    )
    require(
        '"$(id -u)" = "1001"' in profile and "umbra-update-agents.sh" in profile,
        "dev login profile must start the non-blocking agent updater",
    )
    require(
        "/run/umbra/env.sh" in profile
        and "export BASH_ENV='/run/umbra/env.sh'" in entrypoint
        and "write_runtime_env /run/umbra/sandbox-env-placeholders /run/umbra/env.sh"
        in entrypoint,
        "the generated shell environment must stay under the canonical Umbra runtime directory",
    )
    require(
        "required_env SECURITY_CVM_FQDN" in entrypoint
        and "umbra-ca-refresh --bootstrap /run/umbra/security-cvm-ca.launch.pem" in entrypoint
        and entrypoint.index("umbra-ca-refresh --bootstrap") < entrypoint.index("umbra-ca-refresh >/var/log"),
        "sandbox restart must validate and install bound persisted CA state before starting the watcher",
    )
    require(
        "security-cvm-ca.json" in forwarder
        and "security-cvm-ca.json" in ca_refresh
        and "ca_cert_sha256" in ca_refresh
        and "launch_ca_cert_sha256" in ca_refresh
        and "security_cvm_fqdn" in ca_refresh,
        "persisted CA trust must bind FQDN, current digest, and immutable launch baseline",
    )
    require(
        "/home/dev/.ssh exists and is not a symlink" in entrypoint,
        "entrypoint must fail instead of rewriting a persisted .ssh directory",
    )
    require("chown -R" not in entrypoint, "entrypoint must not recursively chown volumes")
    require(
        re.search(r'dev-egress-forwarder:.*?healthcheck:\s+test:\s+\["NONE"\]', compose, re.DOTALL) is not None,
        "forwarder must disable the inherited sshd image healthcheck",
    )
    user_sandbox = compose.split("  dev-egress-forwarder:", 1)[0]
    require(
        "SECURITY_CVM_FQDN: ${SECURITY_CVM_FQDN}" in user_sandbox,
        "sandbox CA bootstrap must receive the launch-bound Security CVM FQDN",
    )
    require(
        re.search(r'dev-tunnel:.*?healthcheck:\s+test:\s+\["NONE"\]', compose, re.DOTALL) is not None,
        "tunnel must disable the inherited sshd image healthcheck",
    )


if __name__ == "__main__":
    main()
