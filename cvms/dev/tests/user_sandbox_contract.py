from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[3]
SANDBOX = ROOT / "cvms" / "dev" / "user-sandbox"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    dockerfile = (SANDBOX / "Dockerfile").read_text()
    entrypoint = (SANDBOX / "entrypoint.sh").read_text()
    sshd_config = (SANDBOX / "sshd_config").read_text().splitlines()

    require("groupadd --gid 1001 dev" in dockerfile, "dev group must use GID 1001")
    require(
        re.search(r"useradd\s+.*--uid 1001\s+.*--gid 1001", dockerfile, re.DOTALL) is not None,
        "dev user must use UID/GID 1001",
    )
    require("useradd -u 0" not in dockerfile, "dev must not be created as UID 0")
    require("passwd -d dev" not in dockerfile, "dev must not receive an empty password")
    require(
        "usermod -aG sudo,docker dev" in dockerfile,
        "dev must be in sudo and docker groups",
    )
    require(
        "dev ALL=(ALL) NOPASSWD:ALL" in dockerfile,
        "dev must have passwordless sudo",
    )
    require("visudo -cf /etc/sudoers.d/dev" in dockerfile, "sudoers drop-in must be validated")
    require("dev:100000:65536" in dockerfile, "dev subuid/subgid range must be configured")
    require("claude.real" in dockerfile, "claude must be baked into the image")
    require("@openai/codex" in dockerfile, "codex must be baked into the image")
    require("concrete-agent-claude.sh" in dockerfile, "claude wrapper must be installed")
    require("concrete-agent-codex.sh" in dockerfile, "codex wrapper must be installed")
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
        "ensure_runtime_dev_dir 0700 /run/concrete/sessions" in entrypoint,
        "session directory must be dev-owned",
    )
    require(
        "ensure_dev_dir_if_missing 0755 /home/dev/workspaces" in entrypoint,
        "workspace volume must not be recursively migrated",
    )
    require(
        "/home/dev/.ssh exists and is not a symlink" in entrypoint,
        "entrypoint must fail instead of rewriting a persisted .ssh directory",
    )
    require("chown -R" not in entrypoint, "entrypoint must not recursively chown volumes")


if __name__ == "__main__":
    main()
