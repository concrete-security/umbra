#!/usr/bin/env python3
"""Run real systemd transactions with prefixed units on disposable GitHub runners."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time
import uuid

import render

HERE = Path(__file__).resolve().parent
UNIT_DIR = Path("/run/systemd/system")
DEPENDENCIES = {
    "After", "Before", "Wants", "Requires", "BindsTo", "PartOf", "OnFailure", "WantedBy",
}
FAULTS = {
    "command": "false",
    "pipeline": "false | true",
    "nounset": 'printf "%s" "$UMBRA_MUST_NOT_EXIST"',
    "term": 'kill -TERM "$BASHPID"',
    "timeout": "timeout 0.1 sleep 2",
}
SIGNAL_CASES = {"term-main": "main", "term-group": "all"}
QUALIFICATION_OVERRIDE = "zz-qualification.conf"
EMPTY_SERVICE_PROPERTIES = (
    "ExecCondition", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost",
    "ExecReload", "EnvironmentFiles", "CPUAffinity",
)


def service_override(layout: render.Layout, role: str, command: str, scenario: str) -> bytes:
    """Reset native commands after every retained vendor drop-in."""
    text = (
        "[Service]\nExecStart=\nExecCondition=\nExecStartPre=\nExecStartPost=\nExecStop=\n"
        "ExecStopPost=\nExecReload=\nEnvironmentFile=\n"
        f"ExecStart={command}\nWorkingDirectory={layout.root}\nCPUAffinity=\n"
        f"Environment=SBQ_ROOT={layout.root} SBQ_ROLE={role}\n"
    )
    if role == "guest":
        text += "WatchdogSec=0\n"
    if role == "fs":
        options = {
            "missing-notify": "SBQ_NO_NOTIFY=1",
            "delayed-listener": "SBQ_SOCKET_DELAY_MS=2000",
            "daemon-death": "SBQ_EXIT_BEFORE_SOCKET=1",
            "wrong-listener-owner": "SBQ_OTHER_LISTENER_PID=1",
        }
        if scenario in options:
            text += "Environment=" + options[scenario] + "\n"
    return text.encode()


def validate_effective_service(
    properties: dict[str, str], command: str, role: str, root: str,
) -> None:
    """Reject native execution or environment sources before any fixture starts."""
    starts = re.findall(r"\bpath=([^;]+);\s*argv\[\]=([^;]+);", properties["ExecStart"])
    expected = shlex.split(command)
    if len(starts) != 1 or starts[0][0].strip() != expected[0] or shlex.split(starts[0][1]) != expected:
        raise AssertionError("effective ExecStart is not the exact isolated test command")
    for name in EMPTY_SERVICE_PROPERTIES:
        if properties[name]:
            raise AssertionError(f"effective {name} retained native service settings")
    environment = dict(value.split("=", 1) for value in shlex.split(properties["Environment"]))
    if environment.get("SBQ_ROOT") != root or environment.get("SBQ_ROLE") != role:
        raise AssertionError("effective environment is not bound to this test fixture")
    drops = shlex.split(properties["DropInPaths"])
    if not drops or Path(drops[-1]).name != QUALIFICATION_OVERRIDE:
        raise AssertionError("qualification override is not the final effective drop-in")
    if role == "guest" and properties["WatchdogUSec"] != "0":
        raise AssertionError("mock guest watchdog is not disabled")
    if role == "prepare" and properties["FailureAction"] != "none":
        raise AssertionError("mock prepare retained a native failure action")


def run(*args: str, check: bool = True, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=timeout)


def transform(content: bytes, prefix: str) -> bytes:
    """Retain explicit ordering/requirement edges, directed only at prefixed copies."""
    lines = []
    for line in content.decode().splitlines():
        key, sep, value = line.partition("=")
        if sep and key in DEPENDENCIES:
            line = key + "=" + " ".join(prefix + unit for unit in value.split())
        elif line == "FailureAction=reboot":
            line = "FailureAction=none"
        lines.append(line)
    return ("\n".join(lines) + "\n").encode()


class Case:
    def __init__(self, version: str, scenario: str, executable: Path, evidence: Path):
        self.version, self.scenario, self.evidence = version, scenario, evidence
        prefix = "umbra-sbq-" + uuid.uuid4().hex[:12] + "-"
        self.layout = render.Layout(prefix=prefix, root="/run/" + prefix[:-1])
        self.root = Path(self.layout.root)
        self.paths: set[Path] = set()
        self.units: set[str] = set()
        self.executable = executable
        self.expected_services: dict[str, tuple[str, str]] = {}

    def ctl(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        # Arguments containing unit names must never address a host service.
        for arg in args:
            if re.fullmatch(r"[A-Za-z0-9_.@-]+\.(service|socket|target)", arg):
                if not arg.startswith(self.layout.prefix):
                    raise AssertionError(f"unprefixed control rejected: {arg}")
        return run("systemctl", *args, check=check)

    def prop(self, unit: str, key: str) -> str:
        return self.ctl("show", "--property=" + key, "--value", self.layout.unit(unit)).stdout.strip()

    def write(self, name: str, data: bytes) -> None:
        if not name.startswith(self.layout.prefix):
            raise AssertionError("fixture path escaped its namespace")
        path = UNIT_DIR / name
        if path.exists() or path.is_symlink():
            raise AssertionError("fixture collision")
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)
        self.paths.add(path)
        self.units.add(name.split(".d/")[0])

    def assert_effective_services(self) -> None:
        fields = (*EMPTY_SERVICE_PROPERTIES, "ExecStart", "Environment", "DropInPaths",
                  "WatchdogUSec", "FailureAction")
        for unit, (role, command) in self.expected_services.items():
            output = self.ctl(
                "show", "--all", "--property=" + ",".join(fields), self.layout.unit(unit),
            ).stdout
            properties = dict(line.split("=", 1) for line in output.splitlines())
            if set(properties) != set(fields):
                raise AssertionError("systemd did not return all effective fixture properties")
            validate_effective_service(properties, command, role, self.layout.root)

    def setup(self) -> None:
        self.root.mkdir(mode=0o700)
        for directory in (self.layout.bin_dir, self.layout.cache_dir, self.layout.socket_dir):
            Path(directory).mkdir(parents=True, mode=0o700)
        files = render.fixtures(self.version)
        transformed = {
            self.layout.prefix + name: transform(content, self.layout.prefix)
            for name, content in files.items() if ".service" in name or name.endswith(".socket")
        }
        for name, content in transformed.items():
            self.write(name, content)
        mock = self.root / "mock-runtime"
        shutil.copyfile(self.executable, mock)
        mock.chmod(0o755)
        pins = {}
        for binary in render.BINARIES:
            for directory in (self.layout.bin_dir, self.layout.cache_dir):
                dest = Path(directory) / binary
                shutil.copyfile(mock, dest)
                dest.chmod(0o755)
            pins[binary] = render.digest(mock.read_bytes())
        self.original_inodes = {
            name: (Path(self.layout.bin_dir) / name).stat().st_ino for name in render.BINARIES
        }
        prepare_script = self.root / "prepare.sh"
        prepare_script.write_text(
            "#!/bin/bash\nset -e\n"
            f"source {self.root}/hook.sh\n"
            + ("exit 1\n" if self.scenario == "prepare-failure" else "")
            + f"printf 'prepare-complete\\n' >{self.root}/prepare-complete\n"
        )
        roles = {
            "dstack-prepare.service": ("prepare", f"/bin/bash {prepare_script}"),
            "app-compose.service": ("app", str(mock)),
            "docker.service": ("docker", str(mock)),
            "containerd.service": ("containerd", str(mock)),
            "sysbox.service": ("sysbox", str(mock)),
            "sysbox-mgr.service": ("mgr", f"{self.layout.bin_dir}/sysbox-mgr --data-root "
                                   f"{self.root}/var/lib/sysbox --disable-ovfs-on-idmapped-mount"),
            "sysbox-fs.service": ("fs", f"{self.layout.bin_dir}/sysbox-fs"),
            "dstack-guest-agent.service": ("guest", str(mock)),
        }
        for unit, (role, command) in roles.items():
            if self.scenario == "wrong-executable" and role == "fs":
                command = str(mock)
            override = service_override(self.layout, role, command, self.scenario)
            name = self.layout.unit(unit) + ".d/" + QUALIFICATION_OVERRIDE
            transformed[name] = override
            self.write(name, override)
            self.expected_services[unit] = (role, command)
        socket_override = (
            "[Socket]\nListenStream=\n"
            f"ListenStream={self.root}/docker.sock\nSocketGroup=root\n"
        ).encode()
        name = self.layout.unit("docker.socket") + ".d/" + QUALIFICATION_OVERRIDE
        transformed[name] = socket_override
        self.write(name, socket_override)
        # Synthetic prerequisites preserve every explicit unit edge without starting
        # host networking, chrony, guest agents, or reboot targets.
        referenced = set()
        for content in transformed.values():
            for line in content.decode().splitlines():
                key, sep, value = line.partition("=")
                if sep and key in DEPENDENCIES:
                    referenced.update(value.split())
        for name in sorted(referenced - self.units):
            if name.endswith(".target"):
                body = b"[Unit]\nDescription=Isolated qualification prerequisite\n"
            elif name.endswith(".socket"):
                body = (
                    f"[Socket]\nListenStream={self.root}/guest.sock\nSocketMode=0600\n"
                ).encode()
            else:
                body = b"[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n"
            self.write(name, body)
        urls = {name: f"https://artifacts.example.com/sysbox/{name}" for name in render.BINARIES}
        hook = render.render(self.version, urls, layout=self.layout, source_files=transformed, pins=pins)
        if self.scenario in FAULTS:
            marker = "# Qualification fault injection point. The renderer exposes no fault/bypass flag."
            assert hook.count(marker) == 1
            hook = hook.replace(marker, f"touch {self.root}/fault-reached\n" + FAULTS[self.scenario])
        if self.scenario in SIGNAL_CASES:
            marker = "# Qualification fault injection point. The renderer exposes no fault/bypass flag."
            assert hook.count(marker) == 1
            hook = hook.replace(
                marker, f"touch {self.root}/fault-reached\n"
                f"while [[ ! -f {self.root}/signal-delivered ]]; do sleep 0.1; done"
            )
        if self.scenario == "requeue":
            marker = 'ctl --no-block start "$ready" "${runtime_units[@]}" "$docker_socket"'
            assert hook.count(marker) == 1
            hook = hook.replace(marker, ": # Omit requeue; actual job assertions must hold.")
        (self.root / "hook.sh").write_text(hook)
        if self.scenario == "hash":
            (Path(self.layout.cache_dir) / "sysbox-fs").write_bytes(b"wrong bytes")
        self.ctl("daemon-reload")
        self.assert_effective_services()
        if self.scenario == "source":
            # Deliberately change the disk fixture after the hook captured its hash.
            path = UNIT_DIR / self.layout.unit("sysbox-fs.service")
            path.write_text(path.read_text() + "\n# altered fixture\n")
            self.ctl("daemon-reload")
            self.assert_effective_services()
        if self.prop("dstack-prepare.service", "TimeoutStartUSec") != "infinity":
            raise AssertionError("native oneshot default timeout is not infinite")

    def wait_for(self, predicate, timeout: float = 20) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        raise AssertionError("bounded systemd observation timed out")

    def events(self) -> str:
        path = self.root / "events.txt"
        return path.read_text() if path.exists() else ""

    def exercise(self) -> dict:
        self.assert_effective_services()
        # Exercise the real socket-start-before-prepare condition.
        self.ctl("start", self.layout.unit("docker.socket"))
        if self.prop("docker.socket", "ActiveState") != "active":
            raise AssertionError("fixture Docker socket did not start")
        self.ctl("--no-block", "start", *(self.layout.unit(u) for u in (
            "dstack-prepare.service", "app-compose.service", "docker.service",
            "containerd.service", "sysbox.service",
        )))
        if self.scenario in SIGNAL_CASES:
            self.wait_for(lambda: (self.root / "fault-reached").is_file())
            main_pid = self.prop("dstack-prepare.service", "MainPID")
            self.ctl("kill", "--kill-whom=" + SIGNAL_CASES[self.scenario], "--signal=TERM",
                     self.layout.unit("dstack-prepare.service"))
            (self.root / "signal-delivered").touch()
        held = self.scenario in {*FAULTS, *SIGNAL_CASES, "hash", "source", "requeue"}
        if held:
            self.wait_for(lambda: "Sysbox bootstrap held:" in self.journal())
            time.sleep(0.2)
            assert self.prop("dstack-prepare.service", "ActiveState") == "activating"
            assert " app start " not in self.events()
            assert " docker start " not in self.events()
            assert not (self.root / "prepare-complete").exists()
            if self.scenario in SIGNAL_CASES:
                assert self.prop("dstack-prepare.service", "MainPID") == main_pid
                os.kill(int(main_pid), 0)
            if self.scenario in FAULTS:
                assert (self.root / "fault-reached").is_file()
            if self.scenario == "hash":
                assert self.original_inodes == {
                    name: (Path(self.layout.bin_dir) / name).stat().st_ino for name in render.BINARIES
                }
            if self.scenario == "requeue":
                assert (Path(self.layout.runtime_dir) / "ready.sh").is_file()
        elif self.scenario in {"missing-notify", "daemon-death", "prepare-failure"}:
            failed_unit = "dstack-prepare.service" if self.scenario == "prepare-failure" else "sysbox-fs.service"
            self.wait_for(lambda: self.prop(failed_unit, "ActiveState") == "failed")
            time.sleep(0.2)
            expected = "timeout" if self.scenario == "missing-notify" else "exit-code"
            assert self.prop(failed_unit, "Result") == expected
            assert " app start " not in self.events()
            assert " docker start " not in self.events()
        elif self.scenario in {"wrong-executable", "wrong-listener-owner"}:
            self.wait_for(
                lambda: self.prop("umbra-sysbox-ready.service", "ActiveState") == "failed",
                timeout=40,
            )
            assert self.prop("umbra-sysbox-ready.service", "Result") == "exit-code"
            assert self.prop("sysbox-fs.service", "ActiveState") == "active"
            assert " app start " not in self.events()
            assert " docker start " not in self.events()
        else:
            self.wait_for(lambda: self.prop("app-compose.service", "ActiveState") == "active")
            assert (self.root / "prepare-complete").exists()
            events = self.events()
            assert events.index(" fs listeners ") < events.index(" app start ")
            assert events.index(" mgr listeners ") < events.index(" app start ")
            # The gate is repeatable: it does not retain a stale active success.
            assert self.prop("umbra-sysbox-ready.service", "ActiveState") == "inactive"
            self.ctl("start", self.layout.unit("umbra-sysbox-ready.service"))
            # Preserve upstream lifecycle: this is a start gate, not a new policy
            # to destroy existing app workloads whenever a runtime daemon dies.
            self.ctl("kill", "--signal=KILL", self.layout.unit("sysbox-mgr.service"))
            self.wait_for(lambda: self.prop("sysbox.service", "ActiveState") == "inactive")
            assert self.prop("app-compose.service", "ActiveState") == "active"
        return {
            "os_fixture": self.version, "scenario": self.scenario, "result": "passed",
            "prepare_state": self.prop("dstack-prepare.service", "ActiveState"),
            "app_state": self.prop("app-compose.service", "ActiveState"),
            "scope": "real prefixed systemd transactions; mocked runtime, no dstack or RPC qualification",
        }

    def journal(self) -> str:
        return run("journalctl", "--no-pager", "-n", "80", "-u",
                   self.layout.unit("dstack-prepare.service"), check=False).stdout

    def retain(self) -> None:
        self.evidence.mkdir(parents=True, exist_ok=True)
        (self.evidence / "prepare.log").write_text(self.journal())
        (self.evidence / "events.txt").write_text(self.events())
        state = {}
        for unit in sorted(self.units | {self.layout.unit("umbra-sysbox-ready.service")}):
            state[unit.removeprefix(self.layout.prefix)] = self.ctl(
                "show", "--property=ActiveState,SubState,Result,Job,Requires,After,Type,MainPID,"
                "ExecStart,ExecCondition,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,ExecReload,"
                "EnvironmentFiles,DropInPaths,FragmentPath,CPUAffinity,WatchdogUSec,FailureAction,"
                "NotifyAccess,TimeoutStartUSec,KillMode,Restart,BindsTo,PartOf,DefaultDependencies",
                unit, check=False,
            ).stdout
        (self.evidence / "unit-state.json").write_text(json.dumps(state, indent=2) + "\n")
        hook = self.root / "hook.sh"
        if hook.exists():
            (self.evidence / "hook.sh").write_bytes(hook.read_bytes())
            (self.evidence / "hook.sha256").write_text(render.digest(hook.read_bytes()) + "\n")

    def cleanup(self) -> None:
        # Nothing unprefixed is stopped, killed, reset or removed.
        units = self.units | {self.layout.unit("umbra-sysbox-ready.service")}
        for unit in sorted(units):
            self.ctl("kill", "--kill-whom=all", "--signal=KILL", unit, check=False)
        self.ctl("--no-block", "stop", *sorted(units), check=False)
        for unit in sorted(units):
            self.ctl("reset-failed", unit, check=False)
        for path in UNIT_DIR.glob(self.layout.prefix + "*"):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        self.ctl("daemon-reload")
        if self.root.exists():
            shutil.rmtree(self.root)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (
        os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or not Path("/run/systemd/system").is_dir()
    ):
        raise SystemExit("requires a disposable GitHub-hosted systemd runner")
    args.output.mkdir(parents=True, exist_ok=False)
    executable = args.output / "mock-runtime"
    run("cc", "-O2", "-Wall", "-Wextra", "-Werror", str(HERE / "mock-runtime.c"), "-o", str(executable))
    (args.output / "systemd-version.txt").write_text(run("systemctl", "--version").stdout)
    results = []
    scenarios = ("success", "delayed-listener", *FAULTS, *SIGNAL_CASES, "hash", "source", "requeue",
                 "missing-notify", "daemon-death", "prepare-failure",
                 "wrong-executable", "wrong-listener-owner")
    for version in ("0.5.9", "0.5.12"):
        for scenario in scenarios:
            case = Case(version, scenario, executable, args.output / f"{version}-{scenario}")
            try:
                case.setup()
                result = case.exercise()
                results.append(result)
                print(json.dumps(result), flush=True)
            finally:
                try:
                    if case.root.exists():
                        case.retain()
                finally:
                    case.cleanup()
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
