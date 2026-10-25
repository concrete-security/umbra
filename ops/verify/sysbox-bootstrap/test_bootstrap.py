"""Offline contracts; runtime transaction tests belong to systemd_harness.py."""

from __future__ import annotations

import os
import json
import configparser
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render
import systemd_harness

URLS = {name: f"https://artifacts.example.com/releases/0.7.1/{name}" for name in render.BINARIES}


class BootstrapTests(unittest.TestCase):
    def test_final_override_clears_late_native_docker_settings_success(self):
        """Both fixture versions reproduce the old ordering bug and clear it with zz."""
        layout = render.Layout(prefix="umbra-sbq-123456abcdef-", root="/run/umbra-sbq-123456abcdef")
        override = systemd_harness.service_override(
            layout, "docker", layout.root + "/mock-runtime", "success",
        ).decode()
        for version in ("0.5.9", "0.5.12"):
            files = render.fixtures(version)
            drops = {Path(name).name: value.decode() for name, value in files.items()
                     if name.startswith("docker.service.d/")}
            self.assertTrue(all(name < systemd_harness.QUALIFICATION_OVERRIDE for name in drops))
            for name in ("80-qualification.conf", systemd_harness.QUALIFICATION_OVERRIDE):
                merged = {**drops, name: override}
                config = configparser.RawConfigParser(strict=False)
                config.read_string(
                    files["docker.service"].decode()
                    + "\n" + "\n".join(merged[key] for key in sorted(merged))
                )
                # These fields have one native assignment, so their last reset is
                # an offline ordering check; PID 1 verifies the effective values.
                for key in ("ExecStartPre", "CPUAffinity"):
                    with self.subTest(version=version, override=name, key=key):
                        value = config.get("Service", key)
                        if name == systemd_harness.QUALIFICATION_OVERRIDE:
                            self.assertEqual(value, "")
                        else:
                            self.assertNotEqual(value, "")

    def test_effective_service_rejects_restored_settings_failure(self):
        """The pre-start gate rejects native commands, env files, affinity and controls."""
        root = "/run/umbra-sbq-123456abcdef"
        command = root + "/mock-runtime"
        baseline = {key: "" for key in systemd_harness.EMPTY_SERVICE_PROPERTIES}
        baseline.update({
            "ExecStart": f"{{ path={command} ; argv[]={command} ; ignore_errors=no ; }}",
            "Environment": f"SBQ_ROOT={root} SBQ_ROLE=docker",
            "DropInPaths": "/run/systemd/system/unit.d/zz-qualification.conf",
            "WatchdogUSec": "0", "FailureAction": "none",
        })
        systemd_harness.validate_effective_service(baseline, command, "docker", root)
        mutations = {key: ("restored-native-value", "docker") for key in
                     systemd_harness.EMPTY_SERVICE_PROPERTIES}
        mutations.update({
            "ExecStart": ("{ path=/bin/app-compose.sh ; argv[]=/bin/app-compose.sh ; }", "docker"),
            "Environment": ("SBQ_ROOT=/dstack SBQ_ROLE=docker", "docker"),
            "DropInPaths": ("/run/systemd/system/unit.d/dstack-guest-agent.conf", "docker"),
            "WatchdogUSec": ("30s", "guest"),
            "FailureAction": ("reboot", "prepare"),
        })
        for key, (value, role) in mutations.items():
            props = {**baseline, "Environment": f"SBQ_ROOT={root} SBQ_ROLE={role}", key: value}
            with self.subTest(property=key), self.assertRaises(AssertionError):
                systemd_harness.validate_effective_service(props, command, role, root)

    def test_systemd_255_empty_property_display_success(self):
        """CI's omitted empty arrays and disabled watchdog still prove isolation."""
        case = systemd_harness.Case("0.5.9", "success", Path("/unused"), Path("/unused"))
        command = case.layout.root + "/mock-runtime"
        case.expected_services = {"dstack-guest-agent.service": ("guest", command)}
        # systemd 255's human printer omits empty structured arrays even with
        # --all; the 40220656650 artifact reports disabled watchdog as infinity.
        shown = {
            "ExecStart": f"{{ path={command} ; argv[]={command} ; ignore_errors=no ; }}",
            "CPUAffinity": "", "Environment": f"SBQ_ROOT={case.layout.root} SBQ_ROLE=guest",
            "DropInPaths": "/run/systemd/system/unit.d/zz-qualification.conf",
            "WatchdogUSec": "infinity", "FailureAction": "none",
        }
        missing = sorted(set(systemd_harness.EMPTY_SERVICE_PROPERTIES) - shown.keys())
        unit = case.layout.unit("dstack-guest-agent.service")
        object_path = "/org/freedesktop/systemd1/unit/" + unit.replace("-", "_2d").replace(".", "_2e")
        def query(*args):
            # Inactive, unreferenced units may disappear between systemctl and
            # GetUnit. Direct object properties load the unit on that same call.
            if "GetUnit" in args:
                raise subprocess.CalledProcessError(1, args, stderr=f"Unit {unit} not loaded.")
            self.assertEqual(args, (
                "busctl", "--system", "--json=short", "get-property",
                "org.freedesktop.systemd1", object_path,
                "org.freedesktop.systemd1.Service", *missing,
            ))
            return subprocess.CompletedProcess([], 0, "\n".join(json.dumps({
                "type": "a(sb)" if name == "EnvironmentFiles" else "a(sasbttttuii)",
                "data": [],
            }) for name in missing), "")
        output = subprocess.CompletedProcess([], 0, "\n".join(
            key + "=" + value for key, value in shown.items()
        ), "")
        with patch.object(case, "ctl", return_value=output), patch.object(
            systemd_harness, "run", side_effect=query,
        ) as dbus:
            case.assert_effective_services()
        dbus.assert_called_once()

    def test_subprocess_failure_retains_bounded_stderr_failure(self):
        """An actual failing child leaves a bounded diagnostic in the traceback."""
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            systemd_harness.run(sys.executable, "-c",
                                "import sys; sys.stderr.write('x' * 10000 + 'unit-not-loaded'); sys.exit(1)")
        notes = raised.exception.__notes__
        self.assertEqual(len(notes), 1)
        self.assertTrue(notes[0].endswith("unit-not-loaded"))
        self.assertLessEqual(len(notes[0]), 2100)

    def test_omitted_array_needs_typed_empty_proof_failure(self):
        """Missing, malformed or nonempty D-Bus values never permit a start."""
        case = systemd_harness.Case("0.5.9", "success", Path("/unused"), Path("/unused"))
        command = case.layout.root + "/mock-runtime"
        case.expected_services = {"docker.service": ("docker", command)}
        shown = {key: "" for key in systemd_harness.EMPTY_SERVICE_PROPERTIES}
        shown.update({
            "ExecStart": f"{{ path={command} ; argv[]={command} ; }}",
            "Environment": f"SBQ_ROOT={case.layout.root} SBQ_ROLE=docker",
            "DropInPaths": "/run/systemd/system/unit.d/zz-qualification.conf",
            "WatchdogUSec": "infinity", "FailureAction": "none",
        })
        del shown["ExecStartPre"]
        output = subprocess.CompletedProcess([], 0, "\n".join(
            key + "=" + value for key, value in shown.items()
        ), "")
        values = (
            "", "not json", json.dumps({"type": "s", "data": ""}),
            json.dumps({"type": "a(sasbttttuii)", "data": [["/bin/native"]]}),
            subprocess.CalledProcessError(1, ["busctl", "get-property"]),
        )
        for value in values:
            reply = value if isinstance(value, Exception) else subprocess.CompletedProcess([], 0, value, "")
            with self.subTest(value=str(value)), patch.object(case, "ctl", return_value=output) as ctl, patch.object(
                systemd_harness, "run", side_effect=[reply],
            ), self.assertRaises((AssertionError, ValueError, subprocess.CalledProcessError)):
                try:
                    case.exercise()
                finally:
                    self.assertTrue(all(call.args[0] == "show" for call in ctl.call_args_list))

    def test_omitted_scalar_is_not_empty_array_failure(self):
        """A missing command identity, CPU mask or environment remains an error."""
        case = systemd_harness.Case("0.5.9", "success", Path("/unused"), Path("/unused"))
        case.expected_services = {"docker.service": ("docker", "/unused")}
        for key in ("ExecStart", "Environment", "CPUAffinity"):
            fields = {*systemd_harness.EMPTY_SERVICE_PROPERTIES, "ExecStart", "Environment",
                      "DropInPaths", "WatchdogUSec", "FailureAction"} - {key}
            output = subprocess.CompletedProcess([], 0, "\n".join(name + "=" for name in fields), "")
            with self.subTest(property=key), patch.object(case, "ctl", return_value=output), patch.object(
                systemd_harness, "run",
            ) as dbus, self.assertRaisesRegex(AssertionError, "omitted required"):
                try:
                    case.assert_effective_services()
                finally:
                    dbus.assert_not_called()

    def test_repeated_command_property_failure(self):
        """A later expected command cannot conceal an earlier native command."""
        case = systemd_harness.Case("0.5.9", "success", Path("/unused"), Path("/unused"))
        case.expected_services = {"docker.service": ("docker", "/unused")}
        output = subprocess.CompletedProcess([], 0, "ExecStart=native\nExecStart=/unused\n", "")
        with patch.object(case, "ctl", return_value=output), self.assertRaisesRegex(AssertionError, "repeated"):
            case.assert_effective_services()

    def test_effective_service_gate_runs_before_any_start_failure(self):
        """A bad effective fixture prevents every scenario from starting a unit."""
        for scenario in ("success", "source", "wrong-executable", *systemd_harness.FAULTS,
                         *systemd_harness.SIGNAL_CASES):
            case = systemd_harness.Case("0.5.9", scenario, Path("/unused"), Path("/unused"))
            with self.subTest(scenario=scenario), patch.object(
                case, "assert_effective_services", side_effect=AssertionError("bad fixture")
            ), patch.object(case, "ctl") as ctl, self.assertRaisesRegex(AssertionError, "bad fixture"):
                try:
                    case.exercise()
                finally:
                    ctl.assert_not_called()

    def test_idle_systemd_job_display_success(self):
        """The actual cancel/check block accepts present empty Job= as idle."""
        hook = render.render("0.5.9", URLS)
        helpers = hook[hook.index("require() {"):hook.index("safe_dir() {")]
        checks = hook[hook.index("# A native socket may"):hook.index("# Qualification fault injection")]
        for mode in ("idle", "queued"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                script = "set -euo pipefail\nhold() { exit 97; }\n" + helpers + r'''
mode=$1
state=$2
runtime_units=(mock.service)
docker_socket=mock.socket
ctl() {
    case "$1" in
        stop) return 0 ;;
        cancel) [[ "$2" = 42 ]]; touch "$state"; printf 'cancel 42\n'; return 0 ;;
    esac
    if [[ "$*" == *--property=ActiveState* ]]; then printf 'inactive\n'; return; fi
    [[ "$*" == *--property=Job* ]] || exit 96
    value=''
    if [[ "$mode" = queued && "${!#}" = mock.service && ! -e "$state" ]]; then value=42; fi
    if [[ "$*" == *--value* ]]; then printf '%s\n' "$value"; else printf 'Job=%s\n' "$value"; fi
}
''' + checks
                result = subprocess.run(["bash", "-c", script, "bash", mode, tmp + "/cancelled"],
                                        capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "cancel 42\n" if mode == "queued" else "")

    def test_malformed_systemd_job_display_failure(self):
        """Absent, differently named and malformed job properties never mean idle."""
        hook = render.render("0.5.9", URLS)
        helpers = hook[hook.index("require() {"):hook.index("safe_dir() {")]
        # Use an argument instead of interpolating returned property bytes into code.
        script = ("set -euo pipefail\nhold() { exit 97; }\n" + helpers
                  + '\nfake_job_output=$1\nctl() { printf "%s\\n" "$fake_job_output"; }\njob_id mock.service\n')
        for value in ("", "LoadState=loaded", "Job=unknown", "Job=42\nJob=", "Job=-1"):
            with self.subTest(value=value):
                result = subprocess.run(["bash", "-c", script, "bash", value],
                                        capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 97)

    def test_pinned_source_fixtures_success(self):
        """All retained bytes match Git and SHA-256; only the app dependency differs."""
        old, new = render.fixtures("0.5.9"), render.fixtures("0.5.12")
        self.assertEqual({k for k in old if old[k] != new[k]}, {"app-compose.service"})
        self.assertNotIn(b"Requires=", old["app-compose.service"])
        self.assertIn(b"Requires=dstack-prepare.service", new["app-compose.service"])
        self.assertIn(b"--disable-ovfs-on-idmapped-mount", old["sysbox-mgr.service"])
        self.assertIn(b"--data-root /var/lib/sysbox", old["sysbox-mgr.service"])
        self.assertIn(b"ExecStart=/usr/bin/containerd", old["containerd.service"])

    def test_changed_source_fixture_failure(self):
        """A local source edit cannot silently change the expected unit identity."""
        original = Path.read_bytes
        def altered(path):
            data = original(path)
            return data + b"# changed\n" if path.name == "sysbox-mgr.service" else data
        with patch.object(Path, "read_bytes", altered), self.assertRaisesRegex(ValueError, "checksum"):
            render.fixtures("0.5.9")

    def test_incomplete_fixture_inventory_failure(self):
        """Extra, absent, duplicate and symlinked files cannot become expected source."""
        for scenario in ("extra-common", "extra-version", "missing", "duplicate", "symlink"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                copied = Path(tmp)
                shutil.copytree(render.HERE / "fixtures", copied / "fixtures")
                if scenario in {"extra-common", "extra-version"}:
                    directory = "common" if scenario == "extra-common" else "0.5.9"
                    extra = copied / f"fixtures/{directory}/sysbox-mgr.service.d/extra.conf"
                    extra.parent.mkdir()
                    extra.write_text("[Service]\nExecStart=/bin/false\n")
                elif scenario == "missing":
                    (copied / "fixtures/common/sysbox-mgr.service").unlink()
                elif scenario == "duplicate":
                    manifest_path = copied / "fixtures/manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    manifest["sources"].append(manifest["sources"][0])
                    manifest_path.write_text(json.dumps(manifest))
                else:
                    (copied / "fixtures/common/extra.conf").symlink_to("sysbox-mgr.service")
                with patch.object(render, "HERE", copied), self.assertRaisesRegex(
                    ValueError, "inventory|duplicate"
                ):
                    render.fixtures("0.5.9")

    def test_native_binary_pins_match_mandatory_build_gate_success(self):
        """The renderer cannot diverge from the reviewed binary build pins."""
        path = render.HERE.parent / "sysbox-build/binaries.expected.sha256"
        expected = dict((name, sha) for sha, name in (line.split() for line in path.read_text().splitlines()))
        self.assertEqual(render.PINS, expected)

    def test_native_output_is_technically_held_success(self):
        """Native rendering embeds exact pins but cannot mutate the guest."""
        hook = render.render("0.5.9", URLS)
        self.assertLess(hook.index('hold "native use blocked:'), hook.index("ctl stop"))
        self.assertNotIn("UMBRA_SYSBOX_ENABLE", hook)
        for digest in render.PINS.values():
            self.assertIn(digest, hook)
        self.assertIn("/persistent/umbra-runtime-cache/", hook)
        self.assertNotIn("sysbox.service.d/", hook)
        self.assertIn("Requires=umbra-sysbox-ready.service dstack-prepare.service", hook)
        self.assertNotIn("RemainAfterExit=yes\nExecStart=/bin/bash", hook)
        subprocess.run(["bash", "-n"], input=hook, text=True, check=True)

    def test_native_pin_override_failure(self):
        """Only isolated test layouts can supply mock hashes or source bytes."""
        for kwargs in ({"pins": render.PINS}, {"source_files": render.fixtures("0.5.9")}):
            with self.subTest(kwargs=next(iter(kwargs))), self.assertRaisesRegex(ValueError, "cannot be overridden"):
                render.render("0.5.9", URLS, **kwargs)

    def test_unsafe_artifact_urls_failure(self):
        """Credentials, query material, private literals and shell syntax are rejected."""
        for url in (
            "http://example.com/a", "https://user:secret@example.com/a",
            "https://example.com/a?token=secret", "https://example.com/a#fragment",
            "https://127.0.0.1/a", "https://[::1]/a", "https://localhost/a",
            "https://127.1/a", "https://1.2.3/a", "https://0x7f.0.0.1/a",
            "https://0177.0.0.1/a", "https://127.0.0.0x1/a",
            "https://2130706433/a", "https://0x7f000001/a",
            "https://host.local/a", "https://example.com:443/a",
            "https://example.com/../a", "https://example.com/a\nwhoami",
            "https://example.com/$(whoami)", "https://example.com/%2e%2e/a",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                render.validate_url(url)

    def test_prefixed_graph_preserves_native_edges_success(self):
        """Each source edge remains, directed only to its isolated counterpart."""
        prefix = "umbra-sbq-123456abcdef-"
        for name, content in render.fixtures("0.5.9").items():
            changed = systemd_harness.transform(content, prefix)
            for line in content.decode().splitlines():
                key, sep, value = line.partition("=")
                if sep and key in systemd_harness.DEPENDENCIES:
                    self.assertIn(
                        (key + "=" + " ".join(prefix + unit for unit in value.split())).encode(),
                        changed, name,
                    )
            self.assertNotIn(b"FailureAction=reboot", changed)

    def test_unisolated_fixture_layout_failure(self):
        """Neither a unit prefix nor a filesystem path can escape the test namespace."""
        for layout in (
            render.Layout(prefix="docker-", root="/run/docker"),
            render.Layout(prefix="umbra-sbq-123456abcdef-", root="/"),
            render.Layout(root="/run/umbra-sbq-123456abcdef"),
        ):
            with self.subTest(layout=layout), self.assertRaises(ValueError):
                render.render("0.5.9", URLS, layout=layout)

    def test_prefixed_render_same_core_success(self):
        """Only identity and paths differ; the core keeps the same failure traps."""
        layout = render.Layout(prefix="umbra-sbq-123456abcdef-", root="/run/umbra-sbq-123456abcdef")
        sources = {
            layout.prefix + name: systemd_harness.transform(content, layout.prefix)
            for name, content in render.fixtures("0.5.9").items()
        }
        hook = render.render("0.5.9", URLS, layout=layout, source_files=sources, pins=render.PINS)
        self.assertNotIn('hold "native use blocked:', hook)
        self.assertIn('trap \'hold "command, pipeline or shell failure"\' ERR EXIT', hook)
        self.assertIn("ctl --no-block start", hook)
        subprocess.run(["bash", "-n"], input=hook, text=True, check=True)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux Bash 5 failure semantics")
    def test_shell_failure_holds_preparation_success(self):
        """Command, pipefail, nounset, TERM and timeout never return successful prepare."""
        prelude = (render.HERE / "hook.sh.in").read_text().split("@@QUALIFICATION_HOLD@@")[0]
        for scenario, command in systemd_harness.FAULTS.items():
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "stderr"
                with path.open("w") as stderr:
                    proc = subprocess.Popen(
                        ["bash", "-c", prelude + "\n" + command
                         + f"\ntouch {shlex.quote(str(Path(tmp) / 'worker-complete'))}\n"
                         + "trap - ERR EXIT HUP INT TERM\n)\n"],
                        stderr=stderr, stdout=subprocess.DEVNULL, start_new_session=True,
                    )
                    try:
                        deadline = time.monotonic() + 3
                        while time.monotonic() < deadline and "held:" not in path.read_text():
                            time.sleep(0.02)
                        self.assertIsNone(proc.poll())
                        self.assertIn("held:", path.read_text())
                        self.assertFalse((Path(tmp) / "worker-complete").exists())
                    finally:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait(timeout=3)

    def test_source_mainpid_and_group_term_hold_success(self):
        """TERM to the source caller or its whole group cannot complete preparation."""
        template = (render.HERE / "hook.sh.in").read_text()
        prelude = template.split("@@QUALIFICATION_HOLD@@")[0]
        postlude = template.split("# Restore the source caller's traps after successful worker completion.")[1]
        for target in ("main", "group"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                reached, release = directory / "reached", directory / "release"
                returned, errors = directory / "returned", directory / "stderr"
                script = directory / "hook.sh"
                script.write_text(
                    prelude + f"\ntouch {shlex.quote(str(reached))}\n"
                    f"while [[ ! -f {shlex.quote(str(release))} ]]; do sleep 0.1; done\n"
                    "trap - ERR EXIT HUP INT TERM\n)\n" + postlude
                )
                with errors.open("w") as stderr:
                    proc = subprocess.Popen(
                        ["bash", "-c", f"set -e; source {shlex.quote(str(script))}; "
                         f"touch {shlex.quote(str(returned))}"],
                        stderr=stderr, stdout=subprocess.DEVNULL, start_new_session=True,
                    )
                    try:
                        deadline = time.monotonic() + 3
                        while time.monotonic() < deadline and not reached.exists():
                            time.sleep(0.02)
                        self.assertTrue(reached.exists())
                        if target == "main":
                            os.kill(proc.pid, signal.SIGTERM)
                        else:
                            os.killpg(proc.pid, signal.SIGTERM)
                        release.touch()
                        deadline = time.monotonic() + 3
                        while time.monotonic() < deadline and "held:" not in errors.read_text():
                            time.sleep(0.02)
                        self.assertIsNone(proc.poll())
                        self.assertIn("held:", errors.read_text())
                        self.assertFalse(returned.exists())
                    finally:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait(timeout=3)

    def test_success_restores_source_caller_traps_success(self):
        """The worker's successful return does not change the native caller's traps."""
        template = (render.HERE / "hook.sh.in").read_text()
        prelude = template.split("@@QUALIFICATION_HOLD@@")[0]
        postlude = template.split("# Restore the source caller's traps after successful worker completion.")[1]
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "hook.sh"
            script.write_text(prelude + "\ntrue\ntrap - ERR EXIT HUP INT TERM\n)\n" + postlude)
            run = subprocess.run(
                ["bash", "-c", "set -e; trap ':' TERM; trap ':' EXIT; "
                 "before=$(trap -p HUP INT TERM ERR EXIT); "
                 f"source {shlex.quote(str(script))}; "
                 'after=$(trap -p HUP INT TERM ERR EXIT); test "$before" = "$after"'],
                capture_output=True, text=True, timeout=3,
            )
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
