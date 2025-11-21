import os
import subprocess
import json
import csv

from pprint import pprint

SCHEME = os.getenv("SCHEME", "http")
PROMETHEUS_PORT = os.getenv("PROMETHEUS_PORT")
VLLM_TARGET = os.getenv("VLLM_TARGET", "localhost:8000")

PROMETHEUS_URL = f"http://prometheus:{PROMETHEUS_PORT}"
REMOTE_VLLM_URL = f"{SCHEME}://{VLLM_TARGET}"


def run_in_prometheus(cmd: str) -> str:
    full_cmd = ["docker", "exec", "prometheus", "sh", "-c", cmd]
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"❌ Command failed:\n`{cmd}`\nSTDERR:\n`{result.stderr.strip()}`")
    return result.stdout.strip()


def test_prometheus_ready():
    response = run_in_prometheus(f"wget -qO- {PROMETHEUS_URL}/-/ready")
    assert "Prometheus Server is Ready." == response.strip(), "Got `{out}`"


def test_prometheus_endpoint_target_api():
    response = run_in_prometheus(f"wget -qO- {PROMETHEUS_URL}/api/v1/targets")
    # response = run_in_prometheus(f"wget -qO- {PROMETHEUS_URL}/targets")
    print(f"\n->{PROMETHEUS_URL}/api/v1/targets:\n{response}")
    data = json.loads(response)
    pprint(data, indent=5)

    active = data["data"]["activeTargets"]
    assert active, "No active targets found in Prometheus"

    target = active[0]
    assert target["health"] == "up", f"Target health is DOWN: `{target}`"

def test_prometheus_list_all_vllm_metrics():
    raw = subprocess.run(["curl", f"{REMOTE_VLLM_URL}/metrics"], capture_output=True, text=True)
    assert raw.returncode == 0, f"curl failed: {raw.stderr}"
    assert "vllm" in raw.stdout.lower(), "Metrics do not look like vLLM output"
