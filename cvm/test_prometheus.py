import subprocess
import pytest
import json
import csv
import re

from pprint import pprint

PROMETHEUS_URL = "http://prometheus:9090"
VLLM_URL = "http://vllm:8000/metrics"


def run_in_prometheus(cmd: str) -> str:
    full_cmd = ["docker", "exec", "prometheus", "sh", "-c", cmd]
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"❌ Command failed:\n`{cmd}`\nSTDERR:\n`{result.stderr.strip()}`")
    return result.stdout.strip()


def test_prometheus_ready():
    response = run_in_prometheus(f"wget -qO- {PROMETHEUS_URL}/-/ready")
    print(f"\n-> {PROMETHEUS_URL}/ready:\n{response}")
    assert "Prometheus Server is Ready." == response.strip(), "Got `{out}`"


def test_prometheus_endpoint_target_api():
    response = run_in_prometheus(f"wget -qO- {PROMETHEUS_URL}/api/v1/targets")
    # response = run_in_prometheus(f"wget -qO- {PROMETHEUS_URL}/targets")
    print(f"\n->{PROMETHEUS_URL}/api/v1/targets:\n{response}")
    data = json.loads(response)
    pprint(data, indent=5)


def test_prometheus_list_all_vllm_metrics():
    entries = set()
    output_file = '../../monitoring/vllm_metrics.csv'
    raw = run_in_prometheus(f"wget -qO- {VLLM_URL}")

    for line in raw.splitlines():
        if line.startswith('# HELP'):
            parts = line.split(' ', 3)
            _, _, name, desc = parts
            entries.add((name, desc))

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "description"])
        w.writerows(sorted(entries))
