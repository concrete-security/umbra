import os
import subprocess
import json

from valid_vllm_metrics_list import VALID_VLLM_METRIC_LIST


VLLM_METRICS_PREFIX = "vllm:"
VLLM_TARGET = os.getenv("VLLM_TARGET")
VLLM_METRICS_AUTH_TOKEN = os.getenv("VLLM_METRICS_AUTH_TOKEN")

SCHEME = os.getenv("SCHEME")
PROMETHEUS_PORT = os.getenv("PROMETHEUS_PORT")
PROMETHEUS_URL = f"http://prometheus:{PROMETHEUS_PORT}"

REMOTE_VLLM_URL = f"{SCHEME}://{VLLM_TARGET}"
AUTH_HEADER = f"Authorization: Bearer {VLLM_METRICS_AUTH_TOKEN}"


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
    data = json.loads(response)

    active = data["data"]["activeTargets"]
    assert active, "No active targets found in Prometheus"

    target = active[0]
    assert target["health"] == "up", f"Target health is DOWN: `{target}`"


def test_vllm_metrics_from_remote_url():
    """Directly scraping metrics from the remote confidential machine that hosts the AI model.
    In this case, the authentification is needed. """

    assert VLLM_METRICS_AUTH_TOKEN, "Missing TOKEN env var. Make sure `.env` defines TOKEN"

    raw = subprocess.run(
        ["curl", "-fsS", "--max-time", "10", "-H", AUTH_HEADER, f"{REMOTE_VLLM_URL}/metrics"],
        capture_output=True,
        text=True,
    )
    assert raw.returncode == 0, f"curl failed: {raw.stderr}"
    assert "vllm" in raw.stdout.lower(), "Metrics do not look like vLLM output"


def test_vllm_metrics_from_prometheus_container():
    assert VLLM_METRICS_AUTH_TOKEN, "Missing VVLM_METRICS_AUTH_TOKEN"
    scraped_raw = run_in_prometheus(
        f"wget -qO- {PROMETHEUS_URL}/api/v1/label/__name__/values "
        "| tr ',' '\\n' "
        "| tr -d '[]{}\" '"
        "| grep '^vllm:' "
    )
    scraped = [line.strip() for line in scraped_raw.splitlines() if line.strip()]

    assert set(scraped) == set(VALID_VLLM_METRIC_LIST), "Mismatch between scraped vLLM metrics and allowlist"


def test_prometheus_scraped_vllm_metrics_are_known():
    """
    Ensure that all vLLM metrics scraped by Prometheus are in the allowlist.

    IMPORTANT:
    - Authentication to vLLM (/metrics) is NOT performed in this test.
    - Authentication already happened earlier, during the Prometheus scrape phase,
      using the `authorization` configuration in `prometheus.yml`.
    - This test assumed that Prometheus has already scraped vLLM and stored the metrics in its TSDB.
    """

    resp = run_in_prometheus(f"wget -qO- {PROMETHEUS_URL}/api/v1/label/__name__/values")
    data = json.loads(resp)
    assert data["status"] == "success", f"Prometheus API error: `{data}`"

    scraped = {n for n in data["data"] if n.startswith(VLLM_METRICS_PREFIX)}
    assert set(scraped) == set(VALID_VLLM_METRIC_LIST), "Mismatch between scraped vLLM metrics and allowlist"
