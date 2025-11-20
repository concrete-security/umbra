import os
import json
import subprocess

from pprint import pprint


GRAFANA_USER = os.getenv("ADMIN_USER", "toto")
GRAFANA_PASS = os.getenv("ADMIN_PASSWORD", "toto")
GRAFANA_PORT = os.getenv("GRAFANA_PORT")
GRAFANA_URL = f"localhost:{GRAFANA_PORT}"

PROMETHEUS_SERVICE_NAME = "prometheus"
PROMETHEUS_PORT= os.getenv("PROMETHEUS_PORT")
PROMETHEUS_URL = f"http://{PROMETHEUS_SERVICE_NAME}:{PROMETHEUS_PORT}"

CMD = f'curl -fsS http://{GRAFANA_USER}:{GRAFANA_PASS}@{GRAFANA_URL}'


def run_in_grafana(cmd: str) -> str:
    full_cmd = ["docker", "exec", "grafana", "sh", "-c", cmd]
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"❌ Command failed:\n`{cmd}`\nSTDERR:\n`{result.stderr.strip()}`")
    return result.stdout.strip()


def test_grafana_health():
    response = run_in_grafana(f"{CMD}/api/health")
    response = json.loads(response)
    print(f"\n-> http://{GRAFANA_URL}/api/health:\n{response}")
    assert response["database"] == "ok", f"Database KO: `{response}`"


def test_grafana_datasource_prometheus():
    response = run_in_grafana(f"{CMD}/api/datasources")
    data = json.loads(response)[0]
    pprint(data, indent=5)
    assert data["type"] == PROMETHEUS_SERVICE_NAME, f"Got `{data['type']}`, expected `{PROMETHEUS_SERVICE_NAME}`"
    assert data["url"] == PROMETHEUS_URL, f"Got `{data['url']}`, expected `{PROMETHEUS_URL}`"
    # Grafana queries Prometheus via the backend, not from the browser
    # Prometheus is isolated in your Docker network
    assert data["access"] == "proxy", f"Got `{data['access']}`, expected `{'proxy'}`"
    # Grafana will use Prometheus by default for all queries
    # No need to specify the data source in your dashboards
    assert data["isDefault"] == True, f"Got `{data['isDefault']}`, expected `{True}`"
