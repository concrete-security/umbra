import json
import subprocess
from pprint import pprint

PROMETHEUS_SERVICE_NAME = "prometheus"
PROMETHEUS_URL = f"http://{PROMETHEUS_SERVICE_NAME}:9090"
GRAFANA_URL = "localhost:4000"

GRAFANA_USER = GRAFANA_PASS = "admin"

def run_in_grafana(cmd: str) -> str:
    full_cmd = ["docker", "exec", "grafana", "sh", "-c", cmd]
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"❌ Command failed:\n`{cmd}`\nSTDERR:\n`{result.stderr.strip()}`")
    return result.stdout.strip()


def test_grafana_health():
    cmd = f"wget -qO- http://{GRAFANA_USER}:{GRAFANA_PASS}@{GRAFANA_URL}/api/health"
    response = run_in_grafana(cmd)
    response = json.loads(response)
    print(f"\n-> http://{GRAFANA_URL}/api/health:\n{response}")
    assert response["database"] == "ok", f"Database KO: `{response}`"


def test_grafana_datasource_prometheus():
    cmd = f"wget -qO- http://{GRAFANA_USER}:{GRAFANA_PASS}@{GRAFANA_URL}/api/datasources"
    response = run_in_grafana(cmd)
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
