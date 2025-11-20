import subprocess
import json

import pytest


EXPECTED_NETWORKS = {
    "vllm": {"vllm", "nginx", "proxy_api"},
    "monitoring": {"grafana", "prometheus"},
}
@pytest.mark.parametrize("network,expected_containers", EXPECTED_NETWORKS.items())
def test_vllm_network(network, expected_containers):
    print(f"🔍 Inspecting {network} network...")
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", network],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        containers = data[0].get("Containers", {})

        attached_containers = {c["Name"] for c in containers.values()}
        missing_containers = expected_containers - attached_containers
        extra_containers = attached_containers - expected_containers

        print(f"✅ Attached containers: {', '.join(sorted(attached_containers))}")
        print(f"❌ Missing containers: {', '.join(sorted(missing_containers))}")
        print(f"⚠️  Unexpected containers: {', '.join(sorted(extra_containers))}")

        assert len(missing_containers) == 0
        assert len(extra_containers) == 0

    except Exception as e:
        print("❌ Error running docker command:", e)
