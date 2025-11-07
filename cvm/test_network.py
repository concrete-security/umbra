import subprocess
import json
import sys

EXPECTED_CONTAINERS = {"nginx", "prometheus", "grafana", "vllm", "proxy_api"}
NETWORK_NAME = "cvm_vllm"

def test_cvm_vllm_network():
    print("🔍 Inspecting cvm_vllm network...")
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", NETWORK_NAME],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        containers = data[0].get("Containers", {})

        attached_containers = {c["Name"] for c in containers.values()}
        missing_containers = EXPECTED_CONTAINERS - attached_containers
        extra_containers = attached_containers - EXPECTED_CONTAINERS

        print(f"✅ Attached containers   : {', '.join(sorted(attached_containers))}")
        print(f"❌ Missing containers    : {', '.join(sorted(missing_containers))}")
        print(f"⚠️  Unexpected containers : {', '.join(sorted(extra_containers))}")

    except Exception as e:
        print("❌ Error running docker command:", e)
