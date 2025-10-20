import os
import requests

PORT = os.getenv("PORT", '8000')
BASE_URL = f"http://localhost:{PORT}"
MODEL_ID = os.getenv("MODEL_ID", "openai/gpt-oss-120b")
METRICS_URL = f"{BASE_URL}/metrics"

# curl -s http://localhost:8000/metrics | head -n 30
def test_base_vllm_endpoint_metrics():
    response = requests.get(f"{BASE_URL}/metrics", timeout=5)
    assert response.status_code == 200, f"Expected `200`, got `{response.status_code}`"

def test_base_vllm_endpoint_v1_models():
    """Test if the /v1/models endpoint returns a valid JSON response."""
    url = f"{BASE_URL}/v1/models"
    response = requests.get(url, timeout=5)
    assert response.status_code == 200, f"Expected `200`, got `{response.status_code}`"
    data = response.json()
    assert "data" in data, "Missing 'data' field in response"
    assert isinstance(data["data"], list), "'data' is not a list"
    model_ids = [m["id"] for m in data["data"]]
    assert MODEL_ID in model_ids, f"Model ID '{MODEL_ID}' not found in available models"


def test_base_vllm_endpoint_v1_completions():
    """Test if the model can handle a simple completion request."""
    url = f"{BASE_URL}/v1/completions"
    payload = {
        "model": MODEL_ID,
        "prompt": "Hello world!",
        "max_tokens": 10,
    }

    response = requests.post(url, json=payload, timeout=10)
    assert response.status_code == 200, f"Expected `200`, got `{response.status_code}`"
    data = response.json()
    assert "choices" in data, "Missing 'choices' field in completion response"
    assert len(data["choices"]) > 0, "No choices returned"
    output_text = data["choices"][0].get("text", "").strip()
    assert output_text, "Model returned an empty text response"
