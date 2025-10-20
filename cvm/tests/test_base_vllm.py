import os
import requests
import pytest

# Configuration
BASE_URL = os.getenv("BASE_URL", "https://localhost")
MODEL_ID = os.getenv("MODEL_ID", "openai/gpt-oss-120b")
TIMEOUT = 10


# curl -k https://localhost/metrics | head -n 30
def test_base_vllm_endpoint_metrics():
    """Test if the /metrics endpoint is reachable and returns expected content."""
    url = f"{BASE_URL}/metrics"
    response = requests.get(url, timeout=TIMEOUT, verify=False)
    assert response.status_code == 200, f"/metrics failed: expected `200`, got `{response.status_code}`"
    assert "vllm" in response.text.lower(), "Le contenu de /metrics ne semble pas valide."


# curl -k https://localhost/v1/models
def test_base_vllm_endpoint_v1_models():
    """Test if the /v1/models endpoint returns a valid JSON response."""
    url = f"{BASE_URL}/v1/models"
    response = requests.get(url, timeout=TIMEOUT, verify=False)
    assert response.status_code == 200, f"/v1/models failed: expected `200`, got `{response.status_code}`"

    data = response.json()
    assert "data" in data, "Missing 'data' field in response"
    assert isinstance(data["data"], list), "'data' is not a list"

    model_ids = [m["id"] for m in data["data"]]
    assert MODEL_ID in model_ids, f"Model ID '{MODEL_ID}' not found in available models"


# curl -k -X POST https://localhost/v1/completions \
#   -H "Content-Type: application/json" \
#   -d '{"model": "openai/gpt-oss-120b", "prompt": "Hello world!", "max_tokens": 10}'
@pytest.mark.parametrize(
    "prompt,max_tokens",
    [
        ("Hello world!", 10),
        ("What is Fully Homomorphic Encryption?", 20),
    ],
)
def test_base_vllm_endpoint_v1_completions(prompt, max_tokens):
    """Test if the model can handle `v1_completions` endpoint with a simple request."""
    url = f"{BASE_URL}/v1/completions"
    payload = {
        "model": MODEL_ID,
        "prompt": prompt,
        "max_tokens": max_tokens,
    }

    response = requests.post(url, json=payload, timeout=TIMEOUT, verify=False)
    assert response.status_code == 200, f"/v1/completions failed: expected `200`, got `{response.status_code}`"
    data = response.json()

    assert "choices" in data, "Missing 'choices' field in completion response"
    assert len(data["choices"]) > 0, "No choices returned"
    output_text = data["choices"][0].get("text", "").strip()
    assert output_text, "Model returned an empty text response"
