import os
import requests
import pytest

# Configuration
BASE_URL = "https://localhost"
MODEL_ID = os.getenv("MODEL_ID", "openai/gpt-oss-120b")
TIMEOUT = 10

# curl -k https://localhost/metrics | head -n 30
def test_vllm_proxy_endpoint_metrics():
    """Test if the /metrics endpoint is reachable and returns expected content."""
    url = f"{BASE_URL}/metrics"
    response = requests.get(url, timeout=TIMEOUT, verify=False)
    assert response.status_code == 200, f"/metrics failed: expected `200`, got `{response.status_code}`"
    assert "vllm" in response.text.lower(), "The content of /metrics does not seem to be valid."


# curl -k https://localhost/v1/models
def test_vllm_proxy_endpoint_v1_models():
    """Test if the /v1/models endpoint returns a valid JSON response."""
    url = f"{BASE_URL}/v1/models"
    response = requests.get(url, timeout=TIMEOUT, verify=False)
    assert response.status_code == 200, f"/v1/models failed: expected `200`, got `{response.status_code}`"

    data = response.json()
    assert "data" in data, "Missing 'data' field in response"
    assert isinstance(data["data"], list), "'data' is not a list"

    model_ids = [m["id"] for m in data["data"]]
    assert MODEL_ID in model_ids, f"Model ID '{MODEL_ID}' not found in available models"


@pytest.mark.parametrize(
    "prompt",
    [
        ("Hello world!"),
        ("What is Fully Homomorphic Encryption? in one word"),
    ],
)
def test_vllm_proxy_endpoint_v1_chat_completions(prompt):
    """Test if the model can handle `v1_completions` endpoint with a simple request."""
    url = f"{BASE_URL}/v1/chat/completions"
    payload = {
        "model": MODEL_ID,
        "prompt": prompt,
        "user_id": "test_user_001",
        "document": "",
    }

    response = requests.post(url, json=payload, timeout=TIMEOUT, verify=False)
    assert response.status_code == 200, f"/v1/completions failed: expected `200`, got `{response.status_code}`"
    response = response.json()

    content = response["choices"][0]["message"]["content"].strip()
    assert len(content) > 5, f"Empty response"

    reasoning_content = response["choices"][0]["message"]["reasoning_content"].strip()
    assert len(reasoning_content) > 5, f"Empty reasoning content"



@pytest.mark.parametrize(
    "prompt,expected_nb_query",
    [
        ("Hello, could you explain the bubble sort algorithm.", 1),
        ("What is Fully Homomorphic Encryption?", 1),
        ("Why are you a secure agent ?", 2),
    ],
)
def test_vllm_proxy_endpoint_v1_chat_completions_tee_flag(prompt, expected_nb_query):
    url = f"{BASE_URL}/v1/chat/completions"
    payload = {
        "model": MODEL_ID,
        "prompt": prompt,
        "user_id": "test_user_001",
        "document": "",
    }

    response = requests.post(url, json=payload, timeout=TIMEOUT, verify=False)
    assert response.status_code == 200, f"/v1/completions failed: expected `200`, got `{response.status_code}`"
    response = response.json()

    content = response["choices"][0]["message"]["content"].strip()
    reasoning_content = response["choices"][0]["message"]["reasoning_content"].strip()
    current_nb_query = response["nb_query"]

    print(f"\n📝 Prompt:\n{prompt}")
    print(f"💬 Answer:\n{content}")
    print(f"🧠 Reasoning:\n{reasoning_content}")
    print(f"🔁 Nb_query: {current_nb_query}")

    assert len(content) > 5, "Empty response"
    assert len(reasoning_content) > 5, "Empty reasoning content"
    assert  current_nb_query == expected_nb_query, f"Expected `{expected_nb_query}`, got `{current_nb_query}`"


@pytest.mark.parametrize(
    "payload",
    [
        {"role": "user", "content": "Hello!"},
        {"model": MODEL_ID, "user_id": "user_test_01", "document": ""},
        {"model": MODEL_ID, "prompt": "hi", "document": ""},
        {"model": MODEL_ID, "prompt": "hi", "user_id": "user_test_01"},
    ],
)
def test_invalid_chat_input(payload):
    url = f"{BASE_URL}/v1/chat/completions"
    response = requests.post(url, json=payload, timeout=TIMEOUT, verify=False)
    with pytest.raises(requests.HTTPError, match=r"422.*Unprocessable*"):
        response.raise_for_status()


@pytest.mark.parametrize(
    "payload",
    [
        {
            "model": MODEL_ID,
            "prompt": "Hello! Say hi!",
            "user_id": "test_user_001",
            "document": "",
            "temperature": 0.7,
            "max_tokens": 64,
        }
    ],
)
def test_valid_chat_input(payload):
    url = f"{BASE_URL}/v1/chat/completions"
    response = requests.post(url, json=payload, timeout=TIMEOUT, verify=False)
    assert response.status_code == 200, f"Expected `200`, got `{response.status_code}`"
