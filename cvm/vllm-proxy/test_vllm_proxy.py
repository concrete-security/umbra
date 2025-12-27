import re
import os
import pytest
import subprocess
from enum import Enum
import json

# Configuration

# External (client -> nginx -> proxy_api -> vllm)
BASE_URL = "https://localhost"
VLLM_TARGET=os.getenv("VLLM_TARGET", "vllm.concrete-security.com")
SCHEME=os.getenv("SCHEME", "https")
REMOTE_VLLM_URL = f"{SCHEME}://{VLLM_TARGET}"

# Internal (docker network)
CONTAINER_VLLM_URL = os.getenv("CONTAINER_VLLM_URL", "http://vllm:8000")
CONTAINER_PROXY_URL = os.getenv("CONTAINER_PROXY_URL", "http://proxy-api:7000")

MODEL_ID = os.getenv("MODEL_ID", "openai/gpt-oss-120b")
TIMEOUT = 10

VLLM_METRICS_AUTH_TOKEN = os.getenv("VLLM_METRICS_AUTH_TOKEN")
AUTH_HEADER = f"Authorization: Bearer {VLLM_METRICS_AUTH_TOKEN}"


class Container(Enum):
    VLLM = ("vllm", CONTAINER_VLLM_URL)
    PROXY = ("proxy-api", CONTAINER_PROXY_URL)
    HTTP_NGINX_TO_PROXY = ("nginx-cert-manager", CONTAINER_PROXY_URL)
    HTTP_NGINX_TO_VLLM = ("nginx-cert-manager", CONTAINER_VLLM_URL)
    HTTPS_NGINX = ("nginx-cert-manager", "-k https://localhost")

    def __init__(self, container_name, url):
        self.container_name = container_name
        self.url = url


def assert_metrics_output(out: str) -> None:
    """Validate that the output string follows the Prometheus metrics format.

    Args:
        out (str): The raw text response from the /metrics endpoint.

    Raises:
        AssertionError: If the output is empty or lacks standard Prometheus headers.
    """
    assert out.strip(), "Empty metrics output"
    lower = out.lower()
    assert "# help" in lower or "# type" in lower or "process_" in lower, (
        "Output does not look like Prometheus metrics.\n"
        f"Got:\n{out[:800]}"
    )


def assert_models_output(out) -> None:
    """Verify that the models endpoint returns the correct model metadata.

    Raises:
        AssertionError: If the expected MODEL_ID is missing or the format is invalid.
    """
    out = json.loads(out)
    assert "data" in out, "Missing 'data' field in response"
    assert isinstance(out["data"], list), "'data' is not a list"
    assert out["data"][0]["id"] == MODEL_ID, f"Model ID '{MODEL_ID}' not found in available models"


def assert_chat_completion_output(out: str, expected_output: str) -> None:
    """Validate the output format.

    Args:
        out (str): Raw JSON response from /v1/chat/completions.
        expected_output (str): The text expected in the assistant's message.

    Raises:
        AssertionError: If JSON structure, content, or reasoning blocks are missing.
    """

    try:
        payload = json.loads(out)
    except json.JSONDecodeError as e:
        raise AssertionError(f"`/v1/chat/completions` did not return valid JSON:\n{out[:800]}") from e

    assert isinstance(payload, dict), f"Payload is not a dict: `{type(payload)}`"
    assert payload.get("object") == "chat.completion", "Missing 'object' field"
    assert isinstance(payload.get("choices"), list) and len(payload["choices"]) > 0, "Empty choices list"

    msg = payload["choices"][0].get("message")
    assert isinstance(msg, dict), "Missing 'message' in first choice"

    content = msg.get("content") or msg.get("reasoning_content")
    assert isinstance(content, str) and content.strip(), "Missing assistant output text"

    # Check expected output
    assert content.strip().lower() == expected_output.lower(), (
        f"Expected `{expected_output}`, got `{content}`"
    )

    assert msg["content"] == expected_output, "`Content` not in first choice message"
    reasoning, reasoning_content = msg.get("reasoning"), msg.get("reasoning_content")

    assert isinstance(reasoning, str) and reasoning.strip(), "Missing reasoning text"
    assert isinstance(reasoning_content, str) and reasoning_content.strip(), "Missing reasoning content text"


def assert_responses_output(out: str, expected_output: str) -> None:
    """Validate the output format.

    Args:
        out (str): Raw JSON response from /v1/responses.
        expected_output (str): The text expected in the message block.

    Raises:
        AssertionError: If the output format, reasoning, or content text is invalid.
    """
    try:
        payload = json.loads(out)
    except json.JSONDecodeError as e:
        raise AssertionError(f"`/v1/response` did not return valid JSON:\n{out[:800]}") from e

    assert isinstance(payload, dict), f"Payload is not a dict: `{type(payload)}`"
    assert "object" in payload and payload["object"] == "response", "Missing 'object' field"
    assert "output" in payload, "Missing 'output' field"
    assert isinstance(payload["output"], list) and len(payload["output"]) > 0, "Empty 'output' list"

    # Reasoning block
    reasoning_block = next(
        (item for item in payload["output"] if item.get("type") == "reasoning"),
        None
    )
    assert reasoning_block is not None, "Missing reasoning block"
    assert isinstance(reasoning_block["content"], list) and len(reasoning_block["content"]) > 0, "Invalid 'content' in reasoning block"
    reasoning_text = reasoning_block["content"][0]["text"]
    assert isinstance(reasoning_text, str) and len(reasoning_text.strip()) > 5, "Invalid reasoning text"

    # Message block
    message_block = next(
        (
            item for item in payload["output"]
            if item.get("type") == "message" and item.get("role") == "assistant"
        ),
        None
    )
    assert message_block is not None, "Missing message block"
    assert isinstance(message_block["content"], list) and len(message_block["content"]) > 0, "Invalid message content"
    content = message_block["content"][0]
    assert "text" in content and len(content["text"]) > 1, "Missing 'text' in message block"
    assert content["type"] == "output_text", "Missing 'type' in message block"
    assert content["text"].strip().lower() == expected_output.lower(), (
        f"Expected `{expected_output}`, got `{content['text']}`"
    )


def _exec(source_key, endpoint, data=None, use_auth=False, use_header=False):
    """Execute a curl command either locally or inside a specific Docker container.

    Args:
        source_key (str): The Container name.
        endpoint (str): The API path to target.
        data (Optional[dict]): Payload to be sent as JSON.
        use_auth (bool): Whether to include the Bearer token in headers.
        use_header (bool): Whether to include HTTP response headers in the output (-i).

    Returns:
        str: The standard output of the curl command.

    Raises:
        RuntimeError: If the curl command returns a non-zero exit code or HTTP error.
    """

    # 1) External: client -> Nginx (HTTPS) -> Proxy -> vLLM
    # Authentification required for /metrics endpoint only
    if source_key == "external":
        cmd = ["curl",  f"{REMOTE_VLLM_URL}{endpoint}"]
        if use_header:
            cmd += ["-i"]
        if use_auth:
            cmd += ["-H", AUTH_HEADER]
        if data:
            cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(data)]

        print(f"{source_key=}: {cmd=}")

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"External curl failed: {result.stderr or result.stdout}")
        return result.stdout
    # Internal docker networking
    else:
        container = getattr(Container, source_key)
        cmd = f"curl -sSf {container.url}{endpoint}"

        if use_header:
            cmd += " -i"
        if use_auth:
            cmd += f" -H '{AUTH_HEADER}'"
        if data:
            cmd += f" -H 'Content-Type: application/json' -d '{json.dumps(data)}'"

        docker_cmd = ["docker", "exec", container.container_name, "sh", "-c", cmd]

        result = subprocess.run(docker_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"❌ Command failed in `{container.container_name}`:\n"
                f"`{cmd}`\n\n"
                f"STDOUT:\n{result.stdout.strip()}\n\n"
                f"STDERR:\n{result.stderr.strip()}"
            )

        return result.stdout.strip()


@pytest.mark.parametrize("endpoint,assert_function", [
    ("/metrics", assert_metrics_output),
    ("/v1/models", assert_models_output),
])
def test_success_network_flow_to_vllm_endpoints(endpoint, assert_function):
    """Verify end-to-end connectivity across Nginx, Proxy, and vLLM.

    Checks if endpoints are reachable via external HTTPS, internal HTTP between containers.
    """
    print(f"\nTesting `{endpoint}` endpoint:")

    auth = (endpoint == "/metrics")

    # 1) External: client -> Nginx (HTTPS) -> Proxy -> vLLM
    # Authentification required for /metrics endpoint only
    assert_function(_exec('external', endpoint, data=None, use_auth=auth))

    # 2) Internal docker networking

    # Case 2.1: Proxy API container > vLLM container
    # Source: Inside proxy-api container
    # Destination: vllm service on the "vllm" docker network
    #
    # HTTP: because there is no TLS (no certificates).
    #
    # What this verifies:
    #   - proxy_api and vllm share the same docker network ("vllm")
    #   - proxy_api can reach vllm directly
    assert_function(_exec("PROXY", endpoint))

    # Case 2.2: nginx-cert-manager (as internal service) > proxy_api (HTTP Internal)
    # Source: Inside nginx-cert-manager container
    # Destination: proxy_api service on the "proxy_api" docker network
    #
    # HTTP: because there is no TLS (no certificates).
    #
    # What this verifies:
    #   - nginx-cert-manager and proxy_api share the docker network ("proxy_api")
    #   - nginx container can talk to proxy_api directly
    assert_function(_exec("HTTP_NGINX_TO_PROXY", endpoint))

    # Case 2.3: Nginx routes correctly (nginx -> proxy -> vllm)
    # Source: Inside nginx-cert-manager container
    # Destination: nginx itself (same container) via localhost
    #
    # HTTPS:
    #   Because we are explicitly testing nginx's HTTPS endpoint.
    #   Nginx speaks HTTPS (TLS) locally, and then forwards to proxy_api via HTTP.
    #
    # What this verifies:
    #   - nginx is actually listening on HTTPS inside the container
    #   - nginx forwards /metrics requests to proxy_api correctly
    #
    # The -k option allows Curl to make an "insecure" SSL connection and skip SSL certificate checks
    # while you still have an SSL-encrypted connection
    assert_function(_exec("HTTPS_NGINX", endpoint))


@pytest.mark.parametrize("endpoint", [
    ("/metrics"),
    ("/v1/models"),
    ("/v1/chat/completions"),
    ("/v1/response"),
])
def test_reject_network_flow_to_vllm_endpoints(endpoint):
    """Ensure Nginx cannot bypass the Proxy to reach vLLM directly."""
    with pytest.raises(RuntimeError, match=r"curl:.*Could not resolve host:\s*vllm"):
        _exec("HTTP_NGINX_TO_VLLM", endpoint)


@pytest.mark.parametrize("endpoint,input_data,assert_function", [
    (
        "/v1/chat/completions",
        {
            "messages": [
                {"role": "user", "content": "Say 'pong' and nothing else."}
            ],
        },
        assert_chat_completion_output,
    ),
    (
        "/v1/responses",
        {
            "input": "Say 'pong' and nothing else.",
        },
        assert_responses_output,
    ),
])
def test_base_vllm_engine_compliant_input_format(endpoint, input_data, assert_function):
    """Test the base vLLM backend using its native input schemas."""
    print(f"\nTesting base vllm `{endpoint}` endpoint:")

    # Base payload shared by both endpoints
    payload = {
        "model": MODEL_ID,
        "temperature": 0,
        "stream": False,
        **input_data,
    }

    # 1) Test External Access: client -> nginx (HTTPS) -> proxy -> vLLM
    assert_function(_exec("external", endpoint, data=payload), "pong")

    # 2)  Test Internal Access (Proxy -> vLLM) with HTTP
    assert_function(_exec("VLLM", endpoint, data=payload), "pong")


@pytest.mark.parametrize("endpoint,payload,assert_function", [
(
        "/v1/chat/completions",
        {
            "prompt": "Say 'pong' and nothing else.",
            "user_id": "test_user_123",
            "document": "No document.",
        },
        assert_chat_completion_output,
    ),
    (
        "/v1/responses",
        {
            "prompt": "Say 'pong' and nothing else.",
            "user_id": "test_user_123",
            "document": "No document.",
        },
        assert_responses_output,
    ),
])
def test_proxy_api_engine_compliant_input_format(endpoint, payload, assert_function):
    """Test the Proxy-API using its custom input format.

    Verifies that the proxy correctly accepts 'prompt', 'user_id', and 'document'.
    """
    print(f"\nTesting proxy_api `{endpoint}` endpoint:")

    # Test internal access: nginx container -> proxy_api (HTTP)
    assert_function(_exec("PROXY", endpoint, data=payload), "pong")

    # Test internal access: nginx routes correctly via its HTTPS endpoint
    assert_function(_exec("HTTPS_NGINX", endpoint, data=payload), "pong")


@pytest.mark.parametrize("endpoint,payload", [
    (
        "/v1/chat/completions",
        {
            "messages": [
                {"role": "user", "content": "Say 'pong' and nothing else."}
            ],
        },
    ),
    (
        "/v1/responses",
        {
            "input": "Say 'pong' and nothing else.",
        },
    ),
])
def test_proxy_api_engine_invalid_input_format(endpoint, payload):
    """Ensure the Proxy-API rejects native vLLM formats with a 422 error."""

    print(f"\nTesting proxy_api `{endpoint}` endpoint:")

    # Test internal access: nginx container -> proxy_api (HTTP)
    with pytest.raises(RuntimeError, match=r"The requested URL returned error: 422"):
        _exec("PROXY", endpoint, data=payload)

    # Test internal access: nginx routes correctly via its HTTPS endpoint
    with pytest.raises(RuntimeError, match=r"The requested URL returned error: 422"):
        _exec("HTTPS_NGINX", endpoint, data=payload)


@pytest.mark.parametrize("source", ["PROXY", "HTTPS_NGINX"])
@pytest.mark.parametrize("endpoint", ["/v1/chat/completions", "/v1/responses"])
@pytest.mark.parametrize("payload, is_tee_related_query", [
    (
        {
            "prompt": "Hello, explain what is Fully Homomorphic Encryption in only 1 sentences?",
            "user_id": "test_user_123",
            "document": "No document.",
        },
        "false",
    ),
    (
        {
            "prompt": "Hello, explain what is TEE in only 1 sentences?",
            "user_id": "test_user_124",
            "document": "No document.",
        },
        "true",
    ),
])
def test_proxy_api_engine_for_tee_related_queries(source, endpoint, payload, is_tee_related_query):
    """Validate TEE intent detection via custom HTTP headers.

    Checks if the Proxy-API correctly identifies queries about security/TEE
    and sets the 'X-TEE-Intent' header accordingly.
    """

    out = _exec(source, endpoint, data=payload, use_header=True)

    # Looking for "x-tee-intent: true" ou "x-tee-intent: false" in the header
    pattern = rf"x-tee-intent:\s*{is_tee_related_query}"
    match = re.search(pattern, out, re.IGNORECASE)

    assert match, f"Expected header `{pattern}` not found in output: `{out}`"
