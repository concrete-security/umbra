import os
import time
import httpx
import logging

from fastapi import FastAPI
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Any, Dict, Optional, Literal, Tuple

from utils import *


# Configuration
MACHINE = os.getenv("MACHINE")
IS_CVM = os.getenv("IS_CVM", "false")
PROMPT_DIR = Path(os.getenv("PROMPT_DIR", "./prompts"))

# Model Configuration
DEFAULT_MODEL_ID = os.getenv("MODEL_ID")
DEFAULT_MAX_TOKENS = int(os.getenv("MAX_TOKENS", "131072"))
DEFAULT_TEMPERATURE = float(os.getenv("TEMPERATURE", "0.2"))
LOCAL_URL_BASE_VLLM = "http://vllm:8000"

# Benchmarking
BENCHMARK_FILE = "benchmark_vllm_proxy_backend.csv"

# TEE Prompts
TEE_DOC = load_txt("tee_info.txt")
TEE_INSTRUCTION = load_txt("tee_instruction_prompt.txt")
BASE_SYSTEM_CORE = load_txt("base_system_prompt.txt")
BASE_INSRUCTIONS = load_txt("base_instructions_prompt.txt")
IS_TEE_RELATED_PROMPT = load_txt("is_tee_related_prompt.txt")
BASIC_SCOPE_PROMPT = load_txt("basic_scope_prompt.txt")


# Logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("vLLM Gateway")

# App
app = FastAPI(title="vLLM Gateway")

# BenchmarkLogger
benchmark_logger = BenchmarkLogger(
    file_path=Path(BENCHMARK_FILE),
    columns=[
        "is_cvm",
        "machine",
        "date",
        "total_call_time_s",
        "call1_time_s",
        "call2_time_s",
        "model",
        "model_arguments",
        "asked_about_tee",
        "route"
    ],
    logger=logger,
    reset=False,
)


VLLMRoute = Literal["chat/completions", "responses"]


def _build_vllm_payload(
    *,
    route: VLLMRoute,
    payload: Any,
    system_prompt: str,
) -> Dict[str, Any]:
    """Construct the JSON payload for vLLM based on the target route.


    The model parameters and system prompts are hardcoded at the backend level.
    Args:
        route (VLLMRoute): Target vLLM endpoint either "chat/completions" or "responses".
        payload (Any): Input object.
        system_prompt (str): System instructions to inject.

    Returns:
        Dict[str, Any]: A dictionary ready for the vLLM POST request.

    Raises:
        ValueError: If the route is not supported.
    """

    if route == "chat/completions":
        assert "messages" in payload
        payload["messages"] = [
            {"role": "system", "content": system_prompt}
        ] + payload["messages"]

    elif route == "responses":
        payload.update({
                "instructions": system_prompt,
                "input": f"[SYSTEM RULE: {system_prompt}]\n\nUser Question: {payload['input']}"
            })

    else:
        raise ValueError(f"Unsupported route: `{route}`")

    return payload


async def _forward_to_vllm(
    route: VLLMRoute,
    payload: Dict[str, Any],
    client: httpx.AsyncClient,
) -> Tuple[httpx.Response, float]:
    """Execute the asynchronous POST request to the local vLLM instance.

    Args:
        route (VLLMRoute): Target vLLM endpoint either "chat/completions" or "responses".
        payload (Dict[str, Any]): The request body.
        client (httpx.AsyncClient): The HTTP client to use.

    Returns:
        Tuple[httpx.Response, float]: The raw response and the execution time in seconds.
    """
    t0 = time.perf_counter()
    raw_response = await client.post(f"{LOCAL_URL_BASE_VLLM}/v1/{route}", json=payload)
    dt = time.perf_counter() - t0
    return raw_response, dt


def _extract_content_and_reasoning(route: VLLMRoute, json_data: Dict[str, Any]) -> Tuple[str, str]:
    """Retrieve the assistant's text and reasoning from the vllm response.

    Args:
        route (VLLMRoute): Target vLLM endpoint either "chat/completions" or "responses".
        json_data (Dict[str, Any]): Raw JSON data from vLLM.

    Returns:
        Tuple[str, str]: The extracted content and reasoning strings.

    Raises:
        ValueError: For unsupported routes.
        AssertionError: If response fields are missing or null.
    """
    if route == "chat/completions":
        assert "choices" in json_data
        choices = json_data.get("choices")
        assert isinstance(choices, list) and len(choices) > 0
        assert "message" in choices[0]
        message = choices[0].get("message", {})
        assert isinstance(message, Dict)
        content = message.get("content", None)
        reasoning = message.get("reasoning_content", None)
    # json_data.get("choices", [{}])[0].get("message", {}).get("content", None),
    # json_data.get("choices", [{}])[0].get("message", {}).get("reasoning_content", None)

    elif route == "responses":

        reasoning_block = next(
            (item for item in json_data["output"] if item.get("type") == "reasoning"),
            None
        )
        message_block = next(
            (
                item for item in json_data["output"]
                if item.get("type") == "message" and item.get("role") == "assistant"
            ),
            None
        )
        assert message_block is not None
        assert "content" in message_block
        assert isinstance(message_block.get("content"), list)
        assert "text" in message_block["content"][0]
        assert reasoning_block is not None
        assert "content" in reasoning_block
        assert isinstance(reasoning_block.get("content"), list)
        assert "text" in reasoning_block["content"][0]
        content = message_block["content"][0]['text']
        reasoning = reasoning_block["content"][0]["text"]
    else:
        raise ValueError(f"Unsupported route: `{route}`")

    assert content is not None, "`Content` is None, you may increase the --max-model-len parameter."
    assert reasoning is not None, "`Reasoning` is None, you may increase the --max-model-len parameter."

    return  content, reasoning


async def proxy_logic(route: VLLMRoute, body: Any) -> Response:
    """Route requests to vLLM and inject TEE explanations if triggered.

    Args:
        route (VLLMRoute): Target vLLM endpoint either "chat/completions" or "responses".
        body (Any): Input data.
    Returns:
        Response: FastAPI response with vLLM output and 'X-TEE-Intent' header.

    Raises:
        httpx.HTTPError: If the vLLM backend is unreachable.
        AssertionError: If the model response structure is invalid.
    """
    dt_call1 = dt_call2 = 0.0
    global_t0 = time.perf_counter()

    payload = _build_vllm_payload(
        route=route,
        payload=body,
        system_prompt=BASE_SYSTEM_CORE + "\n" + IS_TEE_RELATED_PROMPT +  "\n" + BASIC_SCOPE_PROMPT + "\n" + BASE_INSRUCTIONS + "\n",
    )

    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=120.0)) as c:
        raw_response, dt_call1 = await _forward_to_vllm(route, payload, c)

    logger.info(f"1. {raw_response=}")
    logger.info(f"2. {raw_response.json()=}")

    content, reasoning = _extract_content_and_reasoning(route=route, json_data=raw_response.json())

    asked_about_tee: bool = content.strip() == "<confidential chat knowledge>"

    if asked_about_tee:
        logger.info("🎁 TEE related query")
        payload = _build_vllm_payload(
            route=route,
            payload=body,
            system_prompt=BASE_SYSTEM_CORE + "\n" + TEE_INSTRUCTION +  "\n" + TEE_DOC + "\n" + BASE_INSRUCTIONS + "\n",
        )

        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=120.0)) as c:
            raw_response, dt_call2 = await _forward_to_vllm(route, payload, c)

        content, reasoning = _extract_content_and_reasoning(route=route, json_data=raw_response.json())

    global_dt = time.perf_counter() - global_t0
    benchmark_logger.append(
        {
            "is_cvm": IS_CVM,
            "machine": MACHINE,
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_call_time_s": global_dt,
            "call1_time_s": dt_call1,
            "call2_time_s": dt_call2,
            "model": DEFAULT_MODEL_ID,
            "model_arguments": f"temperature={DEFAULT_TEMPERATURE}, max_tokens={DEFAULT_MAX_TOKENS}",
            "asked_about_tee": asked_about_tee,
            "route": route,
        }
    )

    logger.info(f"{route=} - completed in {global_dt}s")
    logger.info(f"👉 {content=}")
    logger.info(f"🧠 {reasoning=}")

    return Response(
        content=raw_response.content,
        status_code=raw_response.status_code,
        media_type=raw_response.headers.get("content-type", "application/json"),
        headers={"X-TEE-Intent": "true" if asked_about_tee else "false"},
    )


@app.post("/v1/chat/completions")
async def chat_endpoint(body: Dict[str, Any]):
    return await proxy_logic("chat/completions", body)


@app.post("/v1/responses")
async def responses_endpoint(body: Dict[str, Any]):
    return await proxy_logic("responses", body)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/v1/models")
async def models():
    t0 = time.perf_counter()
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=120.0)) as c:
        r = await c.get(f"{LOCAL_URL_BASE_VLLM}/v1/models")
    dt = time.perf_counter() - t0
    return Response(r.content, status_code=r.status_code,
                    media_type=r.headers.get("content-type"))


@app.get("/metrics")
async def metrics():
    async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, read=10.0)) as c:
        r = await c.get(f"{LOCAL_URL_BASE_VLLM}/metrics")
    return Response(r.content, status_code=r.status_code, media_type="text/plain")
