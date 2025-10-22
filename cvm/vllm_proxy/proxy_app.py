import os
import time
import httpx
import logging

from fastapi import FastAPI, Request
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel

from utils import *


# Configuration
MACHINE = os.getenv("MACHINE", "H100")
IS_CVM = os.getenv("IS_CVM", "false")

# Model Configuration
MODEL_ID = os.getenv("MODEL_ID", "openai/gpt-oss-120b")
URL_BASE_VLLM = os.getenv("BASE_VLLM_URL", "http://vllm:8000")
DEFAULT_MAX_TOKENS = int(os.getenv("MAX_TOKENS", "131072"))
DEFAULT_TEMPERATURE = float(os.getenv("TEMPERATURE", "0.2"))

# Benchmarking
BENCHMARK_FILE = "benchmark_backend.csv"

# TEE Prompts
TEE_DOC = load_txt("./tee_info.txt")
TEE_INSTRUCTION = load_txt("tee_instruction_prompt.txt")
BASE_SYSTEM_CORE = load_txt("base_system_prompt.txt")
IS_TEE_RELATED_PROMPT = load_txt("is_tee_related_prompt.txt")


class ChatProxyInput(BaseModel):
    # Required
    prompt: str
    user_id: str
    document: str

    # Optional
    model_id: str = MODEL_ID
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int = DEFAULT_MAX_TOKENS


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
        "user_id",
        "date",
        "total_call_time_s",
        "call1_time_s",
        "call2_time_s",
        "model",
        "model_arguments",
        "nb_query",
    ],
    logger=logger,
    reset=False,
)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/v1/models")
async def models():
    t0 = time.perf_counter()
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=120.0)) as c:
        r = await c.get(f"{URL_BASE_VLLM}/v1/models")
    dt = time.perf_counter() - t0
    return Response(r.content, status_code=r.status_code,
                    media_type=r.headers.get("content-type"))


@app.post("/v1/chat/completions")
async def chat(body: ChatProxyInput):
    # expected : {"prompt": "...", "document": "...", "user_id": "..."}
    dt_call2 = None
    nb_query = 1
    global_t0 = time.perf_counter()

    prompt_merged = f"{body.prompt}\n\nDocument:\n{body.document}" if body.document else body.prompt

    payload1 = {
        "user_id": body.user_id,
        "model": body.model_id,
        "messages": [
            {"role": "system", "content": BASE_SYSTEM_CORE + '\n' + IS_TEE_RELATED_PROMPT},
            {"role": "user",   "content": prompt_merged}
        ],
        "extra_body": {"cache_salt": f"user:{body.user_id}"},
        "temperature": body.temperature,
        "max_tokens": body.max_tokens,
    }

    t0 = time.perf_counter()
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=120.0)) as c:
        final_r = await c.post(f"{URL_BASE_VLLM}/v1/chat/completions", json=payload1)
        dt_call1 = time.perf_counter() - t0
        r1 = final_r.json()
        content1 = r1["choices"][0]["message"]["content"].strip()
        reasoning_content1 = r1["choices"][0]["message"]["reasoning_content"].strip()

        if content1 == "<confidential chat knowledge>":
            nb_query += 1
            payload2 = {
                "user_id": body.user_id,
                "model": body.model_id,
                "messages": [
                    {"role": "system", "content": BASE_SYSTEM_CORE + '\n' + TEE_INSTRUCTION},
                    {"role": "user", "content": prompt_merged},
                ],
                "temperature": body.temperature,
                "max_tokens": body.max_tokens,
            }

            t0 = time.perf_counter()
            final_r = await c.post(f"{URL_BASE_VLLM}/v1/chat/completions", json=payload2)
            dt_call2 = time.perf_counter() - t0

            r2 = final_r.json()
            content2 = r2["choices"][0]["message"]["content"].strip()
            reasoning_content2 = r2["choices"][0]["message"]["reasoning_content"].strip()

    global_dt = time.perf_counter() - global_t0

    benchmark_logger.append({
        "is_cvm": IS_CVM,
        "machine": MACHINE,
        "user_id": body.user_id,
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_call_time_s": global_dt,
        "call1_time_s": dt_call1,
        "call2_time_s": dt_call2,
        "model": body.model_id,
        "model_arguments": f'temperature={body.temperature}, max_tokens={body.max_tokens}',
        "nb_query": nb_query,
    })

    data = final_r.json()
    data["nb_query"] = nb_query

    return Response(json.dumps(data), status_code=final_r.status_code,
                    media_type=final_r.headers.get("content-type"))


@app.get("/metrics")
async def metrics():
    async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, read=10.0)) as c:
        r = await c.get(f"{URL_BASE_VLLM}/metrics")
    return Response(r.content, status_code=r.status_code, media_type="text/plain")
