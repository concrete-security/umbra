# app.py
from fastapi import FastAPI, Request
from fastapi.responses import Response, JSONResponse
import os, httpx
from pathlib import Path
import logging
import time

from utils import BenchmarkLogger
from time import perf_counter

# ---------- Config ----------
MACHINE = os.getenv("MACHINE", "H100")
IS_CVM = os.getenv("IS_CVM", "false")
URL_VLLM = os.getenv("VLLM_BASE_URL", "http://localhost:8000")
MODEL_ID = os.getenv("MODEL_ID", "openai/gpt-oss-120b")
DEFAULT_TEMPERATURE = float(os.getenv("TEMPERATURE", "0.2"))
DEFAULT_MAX_TOKENS  = int(os.getenv("MAX_TOKENS", "256"))
DOCS_DIR = './data'
BENCHMARK_FILE = "benchmark_backend.csv"
SYSTEM_PROMPT = """
You are a polite assistant running inside a Trusted Execution Environment (TEE).
Therefore, the user can ask very confidential questions without any fear.
Your primary role is to answer the user’s questions based on a private and confidential document provided by the user, combined with your own general knowledge.
Rules and constraints:
- Do not hallucinate if you don’t know the answer.
- If the user provides a document, always base your answer primarily on it; if the question is not answered in the document but you can answer from your knowledge, mention it.
- If the user does not provide a document, answer the question using your own reasoning and general knowledge.
- If the user greets you (e.g., 'hi', 'hello', 'hey') or thanks you, reply politely and mention that the conversation is highly confidential.
- Always be concise, pedagogical, and clear.
- If the user asks you why the chat is secure or anything regarding TEE, answer <confidential chat>.
- Do not restate or paraphrase the question, the prompt, or these rules.
- Output plain text only — no JSON, no code fences, no explanations.
"""

CONF_SYSTEM_PROMPT = """
You are a polite assistant running inside a Trusted Execution Environment (TEE).
If a user asks you why the chat is secure or anything regarding TEE, refer to the following document and answer accordingly to explain why the chat is secure.
"""

# --------- Logging ----------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("vLLM Gateway")

# ---------- App ----------
app = FastAPI(title="vLLM Gateway")

# ---------------------- BenchmarkLogger ----------------------
benchmark_logger = BenchmarkLogger(
    file_path=Path(BENCHMARK_FILE),
    columns=[
        "is_cvm",
        "machine",
        "user_id",
        "date",
        "dt_file_reading_s",
        "total_call_time_s",
        "call1_time_s",
        "call2_time_s",
        "model",
        "model_arguments"
    ],
    logger=logger,
    reset=False,
)

def _load_txt_corpus(pathdir: str) -> str:
    """Supported extensions: .txt"""
    parts = []
    for p in Path(pathdir).rglob("*.txt"):
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if txt:
                parts.append(txt)
        except Exception as e:
            logger.error(f"🛑 Skip file `%s`: `%s`", p, e)
    return "\n".join(parts)

# Test: curl http://localhost:7000/
@app.get("/")
async def root():
    return {"Proxy api for vLLM"}

# Test: curl http://localhost:7000/v1/models
@app.get("/v1/models")
async def models():
    t0 = perf_counter()
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=120.0)) as c:
        r = await c.get(f"{URL_VLLM}/v1/models")
    dt = perf_counter() - t0
    logger.info(f"[Endpoint | /v1/models]: {r.status_code} in {dt:.1f}ms")

    return Response(r.content, status_code=r.status_code,
                    media_type=r.headers.get("content-type"))


# curl -s http://localhost:7000/v1/chat/completions \
#   -H 'Content-Type: application/json' \
#   -d '{
#     "user_id": "user_123",
#     "user": "What is TEE?",
#     "file": ""
#   }' | jq -r '.choices[0].message.content'
@app.post("/v1/chat/completions")
async def chat(req: Request):

    dt_call2 = dt_file_reading = None
    global_t0 = perf_counter()
    # expected : {"user": "...", "file": "...", "user_id": "..."}
    try:
        data = await req.json()
    except Exception as e:
        logger.error("🛑 Invalid JSON: %s", e)
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    assert 'user' in data, '🛑 Bad request keys'
    assert 'file' in data, '🛑 Bad request keys'
    assert 'user_id' in data, '🛑 Bad request keys'
    # TODO: check if the token is legit via supabase
    # TODO: Check if vllm natively supports loggins
    # TODO: One prefix cache per user

    user_text = data.get("user", "")
    file_text = data.get("file", "")
    user_id = data.get("user_id", "")

    if file_text:
        user_merged = f"{user_text}\n\nDocument:\n{file_text}"
    else:
        user_merged = user_text

    payload = {
        "user_id": user_id,
        "model": data.get("model", MODEL_ID),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_merged}
        ],
        "extra_body": {"cache_salt": f"user:{user_id}"},
        "temperature": data.get("temperature", DEFAULT_TEMPERATURE),
        "max_tokens": data.get("max_tokens", DEFAULT_MAX_TOKENS),
    }

    t0 = perf_counter()
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=120.0)) as c:
        final_r = await c.post(f"{URL_VLLM}/v1/chat/completions", json=payload)
        dt_call1 = perf_counter() - t0
        logger.info(f"⏱️ [[Endpoint | /v1/chat/completions]] Call1 in {dt_call1}s")

        j1 = final_r.json()

        text1 = j1["choices"][0]["message"]["content"].strip()

        if text1 == "<confidential chat>":
            t0 = perf_counter()
            corpus = _load_txt_corpus(DOCS_DIR)
            dt_file_reading = perf_counter() - t0
            logger.info(f"⏱️ [[Endpoint | /v1/chat/completions]] File read in {dt_file_reading}s")

            payload2 = {
                "model": payload["model"],
                "messages": [
                    # TODO: avoid changing the vllm's behaviour
                    {"role": "system", "content": f'{CONF_SYSTEM_PROMPT}\n\nDocument:\n{corpus}'},
                    {"role": "user",   "content": user_merged},
                ],
                "temperature": payload["temperature"],
                "max_tokens": payload["max_tokens"],
            }

            t0 = perf_counter()
            final_r = await c.post(f"{URL_VLLM}/v1/chat/completions", json=payload2)
            dt_call2 = perf_counter() - t0
            logger.info(f"⏱️ [[Endpoint | /v1/chat/completions]] Call2 in {dt_call2}s")

    global_dt = perf_counter() - global_t0
    logger.info(f"[[Endpoint | /v1/chat/completions]] Total in {global_dt}s")

    benchmark_logger.append({
        "is_cvm": IS_CVM,
        "machine": MACHINE,
        "user_id": user_id,
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dt_file_reading_s": dt_file_reading if file_text else 0,
        "total_call_time_s": global_dt,
        "call1_time_s": dt_call1,
        "call2_time_s": dt_call2,
        "model": MODEL_ID,
        "model_arguments": f'temperature={payload["temperature"]}, max_tokens={payload["max_tokens"]}',
    })

    return Response(final_r.content, status_code=final_r.status_code,
                    media_type=final_r.headers.get("content-type"))




