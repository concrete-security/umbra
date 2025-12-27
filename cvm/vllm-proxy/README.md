# vLLM Backend

The backend consists of two tightly services:

- **Base vLLM Server** — the core inference engine exposing an **OpenAI-compatible Chat Completions API**.
- **FastAPI Proxy** — a lightweight intermediary that routes client requests to the base vLLM server. It adds **Retrieval-Augmented Generation (RAG)** logic to enhance the user experience, particularly to explain why the chat is secure.

Both components run inside a **Trusted Execution Environment (TEE)**, ensuring all interactions remain confidential and privacy-preserving.

## API Endpoints

- Provides the following endpoints:
  - `GET /health`: Service health check.
  - `GET /v1/models`: Returns available model IDs.
  - `POST /v1/chat/completions`: Proxy endpoint compatible with OpenAI’s Chat API + RAG.
  - `GET /metrics`: Exposes vLLM metrics.

## Requirements

This service uses [uv](https://docs.astral.sh/uv/) for Python dependency management and virtual environment management. `uv` provides fast, reliable package resolution and installation.

## Usage

See the `Makefile` for common operations:

- `make setup`: Install dependencies and sync the environment using `uv`.
- `make tests`:  Run all tests with `pytest`.
- `make docker-build`: Build Docker images.
- `make docker-run`: Start the service containers.
- `make docker-stop`: Stop and remove running containers.
- `make docker-logs`:  Stream logs from all containers.
- `make docker-up`: Rebuild, restart, and tail logs in one step.
