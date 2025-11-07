SHELL := /bin/bash

# Usage:
#   make docker-run
#   make docker-run cache=--no-cache
cache ?= --no-cache
# Environment mode: dev | staging | prod
MODE ?= dev
SERVICES ?= proxy_api prometheus grafana vllm
VLLM_URL ?= http://localhost:8000/v1
RPS ?= 30
NREQ ?= 500
MAX_OUT ?= 256
MODEL = openai/gpt-oss-120b

.PHONY: setup
setup:
	@echo "- Setting up environment using uv..."
	@uv sync --all-groups
	@echo "✅ Setup complete!"

.PHONY: tests
tests:
	@echo "- Running tests from cvm/vllm_proxy..."
	@uv run pytest ../test_vllm_proxy.py
	@echo "\n\n- Running tests for network..."
	@uv run pytest ../test_network.py
	@echo "\n\n- Running tests for prometheus..."
	@uv run pytest -svvx ../test_prometheus.py
	@echo "\n\n- Running tests for grafana..."
	@uv run pytest ../test_grafana.py

.PHONY: docker-build
docker-build:
	@echo "🏗️ Building images for: $(SERVICES)"
	@docker compose build $(cache) $(SERVICES)
	@echo "✅ Successfully built images."

.PHONY: docker-stop
docker-stop:
	@echo "🛑 Stopping & removing: $(SERVICES)"
	@docker compose stop $(SERVICES) || true
	@docker compose rm -f -v $(SERVICES) || true
	@echo "✅ Successfully stopped and removed containers."

.PHONY: docker-run
docker-run:
	@echo "🚀 Starting: $(SERVICES)"
	@docker compose up -d --force-recreate --no-deps $(SERVICES)
	@echo "✅ Successfully started containers."

.PHONY: docker-logs
docker-logs:
	@echo "📜 Showing logs for all services"
	@docker compose logs -f

.PHONY: docker-up
docker-up:
	@$(MAKE) docker-stop SERVICES="$(SERVICES)"
	@$(MAKE) docker-build SERVICES="$(SERVICES)" cache="$(cache)"
	@$(MAKE) docker-run SERVICES="$(SERVICES)"
	@$(MAKE) docker-logs

.PHONY: bench
bench:
	@echo "🚀 Running vLLM bench..."
	@set -Eeuo pipefail; \
	uv run --group bench --active -- vllm bench serve \
		--backend openai-chat \
		--base-url http://localhost:8000 \
		--endpoint /v1/chat/completions \
		--model openai/gpt-oss-120b \
		--dataset-name random \
		--random-input-len 512 \
		--random-output-len 128 \
		--request-rate 8 \
		--num-prompts 500

.PHONY: watch-gpu
watch-gpu:
	@watch -n1 -- nvidia-smi \
		--query-gpu=index,name,utilization.gpu,utilization.memory,memory.used,memory.total --format=csv,noheader

# watch -n1 'nvidia-smi --query-gpu=index,name,utilization.gpu,utilization.memory,memory.used,memory.total --format=csv,noheader'

.PHONY: watch-requests
watch-requests:
	@watch -n1 -- bash -c "curl -s http://localhost:8000/metrics | awk -F' ' '/^vllm:num_requests_running/ {run=\$$NF} /^vllm:num_requests_waiting/ {wait=\$$NF} /cache.*usage|kv.*cache.*usage/ {kv=\$$NF} END { if (kv==\"\") kv=\"NA\"; printf(\"running=%s  waiting=%s  kv_cache=%s\n\", run, wait, kv) }'"

# curl -s http://localhost:8000/metrics \
# | awk -F" " "
# /^vllm:num_requests_running/ {run=\$NF}
# /^vllm:num_requests_waiting/ {wait=\$NF}
# /cache.*usage|kv.*cache.*usage/ {kv=\$NF}
# END { if (kv==\"\") kv=\"NA\"; printf(\"running=%s  waiting=%s  kv_cache=%s\n\", run, wait, kv) }"'
