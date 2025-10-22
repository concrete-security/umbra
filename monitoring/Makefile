SHELL := /bin/bash

cache ?= --no-cache
ENV_FILE ?= .env
SERVICES ?= prometheus grafana
SCRIPT ?= scripts/bench_tools.sh

BENCHMARK_INPUT_DIR ?= Results_benchmarks/raw_results
BENCHMARK_OUTPUT_DIR ?= Results_benchmarks/combined_results

MACHINE ?= phala
MAXSEQ ?= 8

RIN_LIST ?= 128
ROUT_LIST ?= 128
RPS_LIST ?= 100
NP_LIST ?= 100

USE_OTHER_METRICS ?= false
VERBOSE ?= false
SAVE ?= false

.PHONY: setup
setup:
	@echo "Creating virtual environment (Python 3.12)..."
	@uv venv --python 3.12 .venv
	@uv sync --all-groups
	@echo "✅ Setup complete!"

.PHONY: tests
tests:
	@echo "\n\n- Running tests for network..."
	@uv run pytest tests/test_network.py
	@uv run pytest -vss tests/test_prometheus.py
	@uv run pytest tests/test_grafana.py

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
	@docker compose --env-file $(ENV_FILE) up -d --force-recreate --no-deps $(SERVICES)
	@echo "✅ Successfully started containers."

.PHONY: docker-logs
docker-logs:
	@echo "📜 Showing logs for all services"
	@docker compose --env-file $(ENV_FILE) logs -f

.PHONY: docker-up
docker-up:
	@clear
	@$(MAKE) docker-stop SERVICES="$(SERVICES)"
	@$(MAKE) docker-build SERVICES="$(SERVICES)" cache="$(cache)"
	@$(MAKE) docker-run  SERVICES="$(SERVICES)" ENV_FILE="$(ENV_FILE)"
	@$(MAKE) docker-logs ENV_FILE="$(ENV_FILE)"

.PHONY: gpu-metrics
gpu-metrics:
	@echo "GPU metrics monitor..."
	@BENCHMARK_INPUT_DIR=${BENCHMARK_INPUT_DIR} SAVE=true VERBOSE=true bash $(SCRIPT) gpu_metrics

.PHONY: requests-metrics
requests-metrics:
	@echo "Request metrics monitor..."
	@BENCHMARK_INPUT_DIR=${BENCHMARK_INPUT_DIR} SAVE=true VERBOSE=true bash $(SCRIPT) requests_metrics

.PHONY: single-vllm-bench
single-vllm-bench:
	@echo "Running vLLM benchmark..."
	@BENCHMARK_INPUT_DIR=${BENCHMARK_INPUT_DIR} bash $(SCRIPT) single_vllm_bench

.PHONY: bench-loop
bench-loop:
	@echo "Running benchmark loop..."
	@echo "  RIN_LIST   = $(RIN_LIST)"
	@echo "  ROUT_LIST  = $(ROUT_LIST)"
	@echo "  RPS_LIST   = $(RPS_LIST)"
	@echo "  NP_LIST    = $(NP_LIST)"
	@BENCHMARK_INPUT_DIR=$(BENCHMARK_INPUT_DIR) \
	  MACHINE=$(MACHINE) \
	  SIDE=$(SIDE) \
	  DATASET=$(DATASET) \
	  MAXSEQ=$(MAXSEQ) \
	  SAVE=$(SAVE) \
	  VERBOSE=$(VERBOSE) \
	  bash $(SCRIPT) bench_loop \
	    "$(RIN_LIST)" \
	    "$(ROUT_LIST)" \
	    "$(RPS_LIST)" \
	    "$(NP_LIST)" \
	    "$(USE_OTHER_METRICS)" \
	    "$(VERBOSE)" \
	    "$(SAVE)"

.PHONY: clear
clear:
	@echo "Clearing benchmark results in $(BENCHMARK_INPUT_DIR)..."
	@cd $(BENCHMARK_INPUT_DIR) && rm -f *.csv *.json

.PHONY: combine-results
combine-results:
	@python3 scripts/combine_benchmarks.py --input_dir $(BENCHMARK_INPUT_DIR) --output_dir $(BENCHMARK_OUTPUT_DIR)
