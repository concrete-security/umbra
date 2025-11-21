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
	@echo "\n\n- Running tests for prometheus and grafana..."
	@( \
		set -o allexport; \
		source .env; \
		set +o allexport; \
		uv run pytest tests/test_network.py; \
		uv run pytest tests/test_prometheus.py; \
		uv run pytest tests/test_grafana.py; \
	)

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
	@set -o allexport; source .env; set +o allexport; \
    envsubst < prometheus/prometheus.yml.template > prometheus/prometheus.yml
	@$(MAKE) docker-stop SERVICES="$(SERVICES)"
	@$(MAKE) docker-build SERVICES="$(SERVICES)" cache="$(cache)"
	@$(MAKE) docker-run  SERVICES="$(SERVICES)" ENV_FILE="$(ENV_FILE)"
	@$(MAKE) docker-logs ENV_FILE="$(ENV_FILE)"

.PHONY: single-vllm-bench
single-vllm-bench:
	@echo "Running vLLM benchmark..."
	@BENCHMARK_INPUT_DIR=${BENCHMARK_INPUT_DIR} bash $(SCRIPT) single_vllm_bench

.PHONY: bench-loop
bench-loop:
	@echo "Running benchmark loop..."
	@echo "RIN_LIST  = $(RIN_LIST)"
	@echo "ROUT_LIST = $(ROUT_LIST)"
	@echo "RPS_LIST  = $(RPS_LIST)"
	@echo "NP_LIST   = $(NP_LIST)"
	@echo "MAXSEQ    = $(MAXSEQ)"
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

.PHONY: combine-results
combine-results:
	@python3 scripts/combine_benchmarks.py --input_dir $(BENCHMARK_INPUT_DIR) --output_dir $(BENCHMARK_OUTPUT_DIR)

.PHONY: all-benchmarks
all-benchmarks:
	MAXSEQ=8 NP_LIST=100 RPS_LIST=1 RIN_LIST=100000 ROUT_LIST=1000 make bench-loop
