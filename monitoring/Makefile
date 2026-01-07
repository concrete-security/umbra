SHELL := /bin/bash

cache ?= --no-cache
ENV_FILE ?= .env
SERVICES ?= prometheus grafana
SCRIPT ?= scripts/bench_tools.sh

BENCHMARK_INPUT_DIR ?= Results_benchmarks/raw_results
BENCHMARK_OUTPUT_DIR ?= Results_benchmarks/combined_results

MACHINE ?= Phala-H200
MAXSEQ ?= 8
SCHEME ?= http
VLLM_TARGET ?= 89.169.96.185
RUNTIME ?= CVM
SIDE ?= client
DATASET ?= random
VLLM_ENDPOINT ?= /v1/chat/completions

RIN_LIST ?= 128
ROUT_LIST ?= 128
RPS_LIST ?= 100
NP_LIST ?= 100

USE_OTHER_METRICS ?= false
VERBOSE ?= false
SAVE ?= false

# We use a 2-step process to manage sensitive configuration:
# - TEMPLATING: Store secrets in .env; inject them into *.template files.
# - WHITELISTING: Only variables in PROMETHEUS/GRAFANA_VARS are replaced.
#    This protects internal Grafana/Prometheus vars (e.g., $$job, $$datasource).
# - LIFECYCLE: Config files are generated on 'build' and deleted on 'stop'.
GRAFANA_VARS := '$${VLLM_SCRAPE_JOB_NAME}$${GRAFANA_DATASOURCE_UID}'
PROMETHEUS_VARS := '$${SCHEME}$${VLLM_TARGET}$${VLLM_METRICS_AUTH_TOKEN}'


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

.PHONY: prometheus-conf
prometheus-conf:
	@set -o allexport; source $(ENV_FILE); set +o allexport; \ && \
    envsubst $(PROMETHEUS_VARS) < prometheus/prometheus.yml.template > prometheus/prometheus.yml

.PHONY: grafana-conf
grafana-conf:
	@set -o allexport; source $(ENV_FILE); set +o allexport; \
	envsubst $(GRAFANA_VARS) < grafana/provisioning/dashboards/user_metrics_overview.json.template > grafana/provisioning/dashboards/user_metrics_overview.json && \
	envsubst $(GRAFANA_VARS) < grafana/provisioning/dashboards/machine_metrics_overview.json.template > grafana/provisioning/dashboards/machine_metrics_overview.json && \
	envsubst $(GRAFANA_VARS) < grafana/provisioning/dashboards/vllm_tokens.json.template > grafana/provisioning/dashboards/vllm_tokens.json

.PHONY: docker-build
docker-build:
	@echo "🏗️ Building images for: $(SERVICES)"
	@$(MAKE) prometheus-conf
	@$(MAKE) grafana-conf
	@docker compose build $(cache) $(SERVICES)
	@echo "✅ Successfully built images."

.PHONY: docker-stop
docker-stop:
	@echo "🛑 Stopping & removing: $(SERVICES)"
	@docker compose stop $(SERVICES) || true
	@docker compose rm -f -v $(SERVICES) || true
	@rm -f grafana/provisioning/dashboards/user_metrics_overview.json
	@rm -f grafana/provisioning/dashboards/machine_metrics_overview.json
	@rm -f prometheus/prometheus.yml
	@echo "✅ Successfully stopped and removed containers."

.PHONY: docker-run
docker-run:
	@echo "🚀 Starting: $(SERVICES)"
	@docker compose --env-file $(ENV_FILE) up -d --force-recreate --no-deps $(SERVICES)
	@echo "✅ Successfully started containers."

.PHONY: docker-logs
docker-logs:
	@echo "📜 Showing logs for all services"
	@docker compose --env-file $(ENV_FILE) logs -f $(SERVICES)

.PHONY: docker-up
docker-up:
	@$(MAKE) docker-stop SERVICES="$(SERVICES)"
	@$(MAKE) docker-build SERVICES="$(SERVICES)" cache="$(cache)"
	@$(MAKE) docker-run  SERVICES="$(SERVICES)" ENV_FILE="$(ENV_FILE)"
	@$(MAKE) docker-logs ENV_FILE="$(ENV_FILE)"

.PHONY: single-vllm-bench
single-vllm-bench:
	@echo "Running vLLM benchmark..."
	@BENCHMARK_INPUT_DIR=$(BENCHMARK_INPUT_DIR) \
	  SCHEME=$(SCHEME) \
	  VLLM_TARGET=$(VLLM_TARGET) \
	  VLLM_ENDPOINT=$(VLLM_ENDPOINT) \
	  MACHINE=$(MACHINE) \
	  RUNTIME=$(RUNTIME) \
	  SIDE=$(SIDE) \
	  DATASET=$(DATASET) \
	  MAXSEQ=$(MAXSEQ) \
	  bash $(SCRIPT) single_vllm_bench

.PHONY: bench-loop
bench-loop:
	@echo "Running benchmark loop..."
	@echo "RIN_LIST  = $(RIN_LIST)"
	@echo "ROUT_LIST = $(ROUT_LIST)"
	@echo "RPS_LIST  = $(RPS_LIST)"
	@echo "NP_LIST   = $(NP_LIST)"
	@echo "MAXSEQ    = $(MAXSEQ)"
	@BENCHMARK_INPUT_DIR=$(BENCHMARK_INPUT_DIR) \
	  SCHEME=$(SCHEME) \
	  VLLM_TARGET=$(VLLM_TARGET) \
	  VLLM_ENDPOINT=$(VLLM_ENDPOINT) \
	  MACHINE=$(MACHINE) \
	  RUNTIME=$(RUNTIME) \
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

	VLLM_ENDPOINT=/v1/chat/completions MACHINE=Phala-H200 SCHEME=http VLLM_TARGET=89.169.96.185 RUNTIME=VM \
	MAXSEQ=8 NP_LIST=100 RPS_LIST=1 RIN_LIST=4096 ROUT_LIST=1024 make bench-loop
	VLLM_ENDPOINT=/v1/chat/completions MACHINE=Phala-H200 SCHEME=https VLLM_TARGET=vllm.concrete-security.com RUNTIME=CVM \
	MAXSEQ=8 NP_LIST=100 RPS_LIST=1 RIN_LIST=4096 ROUT_LIST=1024 make bench-loop

	VLLM_ENDPOINT=/v1/chat/completions MACHINE=Phala-H200 SCHEME=http VLLM_TARGET=89.169.96.185 RUNTIME=VM \
	MAXSEQ=8 NP_LIST=100 RPS_LIST=1 RIN_LIST=1000 ROUT_LIST=500 make bench-loop
	VLLM_ENDPOINT=/v1/chat/completions MACHINE=Phala-H200 SCHEME=https VLLM_TARGET=vllm.concrete-security.com RUNTIME=CVM \
	MAXSEQ=8 NP_LIST=100 RPS_LIST=1 RIN_LIST=1000 ROUT_LIST=500 make bench-loop

	VLLM_ENDPOINT=/v1/chat/completions MACHINE=Phala-H200 SCHEME=http VLLM_TARGET=89.169.96.185 RUNTIME=VM \
	MAXSEQ=8 NP_LIST=100 RPS_LIST=16 RIN_LIST=512 ROUT_LIST=256 make bench-loop
	VLLM_ENDPOINT=/v1/chat/completions MACHINE=Phala-H200 SCHEME=https VLLM_TARGET=vllm.concrete-security.com RUNTIME=CVM \
	MAXSEQ=8 NP_LIST=100 RPS_LIST=16 RIN_LIST=512 ROUT_LIST=256 make bench-loop

	VLLM_ENDPOINT=/v1/chat/completions MACHINE=Phala-H200 SCHEME=http VLLM_TARGET=89.169.96.185 RUNTIME=VM \
	MAXSEQ=8 NP_LIST=100 RPS_LIST=16 RIN_LIST=4096 ROUT_LIST=1024 make bench-loop
	VLLM_ENDPOINT=/v1/chat/completions MACHINE=Phala-H200 SCHEME=https VLLM_TARGET=vllm.concrete-security.com RUNTIME=CVM \
	MAXSEQ=8 NP_LIST=100 RPS_LIST=16 RIN_LIST=4096 ROUT_LIST=1024 make bench-loop

	VLLM_ENDPOINT=/v1/chat/completions MACHINE=Phala-H200 SCHEME=http VLLM_TARGET=89.169.96.185 RUNTIME=VM \
	MAXSEQ=8 NP_LIST=100 RPS_LIST=16 RIN_LIST=1000 ROUT_LIST=500 make bench-loop
	VLLM_ENDPOINT=/v1/chat/completions MACHINE=Phala-H200 SCHEME=https VLLM_TARGET=vllm.concrete-security.com RUNTIME=CVM \
	MAXSEQ=8 NP_LIST=100 RPS_LIST=16 RIN_LIST=1000 ROUT_LIST=500 make bench-loop

