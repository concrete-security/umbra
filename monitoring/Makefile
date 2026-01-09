SHELL := /bin/bash

ENV_FILE ?= .env
cache ?= --no-cache
SERVICES ?= grafana prometheus
SCHEME ?= https
VLLM_TARGET ?= vllm.concrete-security.com

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
	@uv pip show vllm
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
	envsubst $(GRAFANA_VARS) < grafana/provisioning/dashboards/machine_metrics_overview.json.template > grafana/provisioning/dashboards/machine_metrics_overview.json

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
