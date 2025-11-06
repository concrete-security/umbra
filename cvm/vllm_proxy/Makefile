SHELL := /bin/bash

# Usage:
#   make docker-run
#   make docker-run cache=--no-cache
cache ?= --no-cache
# Environment mode: dev | staging | prod
MODE ?= dev
SERVICES ?= proxy_api prometheus grafana # vllm


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
	@uv run pytest ../test_prometheus.py
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
