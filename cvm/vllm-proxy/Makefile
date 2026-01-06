SHELL := /bin/bash

cache ?= --no-cache
SERVICES ?= proxy-api # vllm nginx-cert-manager auth-service attestation-service
ENV_FILE ?= .env


.PHONY: setup
setup:
	@command -v uv >/dev/null 2>&1 || { \
            echo "❌ uv not installed."; \
            echo "curl -LsSf https://astral.sh/uv/install.sh | sh"; \
            exit 1; \
    }
	@echo "- Setting up environment using uv..."
	@uv sync --all-groups
	@echo "✅ Setup complete!"

.PHONY: tests
tests:
	@echo "- Running tests from cvm/vllm-proxy..."
	@set -o allexport; source $(ENV_FILE); set +o allexport; \
	uv run pytest test_vllm_proxy.py

.PHONY: docker-build
docker-build:
	@echo "🏗️ Building images for: $(SERVICES)"
	@docker compose build $(cache) $(SERVICES)
	@echo "✅ Successfully built images."

.PHONY: docker-stop
docker-stop:
	@echo "🛑 Stopping & removing: $(SERVICES)"
	@docker compose rm -f -s $(SERVICES) || true
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
	@$(MAKE) docker-build SERVICES="$(SERVICES)" cache="$(cache)"
	@$(MAKE) docker-stop SERVICES="$(SERVICES)"
	@$(MAKE) docker-run SERVICES="$(SERVICES)"
	@$(MAKE) docker-logs SERVICES="$(SERVICES)"
