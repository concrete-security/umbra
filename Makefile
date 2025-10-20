SHELL := /bin/bash

# Usage:
#   make docker-run
#   make docker-run cache=--no-cache
cache ?=--no-cache

# Environment mode: dev | staging | prod
MODE ?= prod
ENV_FILE := cvm/.env_$(MODE)
VENV := .venv-poetryy

.PHONY: setup
setup:
	@echo "- Installing environment from pyproject.toml..."

	@if [ ! -d $(VENV) ]; then \
		echo "Creating virtual environment ($(VENV))..."; \
		python3 -m venv $(VENV); \
	else \
		echo "✅ Virtual environment ($(VENV)) already exists..."; \
	fi

	@if [ ! -f $(VENV)/bin/poetry ]; then \
		echo "❌  Poetry not found. Installing into ($(VENV))..."; \
		. $(VENV)/bin/activate; \
		pip install --upgrade pip >/dev/null; \
		pip install poetry >/dev/null; \
	fi

	@echo "- Poetry version:"; \
	. $(VENV)/bin/activate; \
	poetry --version

	@echo "- Checking for pyproject.toml..."
	@if [ ! -f pyproject.toml ]; then \
		echo "⚙️  pyproject.toml not found, creating a new one automatically..."; \
		$(VENV)/bin/poetry init --no-interaction --name secure-chat --dependency pytest --dependency requests --dependency prometheus-client >/dev/null; \
		echo "✅ pyproject.toml created successfully."; \
	else \
		echo "✅ pyproject.toml already exists."; \
	fi

	@echo "- Installing project dependencies..."
	@$(VENV)/bin/poetry install --no-root
	@echo "✅ Setup complete!"

.PHONY: tests
tests:
	@if [ ! -d $(VENV) ]; then \
		echo "Virtual environment not found."; \
		echo "Please create it and install all dependencies by running: make setup"; \
		exit 1; \
	fi
	# fix issue
	@echo "- Running tests with $(ENV_FILE) and $(VENV)..."
	@set -a && source $(ENV_FILE) && set +a && \
	$(VENV)/bin/poetry run pytest -vvx

.PHONY: docker-build
docker-build:
	@chmod +x ./cvm/docker/docker_build.sh
	@cd cvm && bash ./docker/docker_build.sh $(MODE)

.PHONY: docker-run
docker-run:
	@chmod +x ./cvm/docker/docker_run.sh
	@cd cvm && bash ./docker/docker_run.sh $(MODE)

.PHONY: docker-up
docker-up:
	@$(MAKE) docker-build MODE=$(MODE)
	@$(MAKE) docker-run MODE=$(MODE)
