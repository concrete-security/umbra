SHELL := /bin/bash

# Docker Compose files
COMPOSE_FILE = docker-compose.yml
DEV_COMPOSE_FILE = docker-compose.dev.override.yml
HS_COMPOSE_FILE = docker-compose.hs.override.yml

# Service endpoints - all traffic goes through nginx proxy
NGINX_URL = https://localhost
NGINX_HTTP_URL = http://localhost

# Development mode flag - set DEV=false for production testing
DEV ?= true
DEV_FLAG = $(if $(filter true,$(DEV)),--dev,)

# Python runner command
PYTHON_RUNNER ?= uv run

.PHONY: help dev-full dev-up dev-down hs-up hs-down test-all test-health test-attestation test-vllm test-redirect test-acme test-certificate wait-services

help:
	@echo "CVM (Confidential Virtual Machine) - Build, Run, and Test"
	@echo "========================================================="
	@echo ""
	@echo "🚀 Development Commands:"
	@echo "  dev-full      Full dev workflow: build, up, wait, test"
	@echo "  dev-up        Start services in development mode"
	@echo "  dev-down      Stop development services"
	@echo "  hs-up         Start services in a Hyperstack environment"
	@echo "  hs-down       Stop services in a Hyperstack environment"
	@echo ""
	@echo "🧪 Test Commands:"
	@echo "  test-all          Run all tests via Python test script"
	@echo "  test-health       Test health endpoint"
	@echo "  test-attestation  Test attestation service endpoints"
	@echo "  test-vllm         Test vLLM/mock vLLM endpoints"
	@echo "  test-redirect     Test HTTP to HTTPS redirect"
	@echo "  test-acme         Test ACME challenge endpoint"
	@echo "  test-certificate  Test SSL certificate validation"
	@echo "  test-cors         Test CORS configuration on multiple endpoints"
	@echo ""
	@echo "⚙️  Environment Variables:"
	@echo "  DEV             Set to 'false' for production mode testing"
	@echo "                  (default: true - development mode)"
	@echo "  PYTHON_RUNNER   Set how to run python scripts"
	@echo "                  (default: uv run)"
	@echo ""
	@echo "💡 Examples:"
	@echo "  make dev-full                          # Full development workflow"
	@echo "  make dev-up                            # Start dev docker compose"
	@echo "  make test-attestation                  # Test only attestation endpoints"
	@echo "  DEV=false make test-all                # Run all tests in production mode"
	@echo "  PYTHON_RUNNER=python3 make test all    # Run python scripts using python3"

# Development workflow
dev-full: dev-down dev-up
	DEV=true $(MAKE) wait-services
	DEV=true $(MAKE) test-all
	$(MAKE) dev-down

dev-up:
	@echo "🚀 Starting services in development mode..."
	docker compose -f $(COMPOSE_FILE) -f $(DEV_COMPOSE_FILE) up -d --build

dev-down:
	@echo "🛑 Stopping development services..."
	docker compose -f $(COMPOSE_FILE) -f $(DEV_COMPOSE_FILE) down

hs-up:
	@echo "🚀 Starting services in Hyperstack environment..."
	docker compose -f $(COMPOSE_FILE) -f $(HS_COMPOSE_FILE) up -d --build

hs-down:
	@echo "🛑 Stopping Hyperstack services..."
	docker compose -f $(COMPOSE_FILE) -f $(HS_COMPOSE_FILE) down

wait-services:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --wait --base-url $(NGINX_URL)

test-all:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --all --base-url $(NGINX_URL) --http-url $(NGINX_HTTP_URL)

test-health:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --health --base-url $(NGINX_URL)

test-attestation:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --attestation --base-url $(NGINX_URL)

test-vllm:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --vllm --base-url $(NGINX_URL)

test-redirect:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --redirect --base-url $(NGINX_URL) --http-url $(NGINX_HTTP_URL)

test-acme:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --acme --base-url $(NGINX_URL) --http-url $(NGINX_HTTP_URL)

test-certificate:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --certificate --base-url $(NGINX_URL)

test-cors:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --cors --base-url $(NGINX_URL)
