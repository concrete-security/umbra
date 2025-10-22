SHELL := /bin/bash

NO_TDX ?= true
IMAGE_NAME = attestation-service
IMAGE_NAME_TEST = attestation-service-test
CONTAINER_NAME = attestation-service
CONTAINER_PORT = 8080
HOST_PORT = 8080
BASE_URL = http://localhost:$(HOST_PORT)

.PHONY: help build run test test-build test-api clean dev all

help:
	@echo "Attestation Service - Build, Run, and Test"
	@echo "=========================================="
	@echo ""
	@echo "🏗️  Build Commands:"
	@echo "  build       Build the Docker image"
	@echo "  test-build  Build and immediately remove Docker image (validation)"
	@echo ""
	@echo "🚀 Run Commands:"
	@echo "  run         Run the service in Docker container (builds if needed)"
	@echo "  dev         Run in development mode with hot reload (uses uv)"
	@echo "  stop        Stop the running Docker container"
	@echo ""
	@echo "🧪 Test Commands:"
	@echo "  test        Full test suite (build validation + API tests)"
	@echo "  test-api    Run API tests against running service"
	@echo "  wait-api    Wait for the service to become ready"
	@echo ""
	@echo "📚 Documentation:"
	@echo "  docs        Show API documentation URLs"
	@echo ""
	@echo "🧹 Utility Commands:"
	@echo "  all         Full workflow: clean, build, run, test, stop"
	@echo "  clean       Clean up containers and images"
	@echo ""
	@echo "⚙️  Environment Variables:"
	@echo "  NO_TDX      Set to 'false' to enable TDX/Dstack socket binding"
	@echo "              (default: true - runs without TDX dependencies)"
	@echo ""
	@echo "💡 Examples:"
	@echo "  make run                    # Run with NO_TDX=true (default)"
	@echo "  NO_TDX=false make run       # Run with TDX socket binding"
	@echo "  make dev && make test-api   # Develop and test"

build:
	docker image build -t $(IMAGE_NAME) .

run: build
ifeq ($(NO_TDX),true)
	docker container run -d --rm -p $(HOST_PORT):$(CONTAINER_PORT) \
		--name $(CONTAINER_NAME) \
		$(IMAGE_NAME)
else
	docker container run -d --rm -p $(HOST_PORT):$(CONTAINER_PORT) \
		--name $(CONTAINER_NAME) \
		-v /var/run/dstack.sock:/var/run/dstack.sock \
		$(IMAGE_NAME)
endif

dev:
	uv sync
	uv run fastapi run attestation_service.py --port $(HOST_PORT) --reload

docs:
	@echo "API documentation available at:"
	@echo "  Swagger UI: $(BASE_URL)/docs"
	@echo "  ReDoc:      $(BASE_URL)/redoc"

test-build:
	docker image build -t $(IMAGE_NAME_TEST) .
	docker image rm $(IMAGE_NAME_TEST)

wait-api:
	echo "Waiting for service to start..."
	for i in {1..30}; \
	do \
		if curl -f $(BASE_URL)/health > /dev/null 2>&1; then \
			echo "Service is ready!"; \
			break; \
		fi; \
		echo "Attempt $i: Service not ready yet, waiting..."; \
		sleep 2; \
	done;

test-api: wait-api
	uv sync --group test
ifeq ($(NO_TDX),true)
	uv run test_service.py --base-url $(BASE_URL) --no-tdx
else
	uv run test_service.py --base-url $(BASE_URL)
endif

test: test-build test-api

stop:
	docker container stop $(CONTAINER_NAME) || true

all: clean
	$(MAKE) build
	$(MAKE) run
	$(MAKE) test-api
	$(MAKE) stop

clean: stop
	docker image rm $(IMAGE_NAME) || true
	docker image rm $(IMAGE_NAME_TEST) || true
