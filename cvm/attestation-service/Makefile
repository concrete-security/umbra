.PHONY: help build run test clean dev

help:
	@echo "Available commands:"
	@echo "  build    - Build the Docker image"
	@echo "  run      - Run the service with Docker"
	@echo "  dev      - Run the service in development mode"
	@echo "  test     - Test the service endpoints"
	@echo "  stop     - Stop the running Docker container"

build:
	docker build -t attestation-service .

run: build
	docker run --rm -p 8080:8080 \
		--name attestation-service \
		-v /var/run/dstack.sock:/var/run/dstack.sock \
		attestation-service

dev:
	uv sync
	uv run fastapi run  attestation_service.py --port 8080 --reload

docs:
	@echo "API documentation available at:"
	@echo "  Swagger UI: http://localhost:8080/docs"
	@echo "  ReDoc:      http://localhost:8080/redoc"

test:
	python test_service.py http://localhost:8080

stop:
	docker stop attestation-service
