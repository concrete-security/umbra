.PHONY: help test test-wasm build-wasm proxy web-check demo

CARGO ?= cargo
PYTHON ?= python3
WASM_ARGS ?=

PROXY_LISTEN ?= 127.0.0.1:9000
PROXY_TARGET ?= vllm.concrete-security.com:443
WEB_PORT ?= 8080

help:
	@echo "Available targets:"
	@echo "  make test         # run all native Rust tests (workspace, excluding wasm crate)"
	@echo "  make test-wasm    # cargo check ratls-wasm against wasm32-unknown-unknown"
	@echo "  make build-wasm   # run wasm-pack build (see build-wasm.sh for overrides)"
	@echo "  make proxy        # run the local WebSocket->TCP proxy"
	@echo "  make web-check    # serve the wasm/web-check demo via python http.server"
	@echo "  make demo         # run proxy and web-check simultaneously (Ctrl+C to stop)"

test:
	$(CARGO) test --workspace --exclude ratls-wasm

test-wasm:
	$(CARGO) check -p ratls-wasm --target wasm32-unknown-unknown

build-wasm:
	./build-wasm.sh $(WASM_ARGS)

proxy:
	cd proxy && RATLS_PROXY_LISTEN=$(PROXY_LISTEN) RATLS_PROXY_TARGET=$(PROXY_TARGET) $(CARGO) run

web-check:
	cd wasm && $(PYTHON) -m http.server $(WEB_PORT)
	@echo "Serving wasm demo on http://localhost:$(WEB_PORT)/web-check/ (default proxy ws://localhost:9000)"

demo:
	@set -euo pipefail; \
	trap 'kill 0' INT TERM EXIT; \
	( cd proxy && RATLS_PROXY_LISTEN=$(PROXY_LISTEN) RATLS_PROXY_TARGET=$(PROXY_TARGET) $(CARGO) run ) & PROXY_PID=$$!; \
	sleep 1; \
	if ! kill -0 $$PROXY_PID 2>/dev/null; then \
	  echo "Proxy failed to start (is $(PROXY_LISTEN) already in use?). Aborting demo."; \
	  exit 1; \
	fi; \
	( cd wasm && $(PYTHON) -m http.server $(WEB_PORT) ) & SERVER_PID=$$!; \
	echo "Proxy: ws://$(shell echo $(PROXY_LISTEN) | sed 's/127\.0\.0\.1/localhost/g') (target $(PROXY_TARGET))"; \
	echo "Web demo: http://localhost:$(WEB_PORT)/web-check/"; \
	wait
