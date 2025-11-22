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
	@echo "  make test-node    # build ratls-node and run the AI SDK smoke test (requires deps + network)"
	@echo "  make test-wasm    # cargo check ratls-wasm; optional wasm build + AI SDK smoke via RUN_WASM_AI_SDK=1"
	@echo "  make build-wasm   # run wasm-pack build (see build-wasm.sh for overrides)"
	@echo "  make proxy        # run the local WebSocket->TCP proxy"
	@echo "  make web-check    # serve the wasm/web-check demo via python http.server"
	@echo "  make demo         # run proxy and web-check simultaneously (Ctrl+C to stop)"

test:
	$(CARGO) test --workspace --exclude ratls-wasm

test-node:
	@rustc_v=$$(rustc -V | awk '{print $$2}'); \
	if [ "$${rustc_v}" \< "1.88.0" ]; then \
	  echo "Skipping node native build: rustc $$rustc_v is < 1.88; upgrade rustc to build ratls-node and run the AI SDK smoke test."; \
	  exit 0; \
	fi; \
	if ! command -v pnpm >/dev/null 2>&1; then \
	  echo "pnpm is required for the AI SDK compatibility smoke test. Install pnpm first."; \
	  exit 1; \
	fi; \
	echo "Installing Node dev deps (@ai-sdk/openai ai ws zod@^4) if missing..."; \
	pnpm add -D @ai-sdk/openai ai ws zod@^4; \
	echo "Building ratls-node native addon..."; \
	$(CARGO) build -p ratls-node --release; \
	echo "Ensuring ratls_node.node exists..."; \
	( cd target/release && \
	  rm -f ratls_node.node; \
	  if [ -f libratls_node.dylib ]; then cp -f libratls_node.dylib ratls_node.node; fi; \
	  if [ ! -f ratls_node.node ] && [ -f libratls_node.so ]; then cp -f libratls_node.so ratls_node.node; fi; \
	  if [ ! -f ratls_node.node ] && [ -f ratls_node.dll ]; then cp -f ratls_node.dll ratls_node.node; fi ) || true; \
	echo "Running ai-sdk smoke test against vllm.concrete-security.com (direct TCP RA-TLS)..."; \
	cd node && node examples/ai-sdk-openai-demo.mjs "AI SDK RA-TLS smoke test from make test-node"

test-wasm:
	$(CARGO) check -p ratls-wasm --target wasm32-unknown-unknown
	@if [ -n "$$RUN_WASM_AI_SDK" ]; then \
	  echo "Building wasm bindings..."; \
	  ./build-wasm.sh; \
	  echo "Running ai-sdk WASM smoke test (requires proxy + network; start 'make demo' in another shell)..."; \
	  cd wasm && node examples/ai-sdk-openai-demo.mjs "WASM AI SDK smoke test"; \
	else \
	  echo "Skipping wasm AI SDK smoke test (set RUN_WASM_AI_SDK=1 to enable; requires proxy + network)"; \
	fi

build-wasm:
	./build-wasm.sh $(WASM_ARGS)

proxy:
	cd proxy && RATLS_PROXY_LISTEN=$(PROXY_LISTEN) RATLS_PROXY_TARGET=$(PROXY_TARGET) RATLS_PROXY_ALLOWLIST=$(PROXY_TARGET) $(CARGO) run

web-check:
	cd wasm && $(PYTHON) -m http.server $(WEB_PORT)
	@echo "Serving wasm demo on http://localhost:$(WEB_PORT)/web-check/ (default proxy ws://localhost:9000)"

demo:
	@set -euo pipefail; \
	trap 'kill 0' INT TERM EXIT; \
	( cd proxy && RATLS_PROXY_LISTEN=$(PROXY_LISTEN) RATLS_PROXY_TARGET=$(PROXY_TARGET) RATLS_PROXY_ALLOWLIST=$(PROXY_TARGET) $(CARGO) run ) & PROXY_PID=$$!; \
	sleep 1; \
	if ! kill -0 $$PROXY_PID 2>/dev/null; then \
	  echo "Proxy failed to start (is $(PROXY_LISTEN) already in use?). Aborting demo."; \
	  exit 1; \
	fi; \
	( cd wasm && $(PYTHON) -m http.server $(WEB_PORT) ) & SERVER_PID=$$!; \
	echo "Proxy: ws://$(shell echo $(PROXY_LISTEN) | sed 's/127\.0\.0\.1/localhost/g') (target $(PROXY_TARGET))"; \
	echo "Web demo: http://localhost:$(WEB_PORT)/web-check/"; \
	wait
