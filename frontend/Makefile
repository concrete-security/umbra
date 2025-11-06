# Quick dev workflow for Confidential AI landing page

PORT ?= 3000

.PHONY: help install dev dev-open open open-when-ready build start lint clean

help:
	@echo "Make targets:"
	@echo "  make install       # Install deps (pnpm or npm)"
	@echo "  make dev           # Run dev server on PORT=$(PORT)"
	@echo "  make dev-open      # Start dev and auto-open browser when ready"
	@echo "  make open          # Open http://localhost:$(PORT) in browser"
	@echo "  make build         # Production build"
	@echo "  make start         # Start production server on PORT=$(PORT)"
	@echo "  make lint          # Run linter"
	@echo "  make clean         # Remove .next build output"

install:
	@if command -v pnpm >/dev/null 2>&1; then pnpm install; else npm install; fi

dev:
	@if command -v pnpm >/dev/null 2>&1; then PORT=$(PORT) pnpm dev; else PORT=$(PORT) npm run dev -- -p $(PORT); fi

# Start dev server and open the browser when it's reachable
dev-open:
	@$(MAKE) open-when-ready -s &
	@$(MAKE) dev -s

open-when-ready:
	@echo "Waiting for http://localhost:$(PORT) ..."; \
	until curl -sSf "http://localhost:$(PORT)" >/dev/null 2>&1; do sleep 1; done; \
	$(MAKE) open -s

open:
	@if command -v open >/dev/null 2>&1; then open "http://localhost:$(PORT)"; \
	elif command -v xdg-open >/dev/null 2>&1; then xdg-open "http://localhost:$(PORT)"; \
	elif command -v powershell.exe >/dev/null 2>&1; then powershell.exe -NoProfile -Command Start-Process "http://localhost:$(PORT)"; \
	else printf "Open manually: http://localhost:$(PORT)\n"; fi

build:
	@if command -v pnpm >/dev/null 2>&1; then pnpm build; else npm run build; fi

start:
	@if command -v pnpm >/dev/null 2>&1; then PORT=$(PORT) pnpm start; else PORT=$(PORT) npm run start; fi

lint:
	@if command -v pnpm >/dev/null 2>&1; then pnpm lint; else npm run lint; fi

clean:
	rm -rf .next

