.PHONY: up down clean-phala backup-console-db reset restore-console-db verify verify-dev-image-repro verify-security-image-repro verify-cvm-images-repro bootstrap deploy redeploy-sc redeploy-dev redeploy-console redeploy-installer measure-dev build release package-cli test test-console-db check fmt clean install-cli skill build-env setup-jwt-keys up-env bootstrap-env

UMBRA_PYTHON_VERSION := $(strip $(shell cat .python-version))
UMBRA_PINNED_RUN := uv run --python $(UMBRA_PYTHON_VERSION) --no-project
UMBRA_PINNED_PYTHON := $(UMBRA_PINNED_RUN) python

build: skill
	cargo build

release: skill
	cargo build --release

skill:
	$(UMBRA_PINNED_PYTHON) ops/cli-release/render-skill.py

package-cli:
	./ops/cli-release/package-cli-release.sh

install-cli:
	./ops/cli-release/install-cli.sh

test:
	cargo test
	uv run --locked --project console python -m pytest console/tests
	uv run --locked --project cvms/security python -m pytest cvms/security/tests

# Opt-in: boots an ephemeral Postgres and runs the real-DB integration tests
# (migration + list_sc_control_cvms query). The plain `test` target stays DB-less;
# these tests skip there unless UMBRA_TEST_DATABASE_URL is set.
test-console-db:
	./ops/db/run-console-db-tests.sh

check:
	cargo metadata --locked --no-deps --format-version 1 >/dev/null
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	uv lock --check --project console
	uv lock --check --project cvms/security
	$(UMBRA_PINNED_PYTHON) -m py_compile tools/check-dco.py tools/check-github-actions.py tools/generate-cargo-sbom.py tools/test_check_github_actions.py
	uv run --locked --project console python -m pytest -q tools/test_check_github_actions.py
	uv run --locked --project console python tools/check-github-actions.py
	cd console && npm ci --ignore-scripts --no-audit --no-fund
	@css_tmp="$$(mktemp)"; \
	trap 'rm -f "$${css_tmp}"' EXIT; \
	cd console; \
	./node_modules/.bin/tailwindcss -c tailwind.config.js -i static/admin/tailwind.in.css -o "$${css_tmp}" --minify; \
	printf '\n' >> "$${css_tmp}"; \
	cmp static/admin/tailwind.css "$${css_tmp}"
	uv run --locked --project console python -m compileall console/src console/tests console/alembic/versions
	cd console && uv run --locked python -m alembic heads
	uv run --locked --project cvms/security python -m compileall cvms/security/src cvms/security/tests
	sh -n install.sh ops/installer/install.sh
	bash -n ops/buildkit-version.sh ops/deploy/cvm-redeploy-lib.sh ops/db/console-db-guard.sh ops/db/backup-console-db.sh ops/db/restore-console-db.sh ops/db/guard-console-state-cutover.sh ops/verify/verify-journey.sh ops/verify/verify-journey-lib.sh ops/db/reset-console-db.sh ops/deploy/delete-umbra-phala-cvms.sh ops/deploy/bootstrap.sh ops/deploy/deploy.sh ops/cli-release/install-cli.sh ops/cli-release/package-cli-release.sh ops/cli-release/prepare-cli-installer.sh ops/cli-release/sync-cli-release-artifacts.sh ops/cli-release/sync-cli-workflow-artifacts.sh ops/deploy/redeploy-security-cvm.sh ops/deploy/redeploy-dev-cvm.sh ops/deploy/measure-dev-cvm-image.sh ops/host/build-env.sh ops/host/provision-host.sh ops/host/setup-jwt-keys.sh ops/db/run-console-db-tests.sh
	bash -n ops/installer/entrypoint.sh tests/test-build-env.sh tests/test-console-state-cutover-guard.sh tests/test-entrypoint-reverse-proxy.sh tests/test-provision-host.sh tests/test-setup-jwt-keys.sh tests/test-verify-journey.sh
	$(UMBRA_PINNED_RUN) bash ops/installer/smoke_test.sh
	bash tests/test-build-env.sh
	bash tests/test-console-state-cutover-guard.sh
	bash tests/test-entrypoint-reverse-proxy.sh
	bash tests/test-provision-host.sh
	bash tests/test-setup-jwt-keys.sh
	bash tests/test-verify-journey.sh
	$(UMBRA_PINNED_PYTHON) -m py_compile ops/host/provision-install-host-dns.py
	$(UMBRA_PINNED_PYTHON) ops/cli-release/render-skill.py --check
	sh -n ops/reverse-proxy/entrypoint.sh
	bash -n cvms/dev/user-sandbox/entrypoint.sh
	bash -n cvms/dev/user-sandbox/umbra-update-agents.sh
	bash -n cvms/dev/user-sandbox/umbra-agent-claude.sh
	bash -n cvms/dev/user-sandbox/umbra-agent-codex.sh
	bash -n cvms/dev/tests/user_sandbox_image_smoke.sh
	bash -n cvms/dev/tests/compose_smoke.sh
	bash -n ops/verify/verify-image-reproducibility.sh
	bash cvms/dev/tests/user_sandbox_image_smoke.sh
	$(UMBRA_PINNED_RUN) bash cvms/dev/tests/compose_smoke.sh
	uv run --locked --project console python -m py_compile ops/verify/verify-audit-chain-replay.py ops/verify/verify-openapi-conformance.py
	uv run --locked --project console python -m py_compile ops/deploy/measure-dev-cvm-image.py
	UMBRA_ENTRYPOINT_SELF_TEST=validate-placeholder-value bash cvms/dev/user-sandbox/entrypoint.sh
	$(UMBRA_PINNED_PYTHON) -m py_compile cvms/dev/user-sandbox/umbra-dev-tunnel.py
	$(UMBRA_PINNED_PYTHON) -m py_compile cvms/dev/user-sandbox/umbra-dev-egress-forwarder.py
	$(UMBRA_PINNED_PYTHON) -m py_compile cvms/dev/user-sandbox/umbra-ca-refresh.py
	$(UMBRA_PINNED_PYTHON) cvms/dev/tests/user_sandbox_contract.py
	$(UMBRA_PINNED_PYTHON) cvms/dev/tests/tunnel_smoke.py
	$(UMBRA_PINNED_PYTHON) cvms/dev/tests/egress_forwarder_smoke.py
	$(UMBRA_PINNED_PYTHON) cvms/dev/tests/ca_refresh_smoke.py
	docker run --rm --entrypoint bash -v "$(CURDIR)/cvms/dev/user-sandbox/sshd_config:/tmp/sshd_config:ro" umbra-dev-sandbox-smoke:check -lc 'mkdir -p /run/sshd && ssh-keygen -q -t ed25519 -N "" -f /tmp/ssh_host_ed25519_key && sshd -t -f /tmp/sshd_config -h /tmp/ssh_host_ed25519_key'

verify-dev-image-repro:
	UMBRA_VERIFY_IMAGE_REPRODUCIBILITY=1 bash cvms/dev/tests/user_sandbox_image_smoke.sh

verify-security-image-repro:
	bash ops/verify/verify-image-reproducibility.sh security-cvm cvms/security/Dockerfile cvms/security

verify-cvm-images-repro: verify-dev-image-repro verify-security-image-repro

fmt:
	cargo fmt

clean:
	cargo clean
	docker compose down --remove-orphans

build-env:
	./ops/host/build-env.sh "$(MODE)"

setup-jwt-keys:
	./ops/host/setup-jwt-keys.sh

up-env:
	./ops/db/guard-console-state-cutover.sh
	./ops/host/build-env.sh "$(MODE)"
	$(MAKE) up

# Fresh new host:
# build .env
# provision JWT signing keys (sudo, writes /etc/umbra/jwt)
# then start the stack.
bootstrap-env:
	./ops/db/guard-console-state-cutover.sh
	./ops/host/build-env.sh "$(MODE)"
	./ops/host/setup-jwt-keys.sh
	$(MAKE) up

up:
	./ops/db/guard-console-state-cutover.sh
	$(UMBRA_PINNED_RUN) ./ops/cli-release/prepare-cli-installer.sh
	docker volume create umbra_console_letsencrypt >/dev/null
	docker compose up -d --build

down:
	docker compose down --remove-orphans

clean-phala:
	./ops/deploy/delete-umbra-phala-cvms.sh

backup-console-db:
	./ops/db/backup-console-db.sh

reset:
	./ops/db/reset-console-db.sh

restore-console-db:
	@test -n "$(BACKUP)" || (echo "usage: make restore-console-db BACKUP=/path/to/console-....sql.gz" >&2; exit 1)
	./ops/db/restore-console-db.sh "$(BACKUP)"

verify:
	./ops/verify/verify-journey.sh

bootstrap:
	./ops/deploy/bootstrap.sh

deploy:
	./ops/deploy/deploy.sh

redeploy-sc:
	./ops/deploy/redeploy-security-cvm.sh

redeploy-dev:
	./ops/deploy/redeploy-dev-cvm.sh

measure-dev:
	./ops/deploy/measure-dev-cvm-image.sh

redeploy-console:
	./ops/db/guard-console-state-cutover.sh
	docker compose up -d --build --no-deps console

redeploy-installer:
	$(UMBRA_PINNED_RUN) ./ops/cli-release/prepare-cli-installer.sh
	docker compose up -d --build --no-deps installer reverse-proxy
