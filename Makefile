.PHONY: install lint fix format format-check test test-integration test-x402-localnet node node-stop check all coverage coverage-baseline diff-cover api api-check

install:
	uv sync --all-extras --dev

lint:
	uv run ruff check .

fix:
	uv run ruff check --fix .
	uv run ruff format .

format:
	uv run ruff format .

format-check:
	uv run ruff format --check .

test:
	uv run pytest -v

# Needs the Tempo localnet: make node. TEMPO_RPC_URL overrides its URL.
test-integration:
	TEMPO_NETWORK=localnet uv run pytest -m integration -v

# The full suite against the localnet, Redis and Anvil (docker compose up -d
# --wait), as CI's coverage run; fails if branch coverage drops below
# .coverage-baseline.
coverage:
	TEMPO_NETWORK=localnet REDIS_URL=redis://localhost:6379 \
		X402_ANVIL_RPC_URL=http://localhost:18546 \
		uv run pytest --cov=mpp --cov-report=term-missing \
		--cov-report=xml:coverage.xml --cov-report=json:coverage.json
	uv run python scripts/coverage_ratchet.py coverage.json

# Raise .coverage-baseline to the last coverage run's branch coverage.
coverage-baseline:
	uv run python scripts/coverage_ratchet.py coverage.json --update

# Changed lines since origin/main need 90% coverage (run make coverage first).
diff-cover:
	uv run diff-cover coverage.xml --compare-branch=origin/main --fail-under=90

# Regenerate the public API snapshot after an intended API change.
api:
	uv run python scripts/public_api.py

api-check:
	uv run python scripts/public_api.py --check

# Needs Anvil on port 18546: docker compose up -d anvil
test-x402-localnet:
	X402_ANVIL_RPC_URL=http://localhost:18546 uv run pytest -m x402_localnet -v

node:
	docker compose up -d
	@echo "Waiting for Tempo node..."
	@for i in $$(seq 1 30); do \
		if curl -sf -X POST -H 'Content-Type: application/json' \
			-d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
			http://localhost:8545 > /dev/null 2>&1; then \
			echo "Tempo node ready"; exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "Tempo node failed to start"; docker compose logs tempo; exit 1

node-stop:
	docker compose down

check: lint format-check api-check test

all: install check
