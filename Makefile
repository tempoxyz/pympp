.PHONY: install lint fix format format-check test test-integration node node-stop check all

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

test-integration:
	TEMPO_RPC_URL=http://localhost:8545 uv run pytest -m integration -v

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

check: lint format-check test

all: install check
