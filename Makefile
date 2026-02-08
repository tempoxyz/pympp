.PHONY: install lint fix format format-check test test-integration test-integration-testnet check all

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

test-integration-testnet:
	TEMPO_RPC_URL=https://rpc.testnet.tempo.xyz uv run pytest -m integration -v

check: lint format-check test

all: install check
