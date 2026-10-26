.PHONY: install lint fix format format-check test test-integration test-x402-localnet node node-stop check all mutation fuzz

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

# Mutation testing of the [tool.mutmut] modules. MUTANTS narrows the run to
# mutant-name globs, e.g. make mutation MUTANTS='mpp._parsing.*'.
MUTMUT := uv run --with mutmut==3.8.0
MUTANTS ?=

mutation:
	$(MUTMUT) mutmut run $(MUTANTS)
	$(MUTMUT) python scripts/mutation.py report mutants/report.md

# Coverage-guided fuzzing with atheris: FUZZ_SECONDS per target. Point
# MPP_TOOLS_VECTORS at mpp-tools' conformance/vectors to seed from them.
# Crashes are written to fuzz/crashes/<target>/.
ATHERIS := uv run --with atheris==3.1.0
FUZZ_TARGETS ?= fuzz_www_authenticate fuzz_authorization fuzz_receipt fuzz_tempo_transaction fuzz_body_digest
FUZZ_SECONDS ?= 60
FUZZ_MAX_LEN ?= 4096
MPP_TOOLS_VECTORS ?=

fuzz:
	uv run python fuzz/seeds.py $(if $(MPP_TOOLS_VECTORS),--vectors $(MPP_TOOLS_VECTORS))
	@failed=; for target in $(FUZZ_TARGETS); do \
		mkdir -p fuzz/corpus/$$target fuzz/crashes/$$target; \
		echo "Fuzzing $$target for $(FUZZ_SECONDS)s"; \
		$(ATHERIS) python fuzz/$$target.py fuzz/corpus/$$target fuzz/seeds/$$target \
			-dict=fuzz/json.dict -max_total_time=$(FUZZ_SECONDS) -max_len=$(FUZZ_MAX_LEN) -timeout=10 \
			-rss_limit_mb=2048 -artifact_prefix=fuzz/crashes/$$target/ -print_final_stats=1 \
			|| failed="$$failed $$target"; \
	done; \
	if [ -n "$$failed" ]; then echo "Crashed:$$failed (inputs in fuzz/crashes/)"; exit 1; fi

check: lint format-check test

all: install check
