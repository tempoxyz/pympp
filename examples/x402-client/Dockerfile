# Build context: the repository root, so the image runs this checkout of pympp.
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.9.5 /uv /usr/local/bin/uv
ENV UV_SYSTEM_PYTHON=1 PYTHONUNBUFFERED=1

WORKDIR /src
COPY pyproject.toml README.md LICENSE-MIT LICENSE-APACHE ./
COPY src ./src
# pympp from this checkout, with the evm and x402 extras.
RUN uv pip install ".[evm,x402]" uvicorn

WORKDIR /app
COPY examples/x402-client/*.py examples/x402-client/TestUSDC.json ./
