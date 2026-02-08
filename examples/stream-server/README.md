# Stream Example

A FastAPI server and client demonstrating streaming payments via payment channels.

## What This Demonstrates

- Payment channel–based streaming payments
- Per-token pricing for SSE (Server-Sent Events) responses
- Server: `Mpay.stream()` API with `StreamIntent` for verification
- Client: `StreamMethod` with auto-managed channel lifecycle

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Installation

```bash
cd examples/stream-server
uv sync
```

## Running

```bash
uv run python server.py
```

The server starts at http://localhost:8000.

## Client

In a separate terminal, run the client with a funded Tempo testnet key:

```bash
PRIVATE_KEY=0x... uv run python client.py "Hello world"
```

The client automatically handles the 402 challenge, opens a payment channel, and streams the response.

## Testing

**Health check:**

```bash
curl http://localhost:8000/api/health
# {"status":"ok"}
```

**Chat endpoint without payment (returns 402):**

```bash
curl -i "http://localhost:8000/api/chat?prompt=Hello"
# HTTP/1.1 402 Payment Required
# WWW-Authenticate: Payment ...
```

## How It Works

1. Client sends a request to `/api/chat`
2. Server returns a 402 challenge with stream intent parameters
3. Client opens a payment channel on-chain and sends a voucher
4. Server verifies the voucher and streams tokens via SSE
5. For subsequent requests, client sends incremental vouchers (no new on-chain tx)
