# MCP Server Example

Payment-protected MCP tools using Server-Sent Events (SSE).

## Overview

This example demonstrates:
- **Server**: SSE-based MCP server with free and paid tools
- **Client**: Connects to server and handles the payment flow

The server and client run in separate terminals, communicating via SSE.

## Prerequisites

1. **Python 3.12+**
2. **Tempo testnet account** with pathUSD balance
3. **Private key** for signing transactions

## Setup

```bash
cd examples/mcp-server
pip install -e .
```

## Environment Variables

**Server:**
```bash
export DESTINATION_ADDRESS="0x..."      # Payment recipient address (required)
export TEMPO_RPC_URL="https://rpc.testnet.tempo.xyz/"  # Default: Tempo testnet
export MCP_PORT="8000"                  # Default: 8000
```

**Client:**
```bash
export TEMPO_PRIVATE_KEY="0x..."        # Private key for signing (required)
export MCP_SERVER_URL="http://127.0.0.1:8000/sse"      # Default
```

## Running

**Terminal 1 - Start the server:**
```bash
export DESTINATION_ADDRESS="0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00"
python server_decorator.py
```

**Terminal 2 - Run the client:**
```bash
export TEMPO_PRIVATE_KEY="0x..."
python client.py
```

## Expected Output

**Server:**
```
Starting MCP server on http://127.0.0.1:8000/sse
Destination: 0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00
```

**Client:**
```
Connecting to MCP server at http://127.0.0.1:8000/sse
============================================================
Client address: 0x...

Available tools:
  - echo: Echo a message back (free tool)
  - premium_echo: Echo a message with style (paid tool - 100 units)

1. Calling free tool (echo)...
   Result: Echo: Hello, world!

2. Calling paid tool without credential (premium_echo)...
   Got error code: -32042
   Challenge ID: abc123...

3. Creating payment credential...
   Credential created for challenge: abc123...

4. Retrying with credential...
   Result: ✨ Premium Echo ✨: Hello, premium! (paid by 0x..., tx: 0x...)
```

## Server Implementations

Two server implementations are provided:

| File | Description |
|------|-------------|
| `server_decorator.py` | Clean pattern using `verify_or_challenge()` |
| `server_manual.py` | Same pattern, shows manual request building |

Both implement the same tools:
- `echo`: Free tool that echoes messages
- `premium_echo`: Paid tool (100 pathUSD units) with styled output

## Payment Flow

```
Client                          Server
  |                               |
  |------ call premium_echo ----->|
  |                               |
  |<----- -32042 + challenge -----|
  |                               |
  | [pay on Tempo blockchain]     |
  |                               |
  |-- call + credential (meta) -->|
  |                               |
  |<-------- result + receipt ----|
```

## Payment Request

The server requires this payment for `premium_echo`:

```json
{
  "amount": "100",
  "currency": "0x20c0000000000000000000000000000000000000",
  "recipient": "<DESTINATION_ADDRESS>",
  "expires": "<5 minutes from now>",
  "methodDetails": {"chainId": 42431, "feePayer": true}
}
```

## Claude Desktop Integration

Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "paid-echo": {
      "url": "http://127.0.0.1:8000/sse"
    }
  }
}
```

Note: Claude Desktop doesn't yet support the payment flow automatically.
You'll need to use the client script or a payment-aware MCP client.
