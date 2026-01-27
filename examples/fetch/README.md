# fetch-cli

CLI tool for fetching URLs with automatic payment handling.

## Install

```bash
pip install -e .
```

## Usage

```bash
# GET request
fetch https://api.example.com/resource

# POST with body
fetch -X POST -d '{"query": "test"}' https://api.example.com/search

# PUT request
fetch -X PUT -d '{"name": "updated"}' https://api.example.com/resource/123

# DELETE request
fetch -X DELETE https://api.example.com/resource/123
```

## Credentials

Provide credentials via flags:

```bash
fetch --key 0x... --rpc-url https://rpc.testnet.tempo.xyz/ https://api.example.com
```

Or via environment variables:

```bash
export TEMPO_PRIVATE_KEY=0x...
export TEMPO_RPC_URL=https://rpc.testnet.tempo.xyz/  # optional, this is the default
fetch https://api.example.com/resource
```

## How It Works

When a request returns `402 Payment Required`:

1. The client parses the `WWW-Authenticate` header to get the payment challenge
2. Creates a credential by executing the payment on Tempo
3. Retries the request with the `Authorization` header

This happens automatically via the `mpay.client.Client` wrapper.
