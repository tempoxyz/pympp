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
fetch --key 0x... https://api.example.com
```

Or via environment variables:

```bash
export TEMPO_PRIVATE_KEY=0x...
fetch https://api.example.com/resource
```

Optionally override the RPC URL (defaults to rpc.testnet.tempo.xyz):

```bash
fetch --key 0x... --rpc-url https://rpc.testnet.tempo.xyz/ https://api.example.com
```

## How It Works

When a request returns `402 Payment Required`:

1. The client parses the `WWW-Authenticate` header to get the payment challenge
2. Creates a credential by executing the payment on Tempo
3. Retries the request with the `Authorization` header

This happens automatically via the Machine Payments Protocol client wrapper.
