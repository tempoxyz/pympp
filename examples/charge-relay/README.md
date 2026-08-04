# FastAPI Charge Relay

A single-file FastAPI server that accepts pathUSD on Tempo Moderato. pympp
issues and binds charge challenges, then delegates validation and broadcast to
the Tempo API Moderato relay—the same setup as mppx's `charge-relay` example.

## Setup

Create a Tempo API key with the `mpp:write` scope and provide it only to the
server process:

```bash
export TEMPO_API_KEY=tempo:sk:...
export TEMPO_API_URL=https://api.tempo.xyz
export MPP_SECRET_KEY=$(openssl rand -base64 32)
uv sync
uv run server.py
```

The server starts at `http://127.0.0.1:5173`. `TEMPO_API_URL` can target a
compatible self-hosted or preview Tempo API. `MPP_SECRET_KEY` protects the
server-issued challenges; the example has a development-only default so it can
run locally without one.

In another terminal, run the included Moderato client:

```bash
uv run client.py
```

It creates and funds a disposable test account, pays `/api/photo`, and prints
the decoded relay receipt. Set `TEMPO_PRIVATE_KEY` to reuse an existing test
account or `PAYMENT_URL` to target another deployment.

## Routes

| Route | Description |
|---|---|
| `/api/photo` | Payment-gated image URL |
| `/api/health` | Free health check |

## Flow

1. The server returns a `tempo/charge` challenge for pathUSD.
2. The payer signs a Tempo transaction and retries with its credential.
3. `Relay` calls `POST /v1/mpp/validate`, then `POST /v1/mpp/broadcast`.
4. The relay receipt becomes the `Payment-Receipt` response header.

The normal payment route uses the same split lifecycle as mppx. For standalone
credentials, `Mpp.validate_credential()` performs only the advisory validation
phase and `Mpp.broadcast_credential()` revalidates before the terminal phase.
`Mpp.verify_credential()` remains as a backward-compatible terminal alias.

The relay broadcasts pull credentials. It finalizes push credentials that
contain an already-broadcast transaction hash without broadcasting them again.
Relay failures become payment errors without exposing API details.
