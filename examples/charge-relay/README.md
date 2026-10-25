# Tempo API charge relay

This example protects a FastAPI route with a 0.01 pathUSD charge on Tempo
Moderato. pympp authenticates the challenge while Tempo API validates and
finalizes the submitted credential.

Create a Tempo API key with the `mpp:write` scope, provide it only to the
server process, and start the server:

```bash
export TEMPO_API_KEY=tempo:sk:...
export MPP_SECRET_KEY=$(openssl rand -base64 32)
uv sync
uv run server.py
```

`TEMPO_API_URL` can target a compatible self-hosted or preview Tempo API
(default `https://api.tempo.xyz`). `MPP_SECRET_KEY` protects the
server-issued challenges; the example has a development-only default so it
can run locally without one. The server listens on port 8000 by default; set
`PORT` to override it.

Then run the included payer in another terminal:

```bash
uv run client.py
```

The client creates and funds a disposable Moderato account, handles the initial
402 challenge, pays it, and prints the decoded `Payment-Receipt`. Set
`TEMPO_PRIVATE_KEY` to reuse a test account or `PAYMENT_URL` to call another
deployment.

The server flow is:

1. Issue a bound `tempo/charge` challenge.
2. Call `POST /v1/mpp/validate` without consuming the credential.
3. Call `POST /v1/mpp/broadcast` with a deterministic idempotency key.
4. Return the relay receipt in `Payment-Receipt`.

`Mpp.validate_credential()` exposes the advisory phase independently;
`Mpp.broadcast_credential()` revalidates before the terminal phase.

When the relay declines a payment, the route responds with a 402
problem-details body carrying only safe machine-readable error codes (for
example `insufficient_funds`) and a fresh challenge for retry; relay
internals are never exposed.
