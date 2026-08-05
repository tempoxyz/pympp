# Tempo API charge relay

This example protects a FastAPI route with a 0.01 pathUSD charge on Tempo
Moderato. pympp authenticates the challenge while Tempo API validates and
finalizes the submitted credential.

Start the server:

```bash
export TEMPO_API_KEY=tempo:sk:...
export MPP_SECRET_KEY=$(openssl rand -base64 32)
uv sync
uv run server.py
```

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
`Mpp.verify_credential()` remains a terminal alias.
