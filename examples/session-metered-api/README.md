# Session metered API example

An API that charges 0.00001 per call, and an agent that makes 500 calls through one
[session](https://mpp.dev/payment-methods/tempo/session): one on-chain open, off-chain
vouchers for every call, two automatic top-ups, and one cooperative close that refunds
the unspent deposit.

## What this demonstrates

- `tempo.session` on a Starlette server: a free `/health` route and a paid `/api/quote`
  route priced per request (`amount="0.00001"`, `unit_type="request"`,
  `suggested_deposit="0.002"`)
- Channel state in a `SQLiteStore` on a volume, settlement every 100 paid calls
  (`SettlementSchedule(units=100)`), and a fee sponsor that pays every transaction's gas
- `tempo.session_manager` in the agent: it opens a channel with the suggested deposit,
  signs a voucher per call, tops up when the deposit runs out, and closes the session
- On-chain results: the close transaction's `ChannelClosed` event and the payer's and
  payee's balances

## Run it

```bash
cd examples/session-metered-api
docker compose up --build --exit-code-from agent
```

This starts a Tempo localnet (on host port 18645), the API server (on 18000) and the
agent, and stops everything when the agent finishes. Without `--exit-code-from agent`,
the localnet and server keep running for more agent runs (`docker compose run agent`).
Remove the containers and the channel store with `docker compose down -v`.

The agent prints:

```text
agent-1  | agent 0xf55aE21D468B1b07380d9F822F78B61d5f29a35C: 500 calls to http://server:8000/api/quote
agent-1  | opened channel 0xe724c240…c9ba31 with deposit 0.002000
agent-1  | call 100: spent 0.001000 of 0.002000
agent-1  | call 200: spent 0.002000 of 0.002000
agent-1  | call 201: topped up to 0.004000
agent-1  | call 300: spent 0.003000 of 0.004000
agent-1  | call 400: spent 0.004000 of 0.004000
agent-1  | call 401: topped up to 0.006000
agent-1  | call 500: spent 0.005000 of 0.006000
agent-1  |
agent-1  | 500 calls in 47.3s (11/s) on one channel
agent-1  | closed in tx 0x1c4eae0d…43118a
agent-1  |   deposit   0.006000
agent-1  |   spent     0.005000 (500 x 0.00001)
agent-1  |   refunded  0.001000
agent-1  | on chain: payer paid 0.005000, payee received 0.005000, channel deposit now 0.000000
```

and the server logs a settlement every 100 calls and the close:

```text
server-1  | server scheduled settlement: +1000 (total 1000) on 0xe724c240… tx 0x103af679…
server-1  | server scheduled settlement: +1000 (total 2000) on 0xe724c240… tx 0x80d928a5…
...
server-1  | server close settlement: +0 (total 5000) on 0xe724c240… tx 0x1c4eae0d…
```

Amounts are in pathUSD (6 decimals). The sponsor pays the gas, so the payer loses exactly
what it spent and the payee gains exactly that.

## Run it without Docker for the app

Start only the localnet, then run the server and the agent with [uv](https://docs.astral.sh/uv/):

```bash
cd examples/session-metered-api
docker compose up -d tempo
uv run server.py                                       # terminal 1
SERVER_URL=http://localhost:8000 uv run agent.py       # terminal 2
```

Both default to the localnet at `http://localhost:18645` and fund their accounts from its
faucet (`tempo_fundAddress`).

## Configuration

| Variable | Used by | Default |
|----------|---------|---------|
| `TEMPO_RPC_URL` | both | `http://localhost:18645` |
| `TEMPO_CURRENCY` | both | pathUSD |
| `PAYEE_KEY`, `SPONSOR_KEY` | server | development keys (localnet only; required elsewhere) |
| `MPP_SECRET_KEY` | server | a development secret (localnet only; required elsewhere) |
| `STORE_PATH`, `PORT` | server | `sessions.db`, `8000` |
| `PAYER_KEY` | agent | a new random key |
| `SERVER_URL`, `CALLS`, `MAX_DEPOSIT` | agent | `http://localhost:8000`, `500`, `0.05` |

Accounts are funded from the faucet only on the localnet (chain ID 1337).

## Point it at Moderato

Use your own Moderato accounts, funded with testnet pathUSD (the Moderato node's
`tempo_fundAddress` RPC method funds an address), and the Moderato RPC:

```bash
export TEMPO_RPC_URL=https://rpc.moderato.tempo.xyz
PAYEE_KEY=0x... SPONSOR_KEY=0x... MPP_SECRET_KEY="$(openssl rand -hex 32)" uv run server.py
PAYER_KEY=0x... SERVER_URL=http://localhost:8000 uv run agent.py
```

The sponsor needs pathUSD to pay gas; the payer needs enough for its deposits.
