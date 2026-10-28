# x402 client

A pympp client paying an x402 server built only from Coinbase's official
`x402` package, on a local Anvil chain:

- `setup_chain.py` deploys an EIP-3009 test USDC (`TestUSDC.json`, from
  `tests/fixtures/x402`) and mints 1,000 USDC to the payer.
- `facilitator.py` runs Coinbase's x402 facilitator (`x402FacilitatorSync`),
  which settles payments on-chain, behind `/verify`, `/settle` and `/supported`.
- `server.py` protects `GET /weather` with Coinbase's FastAPI
  `payment_middleware`, priced at 0.0001 USDC.
- `client.py` pays it with `mpp.client.Mpp` and `evm.charge`, then prints the
  response, the decoded `PAYMENT-RESPONSE` and both balances.

Accounts are Anvil's defaults: payer 0, recipient 1, facilitator 2.

## With Docker

From the repository root (the image installs pympp from this checkout):

```bash
docker compose -f examples/x402-client/docker-compose.yml up --build --wait server
docker compose -f examples/x402-client/docker-compose.yml run --rm --no-deps client
docker compose -f examples/x402-client/docker-compose.yml down -v
```

`up --wait` starts Anvil, deploys the token (the one-shot `setup` service), and
waits for the facilitator and server to be healthy. The client exits non-zero
unless it got a 200 and the recipient was paid; run it again to pay again. The
server is also published on `localhost:14021` (`X402_EXAMPLE_PORT`).

## Without Docker

With [Foundry](https://getfoundry.sh)'s `anvil`, from this directory, each in
its own terminal:

```bash
anvil --chain-id 31337
uv run setup_chain.py      # writes token.json
uv run facilitator.py      # :4022
uv run server.py           # :4021
uv run client.py
```

`RPC_URL`, `FACILITATOR_URL`, `SERVER_URL` and `TOKEN_FILE` override the defaults.
