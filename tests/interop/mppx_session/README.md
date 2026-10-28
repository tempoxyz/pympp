# mppx session interop harness

Node scripts that run [mppx](https://github.com/wevm/mppx)'s TIP-1034 precompile session (`tempo.session`,
`sessionProtocol` v2) so pympp's tests can check its session server and client against mppx's.
`tests/session_interop.py` starts and drives them from pytest.

```bash
cd tests/interop/mppx_session && npm ci
docker compose up -d tempo        # localnet at http://localhost:8545, chain 1337
```

- `server.mjs`: `Mppx.create({ methods: [tempo.session({ account, currency, store, getClient, ... })] })`
  serving `/paid` at `MPPX_AMOUNT` (default `0.0001`) per request. Prints `READY <port>` when listening,
  then one JSON line per request and per settlement. Configure it with `MPPX_RPC_URL`, `MPPX_CHAIN_ID`,
  `MPPX_CURRENCY`, `MPPX_PAYEE_KEY`, `MPPX_FEE_PAYER_KEY`, `MPPX_SETTLEMENT_SCHEDULE` (JSON),
  `MPPX_SUGGESTED_DEPOSIT` and `MPPX_PORT` (see the header of the file).
- `client.mjs <url>`: makes `MPPX_CALLS` paid calls with the mppx client fetch and `tempo.session`
  (`MPPX_MODE=fetch`) or the session manager (`MPPX_MODE=manager`, the default when `MPPX_TOP_UP` or
  `MPPX_CLOSE=1` is set), then optionally tops up and closes. Prints one JSON line per call and a
  final line with the channel. `MPPX_TRACE=1` also prints every HTTP exchange.

Both fund their accounts with the node's `tempo_fundAddress` faucet unless `MPPX_FUND=0`. The
currency defaults to pathUSD, like `tests/conftest.py`.

## How mppx behaves per call

Each paid call sends a request without credentials first (`Accept-Payment: tempo/session`, and the
manager adds `Payment-Session: <channelId>` once it has a channel), gets a `402` with a fresh
challenge (unique `opaque` nonce), then retries with `Authorization: Payment ...` carrying `open`
(first call) or `voucher`. Top-up and close are `POST`s to the same URL with only `Authorization`,
reusing the last challenge, and get `204` with `Payment-Receipt` and `Cache-Control: private`.
`maxDeposit` is only a cap: without `suggestedDeposit` in the challenge the client opens with the
first request's amount and sends a `topUp` of the exact shortfall before each later voucher.
