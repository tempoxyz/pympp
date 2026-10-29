---
pympp: minor
---

Aligned Tempo sponsorship, the Tempo client and x402 facilitators with mppx. Sponsored Tempo charges now check the transaction with two `eth_call` simulations, first from the sender and then as the final sponsored transaction, instead of `tempo_simulateV1`, which public Tempo RPCs refuse. A `tempo.charge()` server with a `fee_payer` now sponsors every route unless it passes `fee_payer=False`, and never advertises sponsorship without a sponsor. EVM offers ignore `fee_payer` and accept `external_id`, so one route can compose sponsored Tempo offers with EVM/x402 offers. A Tempo client configured without `chain_id` or `rpc_url` pays on the chain the challenge names (mainnet or Moderato) instead of skipping it. `HttpFacilitator` takes `create_auth_headers` for per-endpoint headers, and `mpp.x402.cdp.facilitator()` (the new `cdp` extra) authenticates to Coinbase's facilitator with a CDP API key, as `@coinbase/x402` does.
