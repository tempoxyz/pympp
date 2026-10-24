---
pympp: minor
---

Added the `evm` payment method with EIP-3009 authorization support, enabling servers to charge USDC and other EIP-3009 tokens on Base, Celo, and other EVM chains. The method serves both native MPP clients and x402 v2 `exact` clients from a single endpoint, settling through an x402 facilitator or a custom settle hook. Added a new `pympp[evm]` optional extra and pre-defined assets for Base USDC, Base Sepolia USDC, Celo USDC, Celo USDT, and Celo Sepolia USDC.
