---
pympp: minor
---

Made `Mpp`, Tempo and EVM charges, `tempo.session` and x402 `payment_middleware` raise `RuntimeError` at startup in production (`MPP_ENV=production`, or platforms such as AWS Lambda, Fly or Vercel) when they would fall back to an in-memory replay store; pass a shared store such as `RedisStore` or `SQLStore` with `store=` or `Mpp(store=...)`, or an explicit `MemoryStore()` to keep instance-local protection, as mppx does. Made EVM claims in an explicitly passed `MemoryStore` expire after the authorization's `validBefore`.
