// mppx x402 server for tests/test_x402_client_mppx.py, the reference pympp's
// x402 client is checked against. Mirrors the paid servers in mppx's
// src/x402/Exact.e2e.test.ts and Exact.localnet.test.ts: an mppx evm.charge
// with an x402 facilitator, served over node:http.
//
// Configured through environment variables; listens on a free port and prints
// one JSON line, {"url": ...}, once it accepts connections.
//
//   MPPX_FACILITATOR_URL  x402 facilitator base URL (required)
//   MPPX_TOKEN            EIP-3009 token address (required)
//   MPPX_RECIPIENT        payee address (required)
//   MPPX_CHAIN_ID         EVM chain ID (default 31337)
//   MPPX_DECIMALS         token decimals (default 6)
//   MPPX_TOKEN_NAME       EIP-712 domain name (default USDC)
//   MPPX_TOKEN_VERSION    EIP-712 domain version (default 2)
//   MPPX_ROUTE_BINDING    'required' or 'resource' (default required)
//   MPPX_AMOUNT           display-unit price of each route (default 0.01)
//
// Routes /paid and /other charge the same amount, so a payment for one route
// presented at the other exercises mppx's route binding.
import * as http from 'node:http'

import { evm, Mppx, NodeListener, Request as ServerRequest } from 'mppx/server'

function env(name, fallback) {
  const value = process.env[name] ?? fallback
  if (value === undefined) throw new Error(`${name} is required`)
  return value
}

const chainId = Number(env('MPPX_CHAIN_ID', '31337'))
const asset = evm.assets.define({
  address: env('MPPX_TOKEN'),
  decimals: Number(env('MPPX_DECIMALS', '6')),
  network: `eip155:${chainId}`,
  transfer: {
    name: env('MPPX_TOKEN_NAME', 'USDC'),
    type: 'eip3009',
    version: env('MPPX_TOKEN_VERSION', '2'),
  },
})

const payment = Mppx.create({
  methods: [
    evm.charge({
      currency: asset,
      recipient: env('MPPX_RECIPIENT'),
      x402: {
        facilitator: env('MPPX_FACILITATOR_URL'),
        routeBinding: env('MPPX_ROUTE_BINDING', 'required'),
      },
    }),
  ],
  realm: 'mppx.test',
  secretKey: 'mppx-x402-interop-secret-key-32b',
})

const amount = env('MPPX_AMOUNT', '0.01')
const routes = {
  '/paid': payment.evm.charge({ amount, description: 'mppx x402 interop' }),
  '/other': payment.evm.charge({ amount, description: 'mppx x402 interop' }),
}

const server = http.createServer(async (req, res) => {
  try {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname
    const route = routes[path]
    if (!route) return NodeListener.sendResponse(res, new Response('not found', { status: 404 }))
    const result = await route(ServerRequest.fromNodeListener(req, res))
    if (result.status === 402) return NodeListener.sendResponse(res, result.challenge)
    return NodeListener.sendResponse(res, result.withReceipt(new Response(`paid ${path}`)))
  } catch (error) {
    console.error(error)
    res.statusCode = 500
    res.end(String(error))
  }
})

server.listen(0, '127.0.0.1', () => {
  const { port } = server.address()
  process.stdout.write(`${JSON.stringify({ url: `http://127.0.0.1:${port}` })}\n`)
})

for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(0))
