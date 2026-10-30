// An mppx tempo.session server, mirroring mppx's own session test servers.
//
// Environment:
//   MPPX_RPC_URL              Tempo RPC (default http://localhost:8545)
//   MPPX_CHAIN_ID             chain ID (default 1337)
//   MPPX_CURRENCY             TIP-20 token (default pathUSD)
//   MPPX_PAYEE_KEY            payee private key (default: a fresh key)
//   MPPX_FEE_PAYER_KEY        fee payer private key; sponsors opens, top-ups and closes
//   MPPX_SETTLEMENT_SCHEDULE  JSON SettlementSchedule, e.g. {"units":2}
//   MPPX_AMOUNT               price per request (default 0.0001)
//   MPPX_UNIT_TYPE            unit type (default request)
//   MPPX_SUGGESTED_DEPOSIT    suggestedDeposit advertised in challenges, in human units. Without it
//                             mppx clients deposit only the first request's amount (maxDeposit is
//                             a cap) and top up the exact shortfall before every later voucher.
//   MPPX_SECRET_KEY           challenge HMAC secret
//   MPPX_PORT                 port (default 0: any free port)
//   MPPX_FUND                 "0" skips funding the payee and fee payer with tempo_fundAddress
//
// Prints "READY <port>" and a JSON line {"ready":true,...} on stdout once listening, then one
// JSON line per request on stdout ({"request":...}) and settlement events.
import * as nodeHttp from 'node:http'
import { Mppx, Request as MppxRequest, Store, tempo } from 'mppx/server'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'

import { chainId, currency, decodeCredential, decodeReceipt, fund, json, makeClient } from './common.mjs'

const account = privateKeyToAccount(process.env.MPPX_PAYEE_KEY || generatePrivateKey())
const feePayer = process.env.MPPX_FEE_PAYER_KEY
  ? privateKeyToAccount(process.env.MPPX_FEE_PAYER_KEY)
  : undefined
const settlementSchedule = process.env.MPPX_SETTLEMENT_SCHEDULE
  ? JSON.parse(process.env.MPPX_SETTLEMENT_SCHEDULE)
  : undefined
const amount = process.env.MPPX_AMOUNT || '0.0001'
const unitType = process.env.MPPX_UNIT_TYPE || 'request'
const suggestedDeposit = process.env.MPPX_SUGGESTED_DEPOSIT || undefined
const secretKey = process.env.MPPX_SECRET_KEY || 'pympp-mppx-session-interop-secret-key'

if (process.env.MPPX_FUND !== '0') {
  await fund(account.address)
  if (feePayer) await fund(feePayer.address)
}

const client = makeClient(account)
const store = Store.memory()

const mppx = Mppx.create({
  secretKey,
  methods: [
    tempo.session({
      account,
      chainId,
      currency,
      store,
      getClient: () => client,
      ...(feePayer ? { feePayer } : {}),
      ...(settlementSchedule ? { settlementSchedule } : {}),
      onSessionSettlement(event) {
        console.log(json({ settlement: event }))
      },
      onSessionSettlementFailure(event) {
        console.log(json({ settlementFailure: { ...event, error: String(event?.error) } }))
      },
    }),
  ],
})

const route = mppx.session({ amount, unitType, ...(suggestedDeposit ? { suggestedDeposit } : {}) })

async function handle(request) {
  const url = new URL(request.url)
  if (url.pathname === '/health') return Response.json({ ok: true })
  if (url.pathname !== '/paid') return new Response('Not Found', { status: 404 })
  const authorization = request.headers.get('authorization')
  const credential = decodeCredential(authorization)
  const result = await route(request)
  const response =
    result.status === 402
      ? result.challenge
      : await result.withReceipt(Response.json({ paid: true, path: url.pathname }))
  console.log(
    json({
      request: {
        method: request.method,
        path: url.pathname + url.search,
        requestHeaders: Object.fromEntries(request.headers.entries()),
        action: credential?.payload?.action ?? null,
        credential,
        status: response.status,
        responseHeaders: Object.fromEntries(response.headers.entries()),
        receipt: decodeReceipt(response.headers.get('payment-receipt')),
      },
    }),
  )
  return response
}

const listener = MppxRequest.toNodeListener(handle, {
  onError(error) {
    console.error('server error', error)
    return Response.json({ error: String(error) }, { status: 500 })
  },
})

const port = Number(process.env.MPPX_PORT || 0)
const httpServer = nodeHttp.createServer(listener)
httpServer.listen(port, '127.0.0.1', () => {
  const address = httpServer.address()
  console.log(
    json({
      ready: true,
      port: address.port,
      payee: account.address,
      feePayer: feePayer?.address ?? null,
      currency,
      chainId,
      amount,
      unitType,
      suggestedDeposit: suggestedDeposit ?? null,
    }),
  )
  console.log(`READY ${address.port}`)
})

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    httpServer.close()
    httpServer.closeAllConnections?.()
    process.exit(0)
  })
}
