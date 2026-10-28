// An mppx tempo.session client: N paid calls, then optional top-up and close.
//
// Usage: node client.mjs <url>
//
// Environment:
//   MPPX_RPC_URL, MPPX_CHAIN_ID, MPPX_CURRENCY   as for server.mjs
//   MPPX_PAYER_KEY     payer private key (default: a fresh key, funded with tempo_fundAddress)
//   MPPX_FUND          "0" skips funding the payer
//   MPPX_CALLS         number of paid calls (default 3)
//   MPPX_MAX_DEPOSIT   channel deposit in human units (default 1)
//   MPPX_TOP_UP        top up the channel by this many human units after the calls
//   MPPX_CLOSE         "1" closes the channel at the end
//   MPPX_MODE          "fetch" (Mppx.create client fetch with tempo.session) or "manager"
//                      (tempo.session.manager). Default: manager when MPPX_TOP_UP or MPPX_CLOSE
//                      is set (top-up and close are manager APIs), else fetch.
//   MPPX_METHOD        HTTP method of the paid calls (default GET)
//   MPPX_TRACE         "1" also prints every HTTP exchange ({"http":...})
//
// Prints one JSON line per call ({"call":i,...}), per management action ({"topUp":...},
// {"close":...}) and a final {"final":...} line with the channel info.
import { Mppx, tempo } from 'mppx/client'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'

import {
  balanceOf,
  chainId,
  currency,
  decodeCredential,
  decodeReceipt,
  fund,
  json,
  makeClient,
} from './common.mjs'

const url = process.argv[2] || process.env.MPPX_URL
if (!url) {
  console.error('usage: node client.mjs <url>')
  process.exit(2)
}
const account = privateKeyToAccount(process.env.MPPX_PAYER_KEY || generatePrivateKey())
const calls = Number(process.env.MPPX_CALLS || 3)
const maxDeposit = process.env.MPPX_MAX_DEPOSIT || '1'
const topUp = process.env.MPPX_TOP_UP
const close = process.env.MPPX_CLOSE === '1'
const mode = process.env.MPPX_MODE || (topUp || close ? 'manager' : 'fetch')
const method = process.env.MPPX_METHOD || 'GET'
const trace = process.env.MPPX_TRACE === '1'

if (process.env.MPPX_FUND !== '0') await fund(account.address)
const client = makeClient(account)
const balanceBefore = await balanceOf(currency, account.address)

/** A fetch that records every HTTP exchange the mppx client makes. */
const exchanges = []
async function tracingFetch(input, init) {
  const request = new Request(input, init)
  const response = await globalThis.fetch(request.clone())
  const authorization = request.headers.get('authorization')
  const exchange = {
    method: request.method,
    url: request.url,
    requestHeaders: Object.fromEntries(request.headers.entries()),
    action: decodeCredential(authorization)?.payload?.action ?? null,
    status: response.status,
    responseHeaders: Object.fromEntries(response.headers.entries()),
  }
  exchanges.push(exchange)
  if (trace) console.log(json({ http: exchange }))
  return response
}

function receiptFields(response) {
  return decodeReceipt(response.headers.get('payment-receipt'))
}

let manager
let fetcher
if (mode === 'manager') {
  manager = tempo.session.manager({ client, account, maxDeposit, fetch: tracingFetch })
  fetcher = (input, init) => manager.fetch(input, init)
} else if (mode === 'fetch') {
  const mppx = Mppx.create({
    fetch: tracingFetch,
    polyfill: false,
    methods: [tempo.session({ account, maxDeposit, getClient: () => client })],
  })
  fetcher = (input, init) => mppx.fetch(input, init)
} else {
  throw new Error(`unknown MPPX_MODE ${mode}`)
}

let lastReceipt = null
let failed = false
for (let i = 0; i < calls; i++) {
  const start = exchanges.length
  const response = await fetcher(url, { method })
  const body = await response.text()
  const receipt = receiptFields(response)
  if (receipt) lastReceipt = receipt
  const line = {
    call: i,
    status: response.status,
    receipt,
    body: body.slice(0, 500),
    exchanges: exchanges.slice(start).map((e) => ({ status: e.status, action: e.action, method: e.method })),
  }
  if (manager) line.cumulative = manager.cumulative
  console.log(json(line))
  if (response.status !== 200) {
    failed = true
    break
  }
}

if (!failed && manager && topUp) {
  const start = exchanges.length
  const receipt = await manager.topUp(topUp)
  console.log(
    json({
      topUp: { amount: topUp, receipt: receipt ?? null, exchanges: exchanges.slice(start) },
    }),
  )
}

if (!failed && manager && close) {
  const start = exchanges.length
  const receipt = await manager.close()
  console.log(json({ close: { receipt: receipt ?? null, exchanges: exchanges.slice(start) } }))
  if (receipt) lastReceipt = receipt
}

const balanceAfter = await balanceOf(currency, account.address)
console.log(
  json({
    final: {
      mode,
      payer: account.address,
      chainId,
      currency,
      channelId: manager?.channelId ?? lastReceipt?.channelId ?? null,
      cumulative: manager?.cumulative ?? null,
      opened: manager?.opened ?? null,
      lastReceipt,
      balanceBefore,
      balanceAfter,
      httpExchanges: exchanges.length,
      ok: !failed,
    },
  }),
)
process.exit(failed ? 1 : 0)
