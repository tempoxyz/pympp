// Shared helpers for the mppx session interop server and client.
import { createClient, defineChain, http } from 'viem'
import { tempoLocalnet } from 'viem/chains'

/** pathUSD, the currency pympp's tests/conftest.py uses by default. */
export const PATH_USD = '0x20c0000000000000000000000000000000000000'

export const rpcUrl = process.env.MPPX_RPC_URL || 'http://localhost:8545'
export const chainId = Number(process.env.MPPX_CHAIN_ID || 1337)
export const currency = process.env.MPPX_CURRENCY || PATH_USD

export const chain = defineChain({
  ...tempoLocalnet,
  id: chainId,
  rpcUrls: { default: { http: [rpcUrl] } },
})

export function makeClient(account) {
  return createClient({
    account,
    chain,
    pollingInterval: 250,
    transport: http(rpcUrl, { retryCount: 0, timeout: 30_000 }),
  })
}

async function rpc(method, params) {
  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  const body = await response.json()
  if (body.error) throw new Error(`${method} failed: ${JSON.stringify(body.error)}`)
  return body.result
}

/** TIP-20 balance of `address` in `token` (balanceOf). */
export async function balanceOf(token, address) {
  const data = `0x70a08231${address.slice(2).toLowerCase().padStart(64, '0')}`
  return BigInt(await rpc('eth_call', [{ to: token, data }, 'latest']))
}

/** Fund `address` with the node's tempo_fundAddress faucet, like tests/conftest.py _fund_account. */
export async function fund(address, token = currency) {
  const hashes = await rpc('tempo_fundAddress', [address])
  if (!hashes || hashes.length === 0) throw new Error('tempo_fundAddress returned no hashes')
  for (let i = 0; i < 150; i++) {
    if ((await balanceOf(token, address)) > 0n) return
    await new Promise((resolve) => setTimeout(resolve, 200))
  }
  throw new Error(`${address} not funded after tempo_fundAddress`)
}

/** JSON.stringify that writes bigints as decimal strings. */
export function json(value) {
  return JSON.stringify(value, (_key, v) => (typeof v === 'bigint' ? v.toString() : v))
}

/** Headers as a plain object, with the Payment credential's base64url payload decoded. */
export function describeHeaders(headers) {
  const out = {}
  for (const [name, value] of headers.entries()) out[name] = value
  return out
}

/** Decode a `Payment <base64url>` Authorization value into its credential JSON. */
export function decodeCredential(authorization) {
  if (!authorization) return null
  const match = /^Payment\s+(\S+)/i.exec(authorization)
  if (!match) return null
  try {
    return JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8'))
  } catch {
    return null
  }
}

/** Decode a Payment-Receipt header (base64url JSON). */
export function decodeReceipt(value) {
  if (!value) return null
  try {
    return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'))
  } catch {
    return null
  }
}
