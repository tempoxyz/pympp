// Generates tests/fixtures/identity/tempo_id_vectors.json: Tempo ID requests proved by mppx's
// TempoId.Client.prover, with the verdict of mppx's TempoId.Server.create on each.
//
// Run from an mppx checkout so tsx and its dependencies resolve:
//   cd <mppx> && node --import tsx <pympp>/tests/fixtures/identity/generate_tempo_id_vectors.mjs \
//     > <pympp>/tests/fixtures/identity/tempo_id_vectors.json
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const mppx = process.cwd()
const src = (path) => import(pathToFileURL(join(mppx, 'src', path)).href)
const TempoId = await src('extensions/identity/tempo/index.ts')
const Jwt = await src('extensions/identity/tempo/internal/Jwt.ts')

const issuer = 'https://id.tempo.xyz'
const alice = '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'
const now = Math.floor(Date.now() / 1000)
const exp = now + 10 * 365 * 24 * 3600

const rsa = await crypto.subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true,
  ['sign', 'verify'],
)
const { e, kty, n } = await crypto.subtle.exportKey('jwk', rsa.publicKey)
const jwks = { keys: [{ e, kid: 'key-1', kty, n }] }

async function sign(header, claims) {
  const input = Jwt.encode({ alg: 'RS256', kid: 'key-1', ...header }) + '.' + Jwt.encode(claims)
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', rsa.privateKey, new TextEncoder().encode(input))
  return input + '.' + Buffer.from(signature).toString('base64url')
}

const ec = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
const jwk = await crypto.subtle.exportKey('jwk', ec.publicKey)
const dpop = { jwk, privateKey: ec.privateKey }

const claims = {
  iss: issuer,
  sub: 'user-1',
  aud: issuer,
  client_id: 'app_1',
  exp,
  access_keys: [{ account: alice, chain_id: 4217 }],
  compliance: { [alice]: 'clear' },
}
const idToken = await sign({ typ: 'JWT' }, { iss: issuer, sub: 'user-1', aud: 'app_1', exp, email: 'Alice@Example.com', email_verified: true })

const cases = [
  { name: 'dpop with id token', token: await sign({ typ: 'at+jwt' }, { ...claims, cnf: { jkt: await Jwt.thumbprint(jwk) } }), dpop, idToken },
  { name: 'bearer', token: await sign({ typ: 'at+jwt' }, claims) },
]

const source = 'did:pkh:eip155:4217:' + alice
const vectors = []
for (const entry of cases) {
  const prover = TempoId.Client.prover({
    accessToken: () => entry.token,
    ...(entry.dpop && { dpop: entry.dpop }),
    ...(entry.idToken && { idToken: () => entry.idToken }),
    scope: ['https://api.example'],
  })
  const request = await prover.prove(new Request('https://api.example/paid?page=2', { method: 'POST' }), { created: now, nonce: 'n' })
  const server = TempoId.Server.create({
    clientId: 'app_1',
    fetch: async () => new Response(JSON.stringify(jwks), { headers: { 'Content-Type': 'application/json' } }),
  })
  const caller = await server.verifier.verify(request)
  const challenge = { id: 'c1', realm: 'api.example', method: 'tempo', intent: 'charge', request: {} }
  const payer = await server.paymentCheck.verify({ request, challenge, credential: { challenge, payload: {}, source } })
  vectors.push({
    name: entry.name,
    request: { method: request.method, url: request.url, headers: Object.fromEntries(request.headers) },
    caller,
    payer,
  })
}

console.log(JSON.stringify({ generated: now, jwks, source, vectors }, null, 2))
