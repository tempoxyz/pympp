// Part 2 of ox_vectors.json (merged into the same JSON object), ox@0.14.45.
import { TxEnvelopeTempo, SignatureEnvelope, KeyAuthorization, AuthorizationTempo } from 'ox/tempo'
import { Secp256k1, Hex, P256, WebAuthnP256, Base64, Bytes, Hash } from 'ox'
const out = {}
const pk1 = '0x' + '11'.repeat(32)
// WebAuthn envelope (headless)
const ppk = '0x' + '44'.repeat(32)
const pub = P256.getPublicKey({ privateKey: ppk })
const challenge = Hash.keccak256(Hex.fromString('hello'))
const { metadata, payload } = WebAuthnP256.getSignPayload({ challenge, rpId: 'example.com', origin: 'https://example.com' })
const sig = P256.sign({ payload, privateKey: ppk, hash: true })
out.webauthn = { envelope: SignatureEnvelope.serialize({ metadata, signature: sig, publicKey: pub, type: 'webAuthn' }), challenge, address: SignatureEnvelope.extractAddress({payload: challenge, signature: SignatureEnvelope.deserialize(SignatureEnvelope.serialize({ metadata, signature: sig, publicKey: pub, type: 'webAuthn' }))}) }
out.webauthnRpc = SignatureEnvelope.toRpc(SignatureEnvelope.deserialize(out.webauthn.envelope))
// p256 prehash
const psig = P256.sign({ payload: challenge, privateKey: ppk, hash: true })
out.p256Prehash = { envelope: SignatureEnvelope.serialize({ signature: psig, publicKey: pub, prehash: true, type: 'p256' }), payload: challenge }
// keychain v1
const base = { chainId: 4217, calls: [{ to: '0x20c0000000000000000000000000000000000000', data: '0x' }], nonce: 5n, gas: 21000n, maxFeePerGas: 10n }
const tx = TxEnvelopeTempo.from(base)
const p = TxEnvelopeTempo.getSignPayload(tx)
const inner = Secp256k1.sign({ payload: p, privateKey: pk1 })
out.keychainV1 = TxEnvelopeTempo.serialize(tx, { signature: SignatureEnvelope.from({ userAddress: '0x' + '12'.repeat(20), inner: SignatureEnvelope.from(inner), type: 'keychain', version: 'v1' }) })
// authorization list
const auth = AuthorizationTempo.from({ address: '0x' + '34'.repeat(20), chainId: 4217, nonce: 3n })
const authSig = Secp256k1.sign({ payload: AuthorizationTempo.getSignPayload(auth), privateKey: pk1 })
const authSigned = AuthorizationTempo.from(auth, { signature: SignatureEnvelope.from(authSig) })
const tx2 = TxEnvelopeTempo.from({ ...base, authorizationList: [authSigned], validAfter: 10, validBefore: 20, nonceKey: 7n })
out.withAuthList = TxEnvelopeTempo.serialize(tx2)
// key authorizations variants
const kas = [
  { address: '0x' + 'ab'.repeat(20), chainId: 0n, type: 'webAuthn', isAdmin: true },
  { address: '0x' + 'ab'.repeat(20), chainId: 4217n, type: 'secp256k1', scopes: [] , expiry: 0},
  { address: '0x' + 'ab'.repeat(20), chainId: 4217n, type: 'p256', limits: [{token: '0x20c0000000000000000000000000000000000000', limit: 0n}], account: '0x' + 'cd'.repeat(20) },
  { address: '0x' + 'ab'.repeat(20), chainId: 4217n, type: 'multisig', account: '0x' + 'cd'.repeat(20), expiry: 99 },
]
out.keyAuths = kas.map((k) => { const a = KeyAuthorization.from(k); return { serialized: KeyAuthorization.serialize(a), payload: KeyAuthorization.getSignPayload(a) } })
console.log(JSON.stringify(out, (k, v) => typeof v === 'bigint' ? v.toString() : v, 2))
