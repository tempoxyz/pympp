// Part 1 of ox_vectors.json, generated with ox@0.14.45 (the version mppx pins).
import { TxEnvelopeTempo, SignatureEnvelope, KeyAuthorization } from 'ox/tempo'
import { Secp256k1, Hex, P256 } from 'ox'
const pk1 = '0x' + '11'.repeat(32), pk2 = '0x' + '22'.repeat(32)
const sender = Secp256k1.getAddress? null : null
const base = {
  chainId: 42431, maxPriorityFeePerGas: 1n, maxFeePerGas: 2n, gas: 1000000n,
  calls: [{ to: '0x20c0000000000000000000000000000000000000', data: '0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f8fe0000000000000000000000000000000000000000000000000000000000000f4240' }, {to:'0x742d35Cc6634c0532925a3b844bC9e7595F8fE00', value: 5n}],
  nonceKey: 2n**256n-1n, nonce: 0n, validBefore: 1900000000, feeToken: '0x20c0000000000000000000000000000000000000',
  accessList: [{address:'0x20c0000000000000000000000000000000000000', storageKeys:['0x'+'00'.repeat(31)+'01']}],
}
const out = {}
const unsigned = TxEnvelopeTempo.from(base)
out.unsigned = TxEnvelopeTempo.serialize(unsigned)
out.signPayload = TxEnvelopeTempo.getSignPayload(unsigned)
const sig = Secp256k1.sign({ payload: out.signPayload, privateKey: pk1 })
out.signed = TxEnvelopeTempo.serialize(unsigned, { signature: SignatureEnvelope.from(sig) })
out.signedHash = TxEnvelopeTempo.hash(TxEnvelopeTempo.deserialize(out.signed))
// sponsored
const sp = TxEnvelopeTempo.from({ ...base, feePayerSignature: null })
out.sponsoredSignPayload = TxEnvelopeTempo.getSignPayload(sp)
const ssig = Secp256k1.sign({ payload: out.sponsoredSignPayload, privateKey: pk1 })
const senderAddr = Secp256k1.recoverAddress({payload: out.sponsoredSignPayload, signature: ssig})
out.sender = senderAddr
out.sponsoredSenderSigned = TxEnvelopeTempo.serialize({...sp, feeToken: undefined}, { signature: SignatureEnvelope.from(ssig), format: 'feePayer', sender: senderAddr })
out.feePayerPayload = TxEnvelopeTempo.getFeePayerSignPayload(sp, { sender: senderAddr })
const fsig = Secp256k1.sign({ payload: out.feePayerPayload, privateKey: pk2 })
out.cosigned = TxEnvelopeTempo.serialize({ ...sp, signature: SignatureEnvelope.from(ssig) }, { feePayerSignature: fsig })
// keychain + key authorization
const ka = KeyAuthorization.from({ address: '0x' + 'ab'.repeat(20), chainId: 42431n, type: 'p256', expiry: 1900000000, limits: [{token:'0x20c0000000000000000000000000000000000000', limit: 1000n, period: 86400}], scopes: [{address: '0x20c0000000000000000000000000000000000000', selector: 'transfer(address,uint256)', recipients: ['0x742d35Cc6634c0532925a3b844bC9e7595F8fE00']}, {address:'0xdec0000000000000000000000000000000000000'}], witness: '0x'+'cd'.repeat(32), account: '0x' + 'ef'.repeat(20) })
out.keyAuthPayload = KeyAuthorization.getSignPayload(ka)
const kasig = Secp256k1.sign({ payload: out.keyAuthPayload, privateKey: pk1 })
const kas = KeyAuthorization.from(ka, { signature: SignatureEnvelope.from(kasig) })
out.keyAuthSerialized = KeyAuthorization.serialize(kas)
out.keyAuthRpc = KeyAuthorization.toRpc(kas)
const kaSimple = KeyAuthorization.from({ address: '0x' + 'ab'.repeat(20), chainId: 4217n, type: 'secp256k1' })
out.keyAuthSimplePayload = KeyAuthorization.getSignPayload(kaSimple)
const kc = TxEnvelopeTempo.from({ ...base, keyAuthorization: kas, validAfter: 1800000000 })
const kcPayload = TxEnvelopeTempo.getSignPayload(kc)
const user = '0x' + 'ef'.repeat(20)
const inner = Secp256k1.sign({ payload: TxEnvelopeTempo.getSignPayload(kc, { from: user }), privateKey: pk2 })
out.keychainSigned = TxEnvelopeTempo.serialize(kc, { signature: SignatureEnvelope.from({ userAddress: user, inner: SignatureEnvelope.from(inner), type: 'keychain' }) })
out.keychainSignPayload = kcPayload
// p256 envelope
const ppk = '0x' + '33'.repeat(32)
const pub = P256.getPublicKey({ privateKey: ppk })
const psig = P256.sign({ payload: kcPayload, privateKey: ppk })
out.p256Envelope = SignatureEnvelope.serialize({ signature: psig, publicKey: pub, prehash: false, type: 'p256' })
out.p256Payload = kcPayload
out.p256Address = SignatureEnvelope.extractAddress({ payload: kcPayload, signature: SignatureEnvelope.deserialize(out.p256Envelope) })
console.log(JSON.stringify(out, (k, v) => typeof v === 'bigint' ? v.toString() : v, 2))
