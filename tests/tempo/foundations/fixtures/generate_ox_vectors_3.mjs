// Part 3 (ox_vectors_3.json): native multisig envelopes and headless WebAuthn signing.
// ox@0.14.45 (mppx 0.13.5's dependency) and viem@2.57.1 (mppx's minimum peer).
// Run: npm i ox@0.14.45 viem@2.57.1 && node generate_ox_vectors_3.mjs > ox_vectors_3.json
import { MultisigConfig, SignatureEnvelope, TxEnvelopeTempo } from 'ox/tempo'
import { Hash, Hex, P256, Secp256k1, Address } from 'ox'
import { Account } from 'viem/tempo'

const out = {}
const pk1 = '0x' + '11'.repeat(32)
const pk2 = '0x' + '22'.repeat(32)
const ppk = '0x' + '44'.repeat(32)
const factory = '0x7171717171717171717171717171717171717171'
const a1 = Address.fromPublicKey(Secp256k1.getPublicKey({ privateKey: pk1 }))
const a2 = Address.fromPublicKey(Secp256k1.getPublicKey({ privateKey: pk2 }))
const ap = Address.fromPublicKey(P256.getPublicKey({ privateKey: ppk }))
const payload = Hash.keccak256(Hex.fromString('tx'))

const config = MultisigConfig.from({
  owners: [
    { owner: a1, weight: 1 },
    { owner: a2, weight: 1 },
    { owner: ap, weight: 2 },
  ],
  threshold: 2,
})
const account = MultisigConfig.getAddress(config, { factory })
const digest = MultisigConfig.getSignPayload({ account, config, payload })
const s1 = SignatureEnvelope.from(Secp256k1.sign({ payload: digest, privateKey: pk1 }))
const s2 = SignatureEnvelope.from(Secp256k1.sign({ payload: digest, privateKey: pk2 }))
const signatures = SignatureEnvelope.sortMultisigApprovals({ account, config, payload, signatures: [s2, s1] })
const envelope = SignatureEnvelope.from({ account, config, signatures, type: 'multisig' })
out.multisig = {
  owners: [a1, a2, ap],
  config: MultisigConfig.toRpc(config),
  account,
  payload,
  digest,
  envelope: SignatureEnvelope.serialize(envelope),
  rpc: SignatureEnvelope.toRpc(envelope),
  commitment: MultisigConfig.getCommitment(config),
}

// A current (versioned, salted) config with a P256 owner approval.
const current = MultisigConfig.from({
  owners: [{ owner: a1, weight: 1 }, { owner: ap, weight: 1 }],
  threshold: 1,
  salt: '0x' + 'aa'.repeat(32),
  version: 3n,
})
const currentAccount = '0x' + '99'.repeat(20)
const currentDigest = MultisigConfig.getSignPayload({ account: currentAccount, config: current, payload })
const ps = P256.sign({ payload: currentDigest, privateKey: ppk })
const pEnvelope = SignatureEnvelope.from({
  account: currentAccount,
  config: current,
  signatures: [SignatureEnvelope.from({ signature: ps, publicKey: P256.getPublicKey({ privateKey: ppk }), prehash: false, type: 'p256' })],
  type: 'multisig',
})
out.multisigCurrent = { digest: currentDigest, envelope: SignatureEnvelope.serialize(pEnvelope) }

// viem multisig account signing a transaction (local owners meet the threshold).
const msAccount = Account.fromMultisig({
  owners: [Account.fromSecp256k1(pk1), Account.fromSecp256k1(pk2), { owner: ap, weight: 2 }],
  threshold: 2,
})
const tx = { chainId: 4217, calls: [{ to: '0x20c0000000000000000000000000000000000000', data: '0x' }], nonce: 0n, nonceKey: 5n, gas: 21000n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n, type: 'tempo' }
out.multisigAccount = {
  address: msAccount.address,
  signedTransaction: await msAccount.signTransaction(tx),
  signHash: await msAccount.sign({ hash: payload }),
}

// Headless WebAuthn accounts (viem Account.fromHeadlessWebAuthn).
const rpId = 'example.com'
const origin = 'https://example.com'
const headless = Account.fromHeadlessWebAuthn(ppk, { rpId, origin })
const accessParent = '0x' + 'cd'.repeat(20)
const headlessAccess = Account.fromHeadlessWebAuthn(ppk, { rpId, origin, access: accessParent })
out.headless = {
  address: headless.address,
  hash: payload,
  sign: await headless.sign({ hash: payload }),
  signedTransaction: await headless.signTransaction(tx),
  accessParent,
  accessSign: await headlessAccess.sign({ hash: payload }),
  accessSignedTransaction: await headlessAccess.signTransaction(tx),
}
// Deterministic P256 (RFC 6979) account signature.
out.p256Sign = await Account.fromP256(ppk).sign({ hash: payload })

console.log(JSON.stringify(out, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 2))

