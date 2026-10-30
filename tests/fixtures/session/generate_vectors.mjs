// Generates tests/fixtures/session/vectors.json from mppx (TypeScript source), ox and viem.
//
// Run from an mppx checkout so tsx and its dependencies resolve:
//   cd <mppx> && node --import tsx <pympp>/tests/fixtures/session/generate_vectors.mjs > <pympp>/tests/fixtures/session/vectors.json
import { createRequire } from 'node:module'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const mppx = process.cwd()
const require = createRequire(join(mppx, 'package.json'))
const load = (specifier) => import(pathToFileURL(require.resolve(specifier)).href)
const src = (path) => import(pathToFileURL(join(mppx, 'src', path)).href)

const { Hex, Secp256k1, Signature } = await load('ox')
const { SignatureEnvelope, TxEnvelopeTempo } = await load('ox/tempo')
const viem = await load('viem')
const { privateKeyToAccount } = await load('viem/accounts')
const { Transaction } = await load('viem/tempo')
const Channel = await src('tempo/session/precompile/Channel.ts')
const Voucher = await src('tempo/session/precompile/Voucher.ts')
const Protocol = await src('tempo/session/precompile/Protocol.ts')
const { escrowAbi } = await src('tempo/session/precompile/escrow.abi.ts')

const json = (value) =>
  JSON.stringify(value, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2)

const payerKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const signerKey = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'
const feePayerKey = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
const payer = privateKeyToAccount(payerKey)
const signer = privateKeyToAccount(signerKey)
const feePayer = privateKeyToAccount(feePayerKey)
const client = viem.createClient({ transport: viem.http('http://127.0.0.1:1') })

const escrow = Protocol.tip20ChannelEscrow
const customEscrow = '0x1111111111111111111111111111111111111111'
const zero = '0x0000000000000000000000000000000000000000'
const token = '0x20c0000000000000000000000000000000000001'

const descriptors = [
  {
    payer: payer.address,
    payee: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    operator: zero,
    token,
    salt: '0x' + '01'.repeat(32),
    authorizedSigner: zero,
    expiringNonceHash: '0x' + 'ab'.repeat(32),
  },
  {
    payer: payer.address,
    payee: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
    operator: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
    token: '0x20C000000000000000000000b9537d11c60E8b50',
    salt: '0x' + 'ff'.repeat(32),
    authorizedSigner: signer.address,
    expiringNonceHash: '0x' + '00'.repeat(31) + '07',
  },
]

const channelIds = []
for (const descriptor of descriptors)
  for (const chainId of [4217, 42431, 1337])
    for (const e of [escrow, customEscrow])
      channelIds.push({ descriptor, chainId, escrow: e, channelId: Channel.computeId({ ...descriptor, chainId, escrow: e }) })

const closeTypes = {
  CloseAuthorization: [
    { name: 'channelId', type: 'bytes32' },
    { name: 'cumulativeAmount', type: 'uint96' },
  ],
}
const voucherTypes = {
  Voucher: [
    { name: 'channelId', type: 'bytes32' },
    { name: 'cumulativeAmount', type: 'uint96' },
  ],
}

const vouchers = []
for (const [chainId, e] of [[4217, escrow], [42431, escrow], [1337, customEscrow]])
  for (const amount of [0n, 1n, 1_000_000n, (1n << 96n) - 1n]) {
    const channelId = Channel.computeId({ ...descriptors[0], chainId, escrow: e })
    const domain = Voucher.getVoucherDomain(e, chainId)
    const message = { channelId, cumulativeAmount: amount }
    const voucherDigest = viem.hashTypedData({ domain, types: voucherTypes, primaryType: 'Voucher', message })
    const closeDigest = viem.hashTypedData({ domain, types: closeTypes, primaryType: 'CloseAuthorization', message })
    const signature = await Voucher.signVoucher(client, payer, message, e, chainId)
    const closeSignature = await Voucher.signCloseAuthorization(client, payer, message, e, chainId)
    const parsed = Signature.fromHex(signature)
    const rawParity = Signature.toHex({ ...parsed, yParity: parsed.yParity }).slice(0, 130) + (parsed.yParity === 0 ? '00' : '01')
    const n = Secp256k1.noble.CURVE.n
    const highS = Signature.toHex({ r: parsed.r, s: n - parsed.s, yParity: parsed.yParity ^ 1 })
    const variants = {
      canonical: signature,
      rawParity,
      highS,
      uppercase: '0x' + signature.slice(2).toUpperCase(),
      keychain: '0x03' + payer.address.slice(2).toLowerCase() + signature.slice(2),
      truncated: signature.slice(0, 128),
    }
    const verify = {}
    for (const [name, sig] of Object.entries(variants)) {
      verify[name] = {
        payer: Voucher.verifyVoucher(e, chainId, { ...message, signature: sig }, payer.address),
        other: Voucher.verifyVoucher(e, chainId, { ...message, signature: sig }, signer.address),
      }
    }
    vouchers.push({
      chainId,
      escrow: e,
      channelId,
      cumulativeAmount: amount,
      voucherDigest,
      closeDigest,
      signer: payer.address,
      signature,
      closeSignature,
      variants,
      verify,
      closeVerify: {
        payer: Voucher.verifyCloseAuthorization(e, chainId, { ...message, signature: closeSignature }, [signer.address, payer.address]),
        voucherSignatureAsClose: Voucher.verifyCloseAuthorization(e, chainId, { ...message, signature }, [payer.address]),
      },
    })
  }

// Expiring-nonce hashes for signed open transactions.
const openData = viem.encodeFunctionData({
  abi: escrowAbi,
  functionName: 'open',
  args: [descriptors[0].payee, zero, token, 5_000_000n, descriptors[0].salt, zero],
})
const baseTx = {
  chainId: 1337,
  calls: [{ to: escrow, data: openData }],
  gas: 500_000n,
  maxFeePerGas: 20_000_000_000n,
  maxPriorityFeePerGas: 1_000_000_000n,
  nonceKey: viem.maxUint256,
  nonce: 0n,
  validBefore: 1_900_000_000,
}
const transactions = []
for (const [label, extra] of [
  ['unsponsored', { feeToken: token }],
  ['unsponsored-no-fee-token', {}],
  ['unsponsored-valid-after', { feeToken: token, validAfter: 123_456 }],
  ['sponsored', { feeToken: token, feePayerSignature: null }],
  ['sponsored-no-fee-token', { feePayerSignature: null }],
]) {
  const envelope = TxEnvelopeTempo.from({ ...baseTx, ...extra })
  const signature = Secp256k1.sign({ payload: TxEnvelopeTempo.getSignPayload(envelope), privateKey: payerKey })
  const sponsored = extra.feePayerSignature === null
  const raw = sponsored
    ? TxEnvelopeTempo.serialize(envelope, { signature: SignatureEnvelope.from(signature), format: 'feePayer', sender: payer.address })
    : TxEnvelopeTempo.serialize(envelope, { signature: SignatureEnvelope.from(signature) })
  const deserialized = Transaction.deserialize(raw)
  const hash = Channel.computeExpiringNonceHash(
    Channel.transactionForExpiringNonceHash({ ...(sponsored ? { feePayer: true } : {}), transaction: deserialized }),
    { sender: payer.address },
  )
  const entry = { label, sponsored, sender: payer.address, raw, expiringNonceHash: hash }
  if (sponsored) {
    // Fee payer co-signs: the 0x76 broadcast form keeps the same expiring nonce hash.
    const withFeeToken = TxEnvelopeTempo.from({ ...baseTx, ...extra, feeToken: token, signature: SignatureEnvelope.from(signature) })
    const feePayerSignature = Secp256k1.sign({
      payload: TxEnvelopeTempo.getFeePayerSignPayload(withFeeToken, { sender: payer.address }),
      privateKey: feePayerKey,
    })
    const cosigned = TxEnvelopeTempo.serialize({ ...withFeeToken, feePayerSignature })
    entry.cosigned = cosigned
    entry.cosignedExpiringNonceHash = Channel.computeExpiringNonceHash(
      Channel.transactionForExpiringNonceHash({ feePayer: true, transaction: Transaction.deserialize(cosigned) }),
      { sender: payer.address },
    )
    entry.cosignedHash = viem.keccak256(cosigned)
    entry.feePayer = feePayer.address
  }
  entry.channelId = Channel.computeId({
    ...descriptors[0],
    expiringNonceHash: hash,
    chainId: 1337,
    escrow,
  })
  transactions.push(entry)
}

// ABI calldata, results and events.
const descriptor = descriptors[1]
const calldata = {
  open: viem.encodeFunctionData({ abi: escrowAbi, functionName: 'open', args: [descriptor.payee, descriptor.operator, descriptor.token, 123n, descriptor.salt, descriptor.authorizedSigner] }),
  topUp: viem.encodeFunctionData({ abi: escrowAbi, functionName: 'topUp', args: [descriptor, 456n] }),
  settle: viem.encodeFunctionData({ abi: escrowAbi, functionName: 'settle', args: [descriptor, 789n, '0x' + '12'.repeat(65)] }),
  close: viem.encodeFunctionData({ abi: escrowAbi, functionName: 'close', args: [descriptor, 1000n, 900n, '0x' + '34'.repeat(65)] }),
  requestClose: viem.encodeFunctionData({ abi: escrowAbi, functionName: 'requestClose', args: [descriptor] }),
  withdraw: viem.encodeFunctionData({ abi: escrowAbi, functionName: 'withdraw', args: [descriptor] }),
  getChannel: viem.encodeFunctionData({ abi: escrowAbi, functionName: 'getChannel', args: [descriptor] }),
  getChannelState: viem.encodeFunctionData({ abi: escrowAbi, functionName: 'getChannelState', args: ['0x' + '56'.repeat(32)] }),
  getChannelStatesBatch: viem.encodeFunctionData({ abi: escrowAbi, functionName: 'getChannelStatesBatch', args: [['0x' + '56'.repeat(32), '0x' + '78'.repeat(32)]] }),
  computeChannelId: viem.encodeFunctionData({ abi: escrowAbi, functionName: 'computeChannelId', args: [descriptor.payer, descriptor.payee, descriptor.operator, descriptor.token, descriptor.salt, descriptor.authorizedSigner, descriptor.expiringNonceHash] }),
}
const state = { settled: 10n, deposit: 100n, closeRequestedAt: 1_700_000_000 }
const results = {
  getChannel: viem.encodeFunctionResult({ abi: escrowAbi, functionName: 'getChannel', result: { descriptor, state } }),
  getChannelState: viem.encodeFunctionResult({ abi: escrowAbi, functionName: 'getChannelState', result: state }),
  getChannelStatesBatch: viem.encodeFunctionResult({ abi: escrowAbi, functionName: 'getChannelStatesBatch', result: [state, { settled: 0n, deposit: 0n, closeRequestedAt: 0 }] }),
}
const channelId = '0x' + '9a'.repeat(32)
const eventArgs = {
  ChannelOpened: { channelId, payer: descriptor.payer, payee: descriptor.payee, operator: descriptor.operator, token: descriptor.token, authorizedSigner: descriptor.authorizedSigner, salt: descriptor.salt, expiringNonceHash: descriptor.expiringNonceHash, deposit: 5_000_000n },
  TopUp: { channelId, payer: descriptor.payer, payee: descriptor.payee, additionalDeposit: 7n, newDeposit: 5_000_007n },
  Settled: { channelId, payer: descriptor.payer, payee: descriptor.payee, cumulativeAmount: 99n, deltaPaid: 9n, newSettled: 99n },
  CloseRequested: { channelId, payer: descriptor.payer, payee: descriptor.payee, closeGraceEnd: 1_700_000_900n },
  ChannelClosed: { channelId, payer: descriptor.payer, payee: descriptor.payee, settledToPayee: 99n, refundedToPayer: 1n },
  CloseRequestCancelled: { channelId, payer: descriptor.payer, payee: descriptor.payee },
}
const events = {}
for (const [name, args] of Object.entries(eventArgs)) {
  const item = escrowAbi.find((i) => i.type === 'event' && i.name === name)
  const topics = viem.encodeEventTopics({ abi: escrowAbi, eventName: name, args })
  const nonIndexed = item.inputs.filter((i) => !i.indexed)
  const data = viem.encodeAbiParameters(nonIndexed, nonIndexed.map((i) => args[i.name]))
  events[name] = { topics, data, args }
}

const receipt = {
  method: 'tempo',
  intent: 'session',
  status: 'success',
  timestamp: '2026-10-28T12:00:00.123Z',
  reference: channelId,
  challengeId: 'challenge-ü-1',
  channelId,
  acceptedCumulative: '1000',
  spent: '250',
  units: 3,
  txHash: '0x' + 'cd'.repeat(32),
}
const minimalReceipt = { ...receipt }
delete minimalReceipt.units
delete minimalReceipt.txHash
const receipts = [receipt, minimalReceipt].map((r) => ({ receipt: r, serialized: Protocol.serializeSessionReceipt(r) }))

process.stdout.write(
  json({
    keys: { payer: payerKey, signer: signerKey, feePayer: feePayerKey },
    addresses: { payer: payer.address, signer: signer.address, feePayer: feePayer.address },
    channelIds,
    vouchers,
    transactions,
    abi: { descriptor, calldata, state, results, events },
    receipts,
  }) + '\n',
)
