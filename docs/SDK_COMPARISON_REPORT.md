# mpay SDK Comparison: Python vs TypeScript

## Executive Summary

This report compares the **mpay-python** SDK against the **mpay TypeScript** SDK to identify divergences in functionality, interface design, and architectural patterns.

**Key Finding:** The TypeScript SDK is schema-driven with stateless HMAC-bound challenge verification, while Python is simpler but currently lacks several security/correctness properties—notably, credentials are not cryptographically bound to issued challenges.

---

## Object Graph: Side-by-Side Comparison

### Python SDK Object Graph

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              mpay-python                                      │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                          CORE TYPES                                      │ │
│  │                                                                         │ │
│  │  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                   │ │
│  │  │  Challenge  │   │  Credential │   │   Receipt   │                   │ │
│  │  │ (dataclass) │   │ (dataclass) │   │ (dataclass) │                   │ │
│  │  ├─────────────┤   ├─────────────┤   ├─────────────┤                   │ │
│  │  │ id: str     │   │ id: str     │◄──┤ status      │                   │ │
│  │  │ method: str │   │ payload     │   │ timestamp   │                   │ │
│  │  │ intent: str │   │ source?     │   │ reference   │                   │ │
│  │  │ request     │   └─────────────┘   └─────────────┘                   │ │
│  │  │ digest?     │         │                  ▲                          │ │
│  │  │ expires?    │         │                  │                          │ │
│  │  │ description?│         │                  │                          │ │
│  │  └─────────────┘         │                  │                          │ │
│  │        │                 │                  │                          │ │
│  │        ▼                 ▼                  │                          │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │  │                    WIRE FORMAT                                   │   │ │
│  │  │  WWW-Authenticate ◄───── _parsing.py ─────► Authorization       │   │ │
│  │  │  Payment-Receipt ◄─────────────────────────►                    │   │ │
│  │  └─────────────────────────────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                          CLIENT                                          │ │
│  │                                                                         │ │
│  │  ┌───────────────────┐      ┌─────────────────────────────────────┐    │ │
│  │  │      Client       │      │         PaymentTransport            │    │ │
│  │  │ (async context)   │─────►│     (httpx.AsyncBaseTransport)      │    │ │
│  │  ├───────────────────┤      ├─────────────────────────────────────┤    │ │
│  │  │ get()             │      │ Wraps inner transport               │    │ │
│  │  │ post()            │      │ Auto-retries on 402                 │    │ │
│  │  │ request()         │      │ Parses WWW-Authenticate             │    │ │
│  │  └───────────────────┘      │ Routes to Method.create_credential  │    │ │
│  │         │                   └──────────────────┬──────────────────┘    │ │
│  │         │                                      │                       │ │
│  │         ▼                                      ▼                       │ │
│  │  ┌───────────────────────────────────────────────────────────────┐     │ │
│  │  │                   Method (Protocol)                           │     │ │
│  │  │                                                               │     │ │
│  │  │   name: str                                                   │     │ │
│  │  │   create_credential(challenge) -> Credential                  │     │ │
│  │  └───────────────────────────────────────────────────────────────┘     │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                          SERVER                                          │ │
│  │                                                                         │ │
│  │  ┌───────────────────────────────────────────────────────────────┐     │ │
│  │  │               verify_or_challenge()                           │     │ │
│  │  │                                                               │     │ │
│  │  │  authorization ───► parse ───► Intent.verify() ───► Receipt  │     │ │
│  │  │       │                             │                         │     │ │
│  │  │       └─► None? ────────────────────┼─► Challenge (402)       │     │ │
│  │  └───────────────────────────────────────────────────────────────┘     │ │
│  │                          │                                              │ │
│  │                          ▼                                              │ │
│  │  ┌───────────────────────────────────────────────────────────────┐     │ │
│  │  │               @requires_payment                               │     │ │
│  │  │                                                               │     │ │
│  │  │  Decorator for Starlette/FastAPI/Django endpoints            │     │ │
│  │  │  Extracts Authorization, calls verify_or_challenge            │     │ │
│  │  │  Returns 402 or calls handler with (credential, receipt)      │     │ │
│  │  └───────────────────────────────────────────────────────────────┘     │ │
│  │                          │                                              │ │
│  │                          ▼                                              │ │
│  │  ┌───────────────────────────────────────────────────────────────┐     │ │
│  │  │                    Intent (Protocol)                          │     │ │
│  │  │                                                               │     │ │
│  │  │   name: str                                                   │     │ │
│  │  │   verify(credential, request) -> Receipt                      │     │ │
│  │  └───────────────────────────────────────────────────────────────┘     │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                     TEMPO METHOD                                         │ │
│  │                                                                         │ │
│  │  ┌──────────────────────┐    ┌──────────────────────┐                  │ │
│  │  │     TempoMethod      │    │    ChargeIntent      │                  │ │
│  │  ├──────────────────────┤    ├──────────────────────┤                  │ │
│  │  │ name = "tempo"       │    │ name = "charge"      │                  │ │
│  │  │ account: TempoAccount│    │ rpc_url: str         │                  │ │
│  │  │ rpc_url: str         │    ├──────────────────────┤                  │ │
│  │  ├──────────────────────┤    │ verify()             │                  │ │
│  │  │ create_credential()  │    │ _verify_hash()       │                  │ │
│  │  │ _build_tempo_transfer│    │ _verify_transaction()│                  │ │
│  │  └──────────────────────┘    │ _verify_transfer_logs│                  │ │
│  │                              └──────────────────────┘                  │ │
│  │                                                                         │ │
│  │  Supported credential payload types:                                    │ │
│  │    • hash: { type: "hash", hash: "0x..." }                             │ │
│  │    • transaction: { type: "transaction", signature: "0x..." }          │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                     EXTENSIONS                                           │ │
│  │                                                                         │ │
│  │  extensions/mcp/                                                        │ │
│  │    • MCP transport support                                              │ │
│  │    • @requires_mcp_payment decorator                                    │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

### TypeScript SDK Object Graph

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              mpay (TypeScript)                                │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                          CORE TYPES + SCHEMAS                            │ │
│  │                                                                         │ │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │ │
│  │  │    Challenge    │  │   Credential    │  │     Receipt     │         │ │
│  │  │   (Zod schema)  │  │   (Zod-aware)   │  │   (Zod schema)  │         │ │
│  │  ├─────────────────┤  ├─────────────────┤  ├─────────────────┤         │ │
│  │  │ id: string      │  │ challenge ◄────┼──┤ method: string  │         │ │
│  │  │ realm: string   │  │ (full embed)   │  │ status          │         │ │
│  │  │ method: string  │  │ payload: T     │  │ timestamp       │         │ │
│  │  │ intent: string  │  │ source?: DID   │  │ reference       │         │ │
│  │  │ request: T      │  └─────────────────┘  └─────────────────┘         │ │
│  │  │ digest?: ^sha-256│                                                   │ │
│  │  │ expires?: ISO   │                                                   │ │
│  │  │ description?    │                                                   │ │
│  │  ├─────────────────┤                                                   │ │
│  │  │ HMAC-bound IDs: │                                                   │ │
│  │  │ from({secretKey})                                                   │ │
│  │  │ verify({secretKey})                                                 │ │
│  │  └─────────────────┘                                                   │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                       INTENT ARCHITECTURE                                │ │
│  │                                                                         │ │
│  │  ┌──────────────────────┐        ┌────────────────────────────────┐    │ │
│  │  │       Intent         │        │        MethodIntent            │    │ │
│  │  │ (method-agnostic)    │◄───────│    (method-specific)           │    │ │
│  │  ├──────────────────────┤        ├────────────────────────────────┤    │ │
│  │  │ name: string         │        │ method: string                 │    │ │
│  │  │ schema.request       │        │ name: string                   │    │ │
│  │  └──────────────────────┘        │ schema.credential.payload      │    │ │
│  │         │                        │ schema.request (merged)        │    │ │
│  │         ├── Intent.charge        │   - requires: ['recipient']    │    │ │
│  │         ├── Intent.authorize     │   - methodDetails: {...}       │    │ │
│  │         └── Intent.subscription  └────────────────────────────────┘    │ │
│  │                                           │                            │ │
│  │                                           ├── tempo/charge             │ │
│  │                                           ├── tempo/authorize          │ │
│  │                                           └── tempo/subscription       │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                          METHOD SYSTEM                                   │ │
│  │                                                                         │ │
│  │  ┌────────────────────────────────────────────────────────────────┐    │ │
│  │  │                    Method (base)                                │    │ │
│  │  │                                                                │    │ │
│  │  │   name: string                                                 │    │ │
│  │  │   intents: { charge, authorize, subscription }                 │    │ │
│  │  └─────────────────┬──────────────────────┬───────────────────────┘    │ │
│  │                    │                      │                            │ │
│  │      ┌─────────────▼────────────┐ ┌──────▼─────────────────┐          │ │
│  │      │  Method.toClient(...)    │ │ Method.toServer(...)   │          │ │
│  │      ├──────────────────────────┤ ├────────────────────────┤          │ │
│  │      │ context?: ZodSchema      │ │ context?: ZodSchema    │          │ │
│  │      │ createCredential({       │ │ request?(options)      │          │ │
│  │      │   challenge, context     │ │ verify({credential,    │          │ │
│  │      │ }) -> string             │ │   request, context})   │          │ │
│  │      └──────────────────────────┘ │   -> Receipt           │          │ │
│  │                                   └────────────────────────┘          │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                          CLIENT                                          │ │
│  │                                                                         │ │
│  │  ┌────────────────────────────────────────────────────────────────┐    │ │
│  │  │                  Mpay.create({ methods, transport })            │    │ │
│  │  ├────────────────────────────────────────────────────────────────┤    │ │
│  │  │ methods: [tempo(...), ...]                                     │    │ │
│  │  │ transport: http() | mcp()                                      │    │ │
│  │  ├────────────────────────────────────────────────────────────────┤    │ │
│  │  │ createCredential(response, context?) -> Promise<string>        │    │ │
│  │  │   - transport.getChallenge(response)                           │    │ │
│  │  │   - route to method.createCredential                           │    │ │
│  │  └────────────────────────────────────────────────────────────────┘    │ │
│  │                          │                                              │ │
│  │                          ▼                                              │ │
│  │  ┌────────────────────────────────────────────────────────────────┐    │ │
│  │  │              Transport (abstraction)                           │    │ │
│  │  ├────────────────────────────────────────────────────────────────┤    │ │
│  │  │ isPaymentRequired(response)                                    │    │ │
│  │  │ getChallenge(response) -> Challenge                            │    │ │
│  │  │ setCredential(request, credential) -> request                  │    │ │
│  │  ├────────────────────────────────────────────────────────────────┤    │ │
│  │  │ • Transport.http() - fetch/Response                            │    │ │
│  │  │ • Transport.mcp()  - JSON-RPC                                  │    │ │
│  │  └────────────────────────────────────────────────────────────────┘    │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                          SERVER                                          │ │
│  │                                                                         │ │
│  │  ┌────────────────────────────────────────────────────────────────┐    │ │
│  │  │         Mpay.create({ method, realm, secretKey, transport })   │    │ │
│  │  ├────────────────────────────────────────────────────────────────┤    │ │
│  │  │ Returns handler with per-intent functions:                     │    │ │
│  │  │   payment.charge({ request, expires?, description? })          │    │ │
│  │  │   payment.authorize({ request, ... })                          │    │ │
│  │  │   payment.subscription({ request, ... })                       │    │ │
│  │  ├────────────────────────────────────────────────────────────────┤    │ │
│  │  │ Each intent function:                                          │    │ │
│  │  │   1. Recomputes challenge with HMAC-bound ID                   │    │ │
│  │  │   2. Extracts credential via transport                         │    │ │
│  │  │   3. Validates challenge HMAC (stateless!)                     │    │ │
│  │  │   4. Validates payload against intent schema                   │    │ │
│  │  │   5. Calls method.verify()                                     │    │ │
│  │  │   6. Returns { status: 402, challenge } or                     │    │ │
│  │  │              { status: 200, withReceipt(response) }            │    │ │
│  │  └────────────────────────────────────────────────────────────────┘    │ │
│  │                          │                                              │ │
│  │                          ▼                                              │ │
│  │  ┌────────────────────────────────────────────────────────────────┐    │ │
│  │  │              Server Transport (abstraction)                    │    │ │
│  │  ├────────────────────────────────────────────────────────────────┤    │ │
│  │  │ getCredential(input) -> Credential | null                      │    │ │
│  │  │ respondChallenge({ challenge, input, error })                  │    │ │
│  │  │ respondReceipt({ receipt, response, challengeId })             │    │ │
│  │  └────────────────────────────────────────────────────────────────┘    │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                     TEMPO METHOD                                         │ │
│  │                                                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │  │                     Intents.ts                                   │   │ │
│  │  │                                                                 │   │ │
│  │  │  tempo/charge = MethodIntent.fromIntent(Intent.charge, {        │   │ │
│  │  │    method: 'tempo',                                             │   │ │
│  │  │    schema: {                                                    │   │ │
│  │  │      credential.payload: { hash | transaction }                 │   │ │
│  │  │      request: {                                                 │   │ │
│  │  │        requires: ['recipient', 'expires'],                      │   │ │
│  │  │        methodDetails: { chainId?, feePayer?, memo? }            │   │ │
│  │  │      }                                                          │   │ │
│  │  │    }                                                            │   │ │
│  │  │  })                                                             │   │ │
│  │  │                                                                 │   │ │
│  │  │  tempo/authorize = MethodIntent.fromIntent(Intent.authorize...) │   │ │
│  │  │  tempo/subscription = MethodIntent.fromIntent(...)              │   │ │
│  │  └─────────────────────────────────────────────────────────────────┘   │ │
│  │                                                                         │ │
│  │  ┌──────────────────────┐    ┌──────────────────────┐                  │ │
│  │  │  tempo/client/Method │    │ tempo/server/Method  │                  │ │
│  │  ├──────────────────────┤    ├──────────────────────┤                  │ │
│  │  │ Uses viem for:       │    │ Uses viem for:       │                  │ │
│  │  │ - prepareTransactionRequest                     │ │                  │ │
│  │  │ - signTransaction    │    │ - parseEventLogs    │                  │ │
│  │  │                      │    │ - getTransactionReceipt               │ │
│  │  │ Supports:            │    │ - sendRawTransactionSync              │ │
│  │  │ - Per-call account   │    │                      │                  │ │
│  │  │   context            │    │ Validates:           │                  │ │
│  │  │                      │    │ - Transfer logs      │                  │ │
│  │  │                      │    │ - TransferWithMemo   │                  │ │
│  │  │                      │    │ - Transaction struct │                  │ │
│  │  │                      │    │   (preflight check)  │                  │ │
│  │  └──────────────────────┘    └──────────────────────┘                  │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Feature Comparison Matrix

| Feature | Python SDK | TypeScript SDK | Impact |
|---------|------------|----------------|--------|
| **Core Types** | | | |
| Challenge dataclass/type | ✅ dataclass | ✅ Zod schema | TS has runtime validation |
| Credential embeds challenge | ❌ ID only | ✅ Full challenge | **Security gap in Python** |
| Receipt includes method | ❌ | ✅ | TS has richer receipts |
| realm as first-class field | ❌ (serialize param) | ✅ | TS more complete |
| HMAC-bound challenge IDs | ❌ Random IDs | ✅ `Challenge.verify()` | **Security gap in Python** |
| **Intents** | | | |
| charge intent | ✅ | ✅ | |
| authorize intent | ❌ | ✅ | Python missing |
| subscription intent | ❌ | ✅ | Python missing |
| Schema-driven intents | ❌ Protocol only | ✅ MethodIntent.fromIntent | TS more type-safe |
| methodDetails support | Partial | ✅ Full | Python lacks memo validation |
| **Client** | | | |
| Auto-retry on 402 | ✅ PaymentTransport | ❌ Manual retry | Python more ergonomic |
| HTTP transport | ✅ httpx | ✅ fetch | |
| MCP transport | ✅ extensions/mcp | ✅ Transport.mcp() | |
| Per-call context schema | ❌ | ✅ Zod | |
| **Server** | | | |
| Main entry point | `verify_or_challenge()` | `Mpay.create()` | Different patterns |
| Decorator support | ✅ `@requires_payment` | ❌ | Python more ergonomic |
| Stateless verification | ❌ | ✅ HMAC | **Security gap in Python** |
| Structured errors | ❌ | ✅ Error taxonomy | TS more explicit |
| Node.js HTTP listener | N/A | ✅ `toNodeListener()` | |
| **Tempo Method** | | | |
| hash credential | ✅ | ✅ | |
| transaction credential | ✅ | ✅ | |
| keyAuthorization credential | ❌ | ✅ (authorize) | Python missing |
| memo (TransferWithMemo) | ❌ | ✅ | **Missing in Python** |
| fee payer (server-side) | Service URL proxy | Local signing | Different approaches |
| Preflight tx validation | ❌ Post-receipt | ✅ Pre-send | TS safer |

---

## Critical Divergences

### 1. Stateless Challenge Verification (CRITICAL)

**TypeScript:**
```typescript
// Challenge ID is HMAC-SHA256(secret, realm|method|intent|request|expires|digest)
const challenge = Challenge.from({ ..., secretKey })

// Verification without database lookup
Challenge.verify(credential.challenge, { secretKey }) // true/false
```

**Python:**
```python
# Challenge ID is random
challenge = Challenge(id=secrets.token_urlsafe(16), ...)

# No verification mechanism - id is never validated!
```

**Risk:** Python cannot verify that a credential was issued by this server or for the same request parameters.

### 2. Credential Structure

**TypeScript Credential (wire format):**
```json
{
  "challenge": { "id": "...", "realm": "...", "method": "...", ... },
  "payload": { "signature": "0x..." },
  "source": "did:pkh:eip155:1:0x..."
}
```

**Python Credential (wire format):**
```json
{
  "id": "...",        // Just the challenge ID, not full challenge
  "payload": {...},
  "source": "..."
}
```

**Risk:** Python credentials require server-side state or trust client's request parameters.

### 3. Intent Schema Validation

**TypeScript:**
```typescript
// Centralized schema with requires + methodDetails
const tempoCharge = MethodIntent.fromIntent(Intent.charge, {
  method: 'tempo',
  schema: {
    credential: { payload: z.discriminatedUnion('type', [...]) },
    request: {
      requires: ['recipient', 'expires'],
      methodDetails: z.object({ chainId, feePayer, memo })
    }
  }
})
```

**Python:**
```python
# Schema lives in intent implementation
class ChargeIntent:
    name = "charge"
    
    async def verify(self, credential, request):
        req = ChargeRequest.model_validate(request)  # Pydantic inside
```

**Impact:** TS provides type-safe contracts at framework level; Python relies on implementation correctness.

### 4. Transaction Validation Timing

**TypeScript (pre-send validation):**
```typescript
// Validate before sending
if (calls.length !== 1) throw new MismatchError(...)
if (!Address.isEqual(call.to, currency)) throw new MismatchError(...)
const [to, amount] = AbiFunction.decodeData(transfer, call.data)
// ... then send
```

**Python (post-receipt validation):**
```python
# Send first, validate logs after
tx_hash = result.get("result")
# ... poll for receipt ...
if not self._verify_transfer_logs(receipt_data, request):
    raise VerificationError(...)
```

**Impact:** TS rejects bad transactions earlier; Python may broadcast invalid transactions.

---

## API Ergonomics Comparison

### Client Usage

**Python (automatic retry - very ergonomic):**
```python
async with Client(methods=[tempo(account=account)]) as client:
    response = await client.get("https://api.example.com/resource")
    # 402 handling is automatic!
```

**TypeScript (manual retry):**
```typescript
const response = await fetch('/resource')
if (response.status === 402) {
    const credential = await mpay.createCredential(response, { account })
    await fetch('/resource', { headers: { Authorization: credential } })
}
```

### Server Usage

**Python (decorator - very ergonomic):**
```python
@requires_payment(
    intent=ChargeIntent(rpc_url="..."),
    request={"amount": "1000", ...},
    realm="api.example.com",
)
async def handler(request, credential, receipt):
    return {"data": "..."}
```

**TypeScript (handler factory):**
```typescript
const payment = Mpay.create({ method: tempo(...), realm: "...", secretKey })

async function handler(req: Request) {
    const result = await payment.charge({ request: {...} })(req)
    if (result.status === 402) return result.challenge
    return result.withReceipt(Response.json({ data: "..." }))
}
```

---

## Recommendations

### For Python SDK (Priority Order)

1. **Add HMAC-bound challenge IDs** - Critical security improvement
2. **Embed full challenge in credential** - Enables stateless verification  
3. **Add `realm` as first-class Challenge field** - Protocol alignment
4. **Add authorize/subscription intents** - Feature parity
5. **Add TransferWithMemo validation** - Tempo method completeness
6. **Add preflight transaction validation** - Defense in depth

### For TypeScript SDK

1. **Add auto-retry transport option** - Improve client ergonomics
2. **Add decorator/middleware pattern** - Simpler server integration

---

## Summary

The **TypeScript SDK** is more mature with:
- Schema-driven type safety
- Stateless HMAC verification
- Complete intent support
- Stricter validation

The **Python SDK** offers:
- Simpler Protocol-based design
- Better client ergonomics (auto-retry)
- Easier server integration (@decorator)
- But lacks security properties for production use

**Recommendation:** The Python SDK should prioritize implementing HMAC-bound challenge verification and embedded credentials before production deployment.
