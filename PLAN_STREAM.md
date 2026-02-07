# Plan: Add Stream Payment Intent to mpay-python

## Overview

Port the Tempo stream payment intent from the TypeScript mpay reference to pympay. This adds pay-as-you-go streaming payment channels using on-chain escrow contracts and off-chain EIP-712 vouchers.

## Key Changes

### New Files

1. **`src/mpay/methods/tempo/stream/`** — New subpackage for stream-specific logic
   - `__init__.py` — Exports
   - `types.py` — Dataclasses: `Voucher`, `SignedVoucher`, `StreamCredentialPayload` (discriminated union), `StreamReceipt`
   - `voucher.py` — EIP-712 voucher signing (`sign_voucher`) and verification (`verify_voucher`) using `eth_account.sign_typed_data` / `encode_typed_data` + `recover_message`
   - `storage.py` — `ChannelState`, `SessionState` dataclasses and `ChannelStorage` protocol (abstract interface with atomic update callbacks), plus `MemoryStorage` implementation
   - `chain.py` — On-chain escrow contract interaction via JSON-RPC: `get_on_chain_channel`, `broadcast_open_transaction`, `broadcast_top_up_transaction`, `settle_on_chain`, `close_on_chain`. ABI encoding/decoding for the TempoStreamChannel contract
   - `receipt.py` — `create_stream_receipt`, `serialize_stream_receipt`, `deserialize_stream_receipt`
   - `errors.py` — Stream-specific error classes: `InsufficientBalanceError`, `InvalidSignatureError`, `AmountExceedsDepositError`, `DeltaTooSmallError`, `ChannelNotFoundError`, `ChannelClosedError`, `ChannelConflictError`

2. **`src/mpay/methods/tempo/stream_client.py`** — Client-side stream credential creation
   - Auto-management mode (with `deposit` parameter): handles channel open, incremental vouchers, channel recovery
   - Manual mode: caller provides explicit action (open/topUp/voucher/close) with parameters

3. **`src/mpay/methods/tempo/stream_server.py`** — Server-side stream verification
   - 4 action handlers: `handle_open`, `handle_top_up`, `handle_voucher`, `handle_close`
   - Shared `verify_and_accept_voucher` logic
   - `charge()` function for deducting from session balance
   - `settle()` function for one-shot on-chain settlement

4. **`tests/test_stream.py`** — Comprehensive test suite mirroring TS tests
   - Tests for all 4 actions (open, voucher, topUp, close)
   - Full lifecycle test (open -> voucher -> voucher -> close)
   - Charge/settle tests
   - Monotonicity/TOCTOU unit tests
   - Error type tests

5. **`examples/stream-server/`** — FastAPI streaming server example
   - `server.py` — SSE endpoint with per-token charging
   - `client.py` — Client that opens channel and streams responses

### Modified Files

6. **`src/mpay/methods/tempo/__init__.py`** — Export new stream types: `StreamIntent`, `StreamMethod`, etc.

7. **`src/mpay/methods/tempo/client.py`** — Add `stream()` factory function to `TempoMethod` or as standalone, add stream intent support to `create_credential`

8. **`src/mpay/server/mpay.py`** — Add `stream()` method to `Mpay` class (mirrors `charge()`)

9. **`pyproject.toml`** — Add `eth-abi` to tempo extras if needed for ABI decoding (may already be transitive via pytempo)

## Key Design Decisions & Tradeoffs

### 1. EIP-712 Signing via eth_account (not pytempo)

The `eth_account` library (already a transitive dependency via pytempo) provides `sign_typed_data` and `recover_message` + `encode_typed_data` for EIP-712. This avoids adding new dependencies.

**Tradeoff**: We must manually construct the EIP-712 domain and types dict rather than using a typed builder. This is fragile but matches how the TS version works with viem.

### 2. ABI Encoding/Decoding via eth_abi

For escrow contract interactions (encoding `open()`, `topUp()` function calls and decoding `getChannel()` results), we use `eth_abi` which is already a transitive dependency. We do manual function selector computation via keccak256.

**Tradeoff**: No full contract abstraction (like web3.py Contract or viem). We manually encode/decode function calls. This is more work but avoids adding web3.py as a dependency, keeping the SDK lightweight.

### 3. Storage Protocol with Atomic Callbacks

Following the TS pattern exactly: `ChannelStorage` is a Protocol with `get_channel`, `get_session`, `update_channel`, `update_session`. The `update_*` methods take a callback function for atomic read-modify-write.

**Tradeoff**: Callback-based atomicity is slightly unusual in Python but faithfully mirrors the TS implementation and allows backends to implement their own atomicity guarantees.

### 4. Stream Method as Separate Class (not extending TempoMethod)

Create a `StreamMethod` class parallel to `TempoMethod` (or add stream as a second intent within `TempoMethod`). Following the TS pattern where `tempo.stream()` and `tempo.charge()` are separate method-intent configurations.

**Decision**: Add stream support as a new intent within the existing `TempoMethod` class, with a `stream()` factory function. The `create_credential` method dispatches on `challenge.intent`.

### 5. On-chain Interaction via JSON-RPC (no web3.py)

All on-chain interactions use raw JSON-RPC calls via httpx (same pattern as existing charge intent). This includes:
- `eth_call` for `getChannel()` and `computeChannelId()`
- `eth_sendRawTransaction` for broadcasting open/topUp transactions
- `eth_getTransactionReceipt` for confirming transactions
- Building TempoTransactions via pytempo for open/topUp

### 6. Tests: Unit Tests with Mocked Chain (not live node)

The TS tests run against a real local Tempo node. For Python, we'll:
- Use mocked JSON-RPC responses for chain interactions
- Test the business logic (voucher verification, storage state, error handling) thoroughly
- Provide a separate integration test example that can run against a real node

**Tradeoff**: Less coverage of actual on-chain behavior, but makes tests fast and CI-friendly. The integration example covers the E2E path.

## Key Data Structures & Interfaces

### StreamCredentialPayload (discriminated union on `action`)

```python
@dataclass
class OpenPayload:
    action: Literal["open"] = "open"
    type: Literal["transaction"] = "transaction"
    channel_id: str  # 0x-prefixed hex
    transaction: str  # RLP-encoded signed tx
    cumulative_amount: str  # decimal string
    signature: str  # EIP-712 voucher sig
    authorized_signer: str | None = None

@dataclass
class TopUpPayload:
    action: Literal["topUp"] = "topUp"
    type: Literal["transaction"] = "transaction"
    channel_id: str
    transaction: str
    additional_deposit: str

@dataclass
class VoucherPayload:
    action: Literal["voucher"] = "voucher"
    channel_id: str
    cumulative_amount: str
    signature: str

@dataclass
class ClosePayload:
    action: Literal["close"] = "close"
    channel_id: str
    cumulative_amount: str
    signature: str
```

**Note on naming**: The TS uses camelCase in the JSON payload (channelId, cumulativeAmount). The Python code must serialize to camelCase to match the protocol, but can use snake_case internally. Pydantic models with `alias` or simple dict construction handle this.

### ChannelState / SessionState

```python
@dataclass
class ChannelState:
    channel_id: str
    payer: str
    payee: str
    token: str
    authorized_signer: str
    deposit: int          # bigint in TS -> Python int
    settled_on_chain: int
    highest_voucher_amount: int
    highest_voucher: SignedVoucher | None
    active_session_id: str | None
    finalized: bool
    created_at: datetime

@dataclass
class SessionState:
    challenge_id: str
    channel_id: str
    accepted_cumulative: int
    spent: int
    units: int
    created_at: datetime
```

### ChannelStorage Protocol

```python
class ChannelStorage(Protocol):
    async def get_channel(self, channel_id: str) -> ChannelState | None: ...
    async def get_session(self, challenge_id: str) -> SessionState | None: ...
    async def update_channel(self, channel_id: str, fn: Callable[[ChannelState | None], ChannelState | None]) -> ChannelState | None: ...
    async def update_session(self, challenge_id: str, fn: Callable[[SessionState | None], SessionState | None]) -> SessionState | None: ...
```

### StreamReceipt

```python
@dataclass
class StreamReceipt:
    method: str = "tempo"
    intent: str = "stream"
    status: str = "success"
    timestamp: str  # ISO 8601
    reference: str  # channelId
    challenge_id: str
    channel_id: str
    accepted_cumulative: str  # decimal string
    spent: str  # decimal string
    units: int | None = None
    tx_hash: str | None = None
```

## Things I'm Unclear On

1. **pytempo's `sendRawTransactionSync`**: The TS version uses `sendRawTransactionSync` from viem/tempo which waits for the receipt. Does pytempo or the Tempo RPC support this? If not, we'll need to poll for the receipt (similar to the existing charge intent's polling pattern).

2. **Transaction deserialization for validation**: The TS server deserializes the client's transaction to validate the open/topUp calls. Does pytempo support `TempoTransaction.from_bytes()` or similar deserialization? If not, we may need to use `eth_rlp` or implement custom RLP decoding.

3. **Escrow contract addresses**: The TS version has default escrow contract addresses per chain. Need to determine the correct default escrow contract address for mainnet/testnet (or require it as a parameter).

4. **Fee payer for stream**: The TS version supports fee payer for open/topUp transactions (server co-signs). Need to check if pytempo supports co-signing/fee-payer addition to already-signed transactions.

## Things Awkward to Program Against

1. **EIP-712 with eth_account**: The `sign_typed_data` method requires dict-based types/domain (no schema validation). Must carefully match the exact EIP-712 domain name ("Tempo Stream Channel"), version ("1"), and Voucher type fields. A single typo will produce valid-looking but wrong signatures.

2. **No contract abstraction**: Without web3.py Contract objects, ABI encoding/decoding is manual. Function selectors must be computed, arguments padded, return values decoded by hand. This is error-prone but avoids the heavy web3.py dependency.

3. **Callback-based storage atomicity**: Python's async callbacks for `update_channel`/`update_session` are slightly awkward compared to TS where closures are idiomatic. Need to handle the case where a callback raises an exception (e.g., `ChannelConflictError` during the update callback).

4. **BigInt serialization**: Python's `int` is arbitrary precision (good for uint128), but must be careful about serialization. The protocol uses decimal strings (not hex) for amounts in credentials/receipts but hex for channel IDs and signatures.

5. **camelCase JSON**: Protocol requires camelCase field names in JSON payloads (channelId, cumulativeAmount, etc.) but Python convention is snake_case. Need consistent serialization strategy.

## Implementation Order

1. **Stream types & errors** (types.py, errors.py) — Foundation
2. **Voucher signing/verification** (voucher.py) — Core crypto
3. **Storage interface + MemoryStorage** (storage.py) — State management
4. **Chain interaction** (chain.py) — On-chain operations
5. **Receipt** (receipt.py) — Receipt creation/serialization
6. **Server-side stream intent** (stream_server.py) — Verification logic
7. **Client-side stream method** (stream_client.py) — Credential creation
8. **Mpay.stream()** (mpay.py) — High-level API
9. **Tests** (test_stream.py) — Full test suite
10. **Examples** (examples/stream-server/) — E2E example
11. **Exports & integration** (__init__.py updates)
