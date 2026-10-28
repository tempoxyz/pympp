"""Local fee-payer co-signing for sponsored Tempo transactions.

Shared by the charge intent and TIP-1034 sessions: decode a sender-signed 0x78
fee payer envelope, enforce the sponsor policy, co-sign it as 0x76, and
simulate the co-signed transaction before broadcast.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from mpp._typing import is_dict, is_list
from mpp.errors import InternalPaymentError, VerificationError
from mpp.methods.tempo._defaults import PATH_USD
from mpp.methods.tempo.fee_payer_policy import MIN_REMAINING_VALIDITY_SECONDS, Policy

if TYPE_CHECKING:
    from mpp.methods.tempo.account import TempoAccount

EXPIRING_NONCE_KEY = (1 << 256) - 1


def assert_not_expired(valid_before: int) -> None:
    """Reject a sponsored transaction whose `valid_before` has passed."""
    if valid_before <= int(time.time()):
        raise VerificationError(
            f"Fee payer envelope expired: valid_before ({valid_before}) is not in the future"
        )


def assert_remaining_validity(valid_before: int) -> None:
    """Reject a sponsored transaction that could expire before it is included."""
    assert_not_expired(valid_before)
    # Leave time to simulate, broadcast and include the sponsored transaction.
    if valid_before < math.ceil(time.time()) + MIN_REMAINING_VALIDITY_SECONDS:
        raise VerificationError(
            "Invalid transaction: fee-sponsored transaction needs at least "
            f"{MIN_REMAINING_VALIDITY_SECONDS} seconds of remaining validity"
        )


def rpc_error_message(result: dict[str, Any]) -> str:
    """Extract the error message from a JSON-RPC error response."""
    error_obj = result["error"]
    if is_dict(error_obj):
        msg = error_obj.get("message") or error_obj.get("name") or str(error_obj)
        data = error_obj.get("data", "")
        return f"{msg}: {data}" if data else msg
    return str(error_obj)


def cosign_fee_payer_envelope(
    raw_tx: str,
    *,
    fee_payer: TempoAccount,
    policy: Callable[[int], Policy],
    fee_token: str | None = None,
    validate_calls: Callable[[tuple[Any, ...]], None] | None = None,
    require_remaining_validity: bool = True,
    allow_expired: bool = False,
    allowed_fee_tokens: Sequence[str] | None = None,
    max_valid_before: int | None = None,
) -> tuple[str, Any, str]:
    """Co-sign a client-signed 0x78 fee payer envelope as fee payer.

    `policy` maps the transaction's chain ID to its sponsor policy.
    Returns `(raw_0x76_hex, cosigned_transaction, sender)`, where `sender` is the
    recovered (checksummed) sender address.

    The envelope must not set a fee token unless `allowed_fee_tokens` is given,
    in which case a fee token it sets must be in that list (TIP-1034 session
    clients name the channel token, as mppx does). The co-signed transaction
    pays fees in the envelope's fee token, else `fee_token`, else pathUSD.

    Authorization-bearing envelopes are rejected before signing because their
    authorization fields cannot yet be faithfully simulated. With
    `require_remaining_validity=False` only an already expired `valid_before` is
    rejected; with `allow_expired=True` as well, an expired one is not either.
    `max_valid_before` further caps `valid_before` (such as the challenge expiry).
    """
    # pytempo ships no type information.
    import attrs
    from pytempo import Call, TempoTransaction  # pyright: ignore[reportMissingTypeStubs]
    from pytempo.models import (  # pyright: ignore[reportMissingTypeStubs]
        Signature,
        as_address,
    )

    from mpp.methods.tempo.fee_payer_envelope import decode_fee_payer_envelope

    try:
        all_bytes = bytes.fromhex(raw_tx[2:] if raw_tx.startswith("0x") else raw_tx)
        decoded, sender_addr_bytes, sender_sig, key_auth = decode_fee_payer_envelope(all_bytes)
    except Exception as err:
        raise VerificationError("Failed to deserialize client transaction") from err

    if key_auth is not None or decoded[12]:
        raise VerificationError(
            "Authorization-bearing transactions cannot be simulated and are not "
            "supported by local fee-payer cosigning"
        )

    # Cosigning recovers the sender via secp256k1 ECDSA, so only a raw
    # 65-byte signature is supported; other envelopes (keychain, P256,
    # WebAuthn) are rejected up front.
    if len(sender_sig) != 65:
        if sender_sig and sender_sig[0] in (0x03, 0x04):
            raise VerificationError(
                "Access-key (keychain) signed fee-payer envelopes are not "
                "supported by local cosigning"
            )
        raise VerificationError(
            "Only 65-byte secp256k1 sender signatures are supported by local fee-payer cosigning"
        )

    def _int(b: bytes) -> int:
        return int.from_bytes(b, "big") if b else 0

    # Fee-payer invariants (matches mpp-rs cosign_fee_payer_transaction)
    envelope_fee_token: bytes | None = decoded[10] or None
    if envelope_fee_token is not None:
        if allowed_fee_tokens is None:
            raise VerificationError(
                "Fee payer transaction must not include fee_token (server sets it)"
            )
        if len(envelope_fee_token) != 20 or "0x" + envelope_fee_token.hex() not in {
            token.lower() for token in allowed_fee_tokens
        }:
            raise VerificationError(
                "Invalid transaction: fee-sponsored transaction feeToken is not allowed"
            )

    nonce_key = _int(decoded[6])
    if nonce_key != EXPIRING_NONCE_KEY:
        raise VerificationError("Fee payer envelope must use expiring nonce key (U256::MAX)")

    valid_before_raw = decoded[8]
    if not valid_before_raw:
        raise VerificationError("Fee payer envelope must include valid_before")
    valid_before = _int(valid_before_raw)
    if require_remaining_validity:
        assert_remaining_validity(valid_before)
    elif not allow_expired:
        assert_not_expired(valid_before)

    chain_id = _int(decoded[0])
    sponsor_policy = policy(chain_id)

    gas_limit = _int(decoded[3])
    if gas_limit > sponsor_policy.max_gas:
        raise VerificationError("Invalid transaction: gas limit exceeds sponsor policy")

    max_priority_fee_per_gas = _int(decoded[1])
    max_fee_per_gas = _int(decoded[2])
    if max_fee_per_gas > sponsor_policy.max_fee_per_gas:
        raise VerificationError("Invalid transaction: max fee per gas exceeds sponsor policy")
    if max_priority_fee_per_gas > max_fee_per_gas:
        raise VerificationError(
            "Invalid transaction: max priority fee per gas exceeds max fee per gas"
        )
    if max_priority_fee_per_gas > sponsor_policy.max_priority_fee_per_gas:
        raise VerificationError(
            "Invalid transaction: max priority fee per gas exceeds sponsor policy"
        )
    if gas_limit * max_fee_per_gas > sponsor_policy.max_total_fee:
        raise VerificationError("Invalid transaction: total fee budget exceeds sponsor policy")
    if valid_before > int(time.time()) + sponsor_policy.max_validity_window_seconds or (
        max_valid_before is not None and valid_before > max_valid_before
    ):
        raise VerificationError("Invalid transaction: validity window exceeds sponsor policy")

    if decoded[5]:
        raise VerificationError("Invalid transaction: access list is not allowed")

    calls = tuple(Call(to=c[0], value=_int(c[1]), data=c[2]) for c in decoded[4])

    if validate_calls is not None:
        validate_calls(calls)

    tx_for_recovery = TempoTransaction(
        chain_id=chain_id,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
        max_fee_per_gas=max_fee_per_gas,
        gas_limit=gas_limit,
        calls=calls,
        access_list=(),
        nonce_key=_int(decoded[6]),
        nonce=_int(decoded[7]),
        valid_before=_int(decoded[8]) if decoded[8] else None,
        valid_after=_int(decoded[9]) if decoded[9] else None,
        fee_token=envelope_fee_token,
        # Part of the sender's signing hash; must be carried through.
        tempo_authorization_list=tuple(decoded[12]),
        awaiting_fee_payer=True,
        key_authorization=key_auth,  # type: ignore[arg-type]
    )
    sender_hash = tx_for_recovery.get_signing_hash(for_fee_payer=False)

    from eth_account import Account

    try:
        recovered_address = Account._recover_hash(sender_hash, signature=sender_sig)  # pyright: ignore[reportPrivateUsage]
    except Exception as err:
        raise VerificationError("Invalid sender signature") from err
    envelope_address = "0x" + sender_addr_bytes.hex()

    if recovered_address.lower() != envelope_address.lower():
        raise VerificationError("Sender address does not match recovered signer")

    tx_to_sign = attrs.evolve(
        tx_for_recovery,
        sender_signature=Signature(
            r=int.from_bytes(sender_sig[:32], "big"),
            s=int.from_bytes(sender_sig[32:64], "big"),
            v=sender_sig[64],
        ),
        sender_address=as_address(recovered_address),
        fee_token=envelope_fee_token or fee_token or PATH_USD,
    )

    try:
        cosigned = tx_to_sign.sign(fee_payer.private_key, for_fee_payer=True)
    except Exception as err:
        raise InternalPaymentError() from err

    return "0x" + cosigned.encode().hex(), cosigned, recovered_address


def build_simulate_payload(tx: Any, sender: str) -> dict[str, Any]:
    """Build a `tempo_simulateV1` payload for a co-signed 0x76 transaction.

    Carries the recovered sender as `from` (the node needs it to model the
    sender) plus the sponsor fields (`feeToken`, `feePayerSignature`) so the node
    simulates the same transaction about to be broadcast.

    Must not be called for a transaction that carries a `key_authorization` or a
    non-empty `tempo_authorization_list`: those fields cannot yet be faithfully
    serialized here, so the payload would describe a different transaction than
    the one broadcast. Local cosigning rejects these envelopes before signing.
    """
    if getattr(tx, "key_authorization", None) is not None or getattr(
        tx, "tempo_authorization_list", ()
    ):
        raise VerificationError(
            "Cannot build a faithful tempo_simulateV1 payload for an "
            "authorization-bearing transaction"
        )

    sig = tx.fee_payer_signature
    parity = sig.v if sig.v in (0, 1) else sig.v - 27

    # The node rebuilds the batch as `calls[]` followed by the top-level call
    # appended last; an absent top-level `to` is read as a CREATE and rejected.
    # So the final call goes top-level and the rest in `calls` to keep order.
    last_call = tx.calls[-1]
    leading_calls = tx.calls[:-1]

    tx_request: dict[str, Any] = {
        "from": sender,
        "type": "0x76",
        "chainId": hex(tx.chain_id),
        "nonce": hex(tx.nonce),
        "nonceKey": hex(tx.nonce_key),
        "gas": hex(tx.gas_limit),
        "maxFeePerGas": hex(tx.max_fee_per_gas),
        "maxPriorityFeePerGas": hex(tx.max_priority_fee_per_gas),
        "feeToken": "0x" + bytes(tx.fee_token).hex(),
        "feePayerSignature": {
            # Fixed 32-byte r/s so leading zeros are not dropped.
            "r": f"0x{sig.r:064x}",
            "s": f"0x{sig.s:064x}",
            "yParity": hex(parity),
        },
        # Top-level final call so the node does not read this as a CREATE.
        "to": "0x" + bytes(last_call.to).hex(),
        "value": hex(last_call.value),
        "data": "0x" + last_call.data.hex(),
    }
    if leading_calls:
        tx_request["calls"] = [
            {
                "to": "0x" + bytes(c.to).hex(),
                "value": hex(c.value),
                "data": "0x" + c.data.hex(),
            }
            for c in leading_calls
        ]
    if tx.valid_before is not None:
        tx_request["validBefore"] = hex(tx.valid_before)
    if tx.valid_after is not None:
        tx_request["validAfter"] = hex(tx.valid_after)

    return {
        "blockStateCalls": [{"calls": [tx_request]}],
        # Only the execution outcome matters, not mempool admission.
        "validation": False,
        "traceTransfers": False,
        "returnFullTransactions": False,
    }


async def simulate_before_broadcast(
    client: Any, simulate_payload: dict[str, Any], rpc_url: str
) -> None:
    """Simulate a co-signed transaction and raise if it would revert.

    Fails closed: any RPC or transport error is treated as a failed check.
    """
    try:
        response = await client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "tempo_simulateV1",
                "params": [simulate_payload, "latest"],
                "id": 1,
            },
        )
        response.raise_for_status()
        result = response.json()
    except Exception as err:
        raise InternalPaymentError() from err

    if "error" in result:
        raise InternalPaymentError() from RuntimeError(
            f"Pre-broadcast simulation failed: {rpc_error_message(result)}"
        )

    rpc_result = result.get("result")
    blocks = rpc_result.get("blocks") if is_dict(rpc_result) else None
    block0 = blocks[0] if is_list(blocks) and blocks else None
    calls = block0.get("calls") if is_dict(block0) else None
    call: dict[Any, Any] | None = None
    if is_list(calls) and calls and is_dict(calls[0]):
        call = calls[0]
    if call is None:
        raise InternalPaymentError() from RuntimeError(
            "Pre-broadcast simulation returned no call results"
        )

    status = call.get("status")
    if status in ("0x1", 1, True):
        return

    call_error: dict[str, Any] = call.get("error") or {}
    detail = call_error.get("message") or "no revert reason returned"
    raise VerificationError(
        f"Sponsored transaction would revert in pre-broadcast simulation: {detail}"
    )
