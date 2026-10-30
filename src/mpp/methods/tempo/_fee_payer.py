"""Fee-payer co-signing for sponsored Tempo transactions.

Shared by the charge intent and TIP-1034 sessions: decode a sender-signed 0x78
fee payer envelope, enforce the sponsor policy, co-sign it as 0x76 locally or
through a hosted fee payer, and simulate the co-signed transaction before
broadcast.
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

import attrs

from mpp._typing import is_dict, is_list
from mpp.errors import InternalPaymentError, VerificationError
from mpp.methods.tempo._defaults import PATH_USD
from mpp.methods.tempo.fee_payer_policy import MIN_REMAINING_VALIDITY_SECONDS, Policy

if TYPE_CHECKING:
    from mpp.methods.tempo.account import TempoAccount
    from mpp.methods.tempo.remote_fee_payer import RemoteFeePayer

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


@attrs.frozen
class _RawSenderSignature:
    """A serialized sender signature envelope that pytempo re-encodes unchanged.

    pytempo models only secp256k1 and keychain V2 sender signatures; P256,
    WebAuthn, keychain V1 and multisig envelopes are carried through as bytes.
    """

    _raw: bytes

    def to_bytes(self) -> bytes:
        return self._raw


_WEBAUTHN_MAX_DATA = 2048


def signature_envelope_signer(signature: bytes) -> str | None:
    """Return the lowercase account a non-secp256k1 signature envelope names.

    Keychain (0x03/0x04) signatures name their root account, P256 (0x01) and
    WebAuthn (0x02) signatures the address of their public key, and multisig
    (0x05) signatures their account. The chain authenticates the signature at
    settlement. Returns ``None`` for malformed or unknown envelopes.
    """
    from eth_hash.auto import keccak

    from mpp.methods.tempo import _rlp as rlp

    if len(signature) < 2:
        return None
    type_id, data = signature[0], signature[1:]
    if type_id in (0x03, 0x04):
        inner = data[20:]
        if len(inner) != 65 and not (
            inner[:1] in (b"\x01", b"\x02") and signature_envelope_signer(inner)
        ):
            return None
        return "0x" + data[:20].hex()
    if type_id == 0x01 and len(data) == 129:
        return "0x" + keccak(data[64:128])[-20:].hex()
    if type_id == 0x02 and 128 <= len(data) <= _WEBAUTHN_MAX_DATA:
        return "0x" + keccak(data[-64:])[-20:].hex()
    if type_id == 0x05:
        try:
            account = rlp.decode(data)[0]
        except Exception:
            return None
        if isinstance(account, bytes) and len(account) == 20:
            return "0x" + account.hex()
    return None


def _hex32(value: bytes) -> str:
    return "0x" + value.rjust(32, b"\x00").hex()


def _quantity(value: bytes) -> str:
    return hex(int.from_bytes(value, "big"))


def _address(value: object) -> str:
    if not isinstance(value, bytes) or len(value) != 20:
        raise ValueError("expected a 20-byte address")
    return "0x" + value.hex()


def _signature_rpc(signature: bytes) -> dict[str, Any] | str:
    """Render a key authorization's signature as JSON-RPC (ox ``SignatureEnvelope.toRpc``)."""
    if len(signature) == 65:
        v = signature[64]
        if v not in (0, 1, 27, 28):
            raise ValueError("invalid secp256k1 recovery id")
        return {
            "r": _hex32(signature[:32]),
            "s": _hex32(signature[32:64]),
            "yParity": hex(v % 27),
            "type": "secp256k1",
        }
    type_id, data = signature[0], signature[1:]
    if type_id == 0x01 and len(data) == 129:
        return {
            "preHash": data[128] != 0,
            "pubKeyX": _hex32(data[64:96]),
            "pubKeyY": _hex32(data[96:128]),
            "r": _hex32(data[:32]),
            "s": _hex32(data[32:64]),
            "type": "p256",
        }
    if type_id == 0x02 and 128 <= len(data) <= _WEBAUTHN_MAX_DATA:
        tail = data[-128:]
        return {
            "pubKeyX": _hex32(tail[64:96]),
            "pubKeyY": _hex32(tail[96:]),
            "r": _hex32(tail[:32]),
            "s": _hex32(tail[32:64]),
            "type": "webAuthn",
            "webauthnData": "0x" + data[:-128].hex(),
        }
    if type_id == 0x05 and signature_envelope_signer(signature) is not None:
        return "0x" + data.hex()
    raise ValueError("unsupported key authorization signature")


_KEY_TYPES = {0: "secp256k1", 1: "p256", 2: "webAuthn", 3: "multisig"}


def _limits_rpc(limits: object) -> list[dict[str, str]]:
    if not is_list(limits):
        raise ValueError("malformed key authorization limits")
    rendered: list[dict[str, str]] = []
    for limit in limits:
        if not is_list(limit) or len(limit) not in (2, 3) or not isinstance(limit[1], bytes):
            raise ValueError("malformed key authorization limit")
        entry = {"token": _address(limit[0]), "limit": _quantity(limit[1])}
        if len(limit) == 3:
            if not isinstance(limit[2], bytes):
                raise ValueError("malformed key authorization limit")
            if any(limit[2]):
                entry["period"] = _quantity(limit[2])
        rendered.append(entry)
    return rendered


def _allowed_calls_rpc(allowed_calls: object) -> list[dict[str, Any]]:
    if not is_list(allowed_calls):
        raise ValueError("malformed key authorization allowed calls")
    scopes: list[dict[str, Any]] = []
    for scope in allowed_calls:
        if not is_list(scope) or len(scope) != 2 or not is_list(scope[1]):
            raise ValueError("malformed key authorization call scope")
        entry: dict[str, Any] = {"target": _address(scope[0])}
        rules: list[dict[str, Any]] = []
        for rule in scope[1]:
            if not is_list(rule) or len(rule) != 2:
                raise ValueError("malformed key authorization selector rule")
            selector, recipients = rule
            if not isinstance(selector, bytes) or len(selector) != 4 or not is_list(recipients):
                raise ValueError("malformed key authorization selector rule")
            rendered: dict[str, Any] = {"selector": "0x" + selector.hex()}
            if recipients:
                rendered["recipients"] = [_address(recipient) for recipient in recipients]
            rules.append(rendered)
        if rules:
            entry["selectorRules"] = rules
        scopes.append(entry)
    return scopes


def key_authorization_rpc(payload: object) -> dict[str, Any]:
    """Render a signed ``keyAuthorization`` RLP payload as its JSON-RPC object.

    Mirrors ox ``KeyAuthorization.toRpc``, so an ``eth_call`` simulates the key
    authorization the broadcast transaction carries. Raises ``ValueError`` for
    a malformed payload.
    """
    if not is_list(payload) or len(payload) != 2:
        raise ValueError("key authorization must be [authorization, signature]")
    fields, signature = payload
    if not is_list(fields) or not 3 <= len(fields) <= 9 or not isinstance(signature, bytes):
        raise ValueError("malformed key authorization")
    chain_id, key_type, key_id = fields[:3]
    trailing: list[Any] = [*fields[3:], *([b""] * (9 - len(fields)))]
    expiry, limits, allowed_calls, witness, is_admin, account = trailing
    if not all(isinstance(value, bytes) for value in (chain_id, key_type, expiry, is_admin)):
        raise ValueError("malformed key authorization")
    kind = _KEY_TYPES.get(int.from_bytes(key_type, "big"))
    if kind is None or not signature:
        raise ValueError("malformed key authorization")
    rpc: dict[str, Any] = {
        "chainId": _quantity(chain_id) if any(chain_id) else "0x",
        "expiry": _quantity(expiry) if any(expiry) else None,
        "keyId": _address(key_id),
        "keyType": kind,
        "signature": _signature_rpc(signature),
    }
    # ox omits an empty limits list (no spending allowed), but the broadcast
    # transaction carries it, so the simulation keeps it.
    if limits != b"":
        rpc["limits"] = _limits_rpc(limits)
    if allowed_calls != b"":
        rpc["allowedCalls"] = _allowed_calls_rpc(allowed_calls)
    if witness != b"":
        if not isinstance(witness, bytes) or len(witness) != 32:
            raise ValueError("malformed key authorization witness")
        rpc["witness"] = "0x" + witness.hex()
    if is_admin != b"":
        if is_admin != b"\x01":
            raise ValueError("invalid key authorization admin marker")
        rpc["isAdmin"] = True
    if account != b"":
        rpc["account"] = _address(account)
    elif kind == "multisig":
        raise ValueError("multisig key authorization must bind an account")
    return rpc


def sponsored_simulation_request(tx: Any, sender: str, fee_payer: str) -> dict[str, Any]:
    """The co-signed transaction as an ``eth_call`` request, without either signature.

    Mirrors mppx ``FeePayer.sponsoredSimulationTransaction``: the final
    transaction with its concrete fee payer and fee token, and its key
    authorization as viem formats it (ox ``KeyAuthorization.toRpc``).
    """
    request: dict[str, Any] = {
        "type": "0x76",
        "from": sender,
        "calls": [
            {"to": "0x" + bytes(c.to).hex(), "value": hex(c.value), "data": "0x" + c.data.hex()}
            for c in tx.calls
        ],
        "chainId": hex(tx.chain_id),
        "nonce": hex(tx.nonce),
        "nonceKey": hex(tx.nonce_key),
        "gas": hex(tx.gas_limit),
        "maxFeePerGas": hex(tx.max_fee_per_gas),
        "maxPriorityFeePerGas": hex(tx.max_priority_fee_per_gas),
        "feeToken": "0x" + bytes(tx.fee_token).hex(),
        # The node rejects ``feePayer: true`` in eth_call; name the sponsor.
        "feePayer": fee_payer,
    }
    if tx.valid_before is not None:
        request["validBefore"] = hex(tx.valid_before)
    if tx.valid_after is not None:
        request["validAfter"] = hex(tx.valid_after)
    key_authorization = getattr(tx, "key_authorization", None)
    if key_authorization is not None:
        request["keyAuthorization"] = key_authorization_rpc(key_authorization.as_rlp_payload())
    return request


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0


def assert_envelope_policy(
    decoded: list[Any],
    *,
    policy: Callable[[int], Policy],
    allowed_fee_tokens: Sequence[str] | None = None,
    require_remaining_validity: bool = True,
    allow_expired: bool = False,
    max_valid_before: int | None = None,
) -> None:
    """Enforce the sponsor policy on a decoded 0x78 envelope before anyone co-signs it.

    Shared by local co-signing and hosted fee payers, which must not be asked
    to sponsor a transaction the local policy refuses (as mppx's
    `assertTransactionPolicy` before `fillHostedFeePayerTransaction`).
    """
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


def envelope_transaction(
    decoded: list[Any], *, fee_token: str | bytes | None = None, key_authorization: Any = None
) -> Any:
    """Return the unsigned pytempo transaction a decoded 0x78 envelope describes.

    The fee token is the envelope's, else `fee_token`.
    """
    from pytempo import Call, TempoTransaction  # pyright: ignore[reportMissingTypeStubs]

    return TempoTransaction(
        chain_id=_int(decoded[0]),
        max_priority_fee_per_gas=_int(decoded[1]),
        max_fee_per_gas=_int(decoded[2]),
        gas_limit=_int(decoded[3]),
        calls=tuple(Call(to=c[0], value=_int(c[1]), data=c[2]) for c in decoded[4]),
        access_list=(),
        nonce_key=_int(decoded[6]),
        nonce=_int(decoded[7]),
        valid_before=_int(decoded[8]) if decoded[8] else None,
        valid_after=_int(decoded[9]) if decoded[9] else None,
        fee_token=decoded[10] or fee_token or None,
        # Part of the sender's signing hash; must be carried through.
        tempo_authorization_list=tuple(decoded[12]),
        awaiting_fee_payer=True,
        key_authorization=key_authorization,
    )


def decode_sponsored_envelope(raw_tx: str) -> tuple[list[Any], bytes, bytes, Any]:
    """Decode a client's 0x78 envelope for sponsorship, local or hosted.

    Returns ``(decoded_fields, sender_address, sender_signature, key_authorization)``.
    Like mppx's ``prepareSponsoredTransaction``, a key authorization is carried
    through (and must render as JSON-RPC, for the simulation), while an
    authorization list is refused as an unsupported field.
    """
    from mpp.methods.tempo.fee_payer_envelope import decode_fee_payer_envelope

    try:
        all_bytes = bytes.fromhex(raw_tx[2:] if raw_tx.startswith("0x") else raw_tx)
        decoded, sender_addr_bytes, sender_sig, key_auth = decode_fee_payer_envelope(all_bytes)
    except Exception as err:
        raise VerificationError("Failed to deserialize client transaction") from err

    if decoded[12]:
        raise VerificationError(
            "Invalid transaction: fee-sponsored transaction contains unsupported fields: "
            "authorizationList"
        )
    if key_auth is not None:
        try:
            key_authorization_rpc(key_auth.as_rlp_payload())
        except ValueError as err:
            raise VerificationError("Invalid transaction: malformed keyAuthorization") from err
    return decoded, sender_addr_bytes, sender_sig, key_auth


def envelope_sender(tx: Any, sender_address: bytes, sender_sig: bytes) -> tuple[str, Any]:
    """Return the checksummed sender of an envelope and its pytempo sender signature.

    secp256k1 signatures are recovered over ``tx``'s sender signing hash;
    keychain, P256, WebAuthn and multisig signatures name their account, which
    the chain authenticates when the transaction executes (as mppx). Either
    way the sender must be the envelope's declared ``sender_address``.
    """
    from eth_account import Account
    from eth_utils.address import to_checksum_address
    from pytempo.models import Signature  # pyright: ignore[reportMissingTypeStubs]

    sender_signature: Any
    if len(sender_sig) == 65:
        sender_hash = tx.get_signing_hash(for_fee_payer=False)
        try:
            recovered_address = Account._recover_hash(sender_hash, signature=sender_sig)  # pyright: ignore[reportPrivateUsage]
            sender_signature = Signature(
                r=int.from_bytes(sender_sig[:32], "big"),
                s=int.from_bytes(sender_sig[32:64], "big"),
                v=sender_sig[64],
            )
        except Exception as err:
            raise VerificationError("Invalid sender signature") from err
    else:
        signer = signature_envelope_signer(sender_sig)
        if signer is None:
            raise VerificationError("Invalid sender signature")
        recovered_address = to_checksum_address(signer)
        sender_signature = _RawSenderSignature(sender_sig)

    if recovered_address.lower() != "0x" + sender_address.hex():
        raise VerificationError("Sender address does not match recovered signer")
    return recovered_address, sender_signature


def hosted_fee_payer_request(
    decoded: list[Any], sender: str, key_authorization: Any = None
) -> dict[str, Any]:
    """Return the `eth_fillTransaction` request asking a hosted fee payer to sponsor.

    The shape of mppx `hostedFeePayerRequest` (src/tempo/internal/fee-payer.ts),
    which omits what ox's deserializer leaves unset: a zero gas, fee or call
    value, empty calldata, and an absent validity bound. A key authorization
    is sent as its JSON-RPC object (ox `KeyAuthorization.toRpc`).
    """
    calls: list[dict[str, Any]] = []
    for to, value, data in (call[:3] for call in decoded[4]):
        call: dict[str, Any] = {}
        if to:
            call["to"] = "0x" + to.hex()
        if data:
            call["data"] = "0x" + data.hex()
        call["value"] = _quantity(value) if _int(value) else "0x"
        calls.append(call)
    request: dict[str, Any] = {"calls": calls, "feePayer": True, "from": sender}
    if _int(decoded[3]):
        request["gas"] = _quantity(decoded[3])
    if key_authorization is not None:
        request["keyAuthorization"] = key_authorization_rpc(key_authorization.as_rlp_payload())
    for key, index in (("maxFeePerGas", 2), ("maxPriorityFeePerGas", 1)):
        if _int(decoded[index]):
            request[key] = _quantity(decoded[index])
    request["nonce"] = _quantity(decoded[7])
    request["nonceKey"] = _quantity(decoded[6])
    request["type"] = "0x76"
    for key, index in (("validAfter", 9), ("validBefore", 8)):
        if decoded[index]:
            request[key] = _quantity(decoded[index])
    return request


_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _signature_int(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("invalid signature value")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    raise ValueError("invalid signature value")


def complete_hosted_fee_payer_envelope(
    decoded: list[Any],
    sender_signature: bytes,
    result: object,
    *,
    key_authorization: Any = None,
    allowed_fee_tokens: Sequence[str] | None = None,
) -> tuple[str, str, str]:
    """Apply a hosted fee payer's `eth_fillTransaction` result to a client envelope.

    Like mppx `fillHostedFeePayerTransaction`, only the sponsor's
    `feePayerSignature` and `feeToken` are taken from `result`: every
    sender-committed field (the key authorization and sender signature
    included) comes from the client's envelope, so a sponsor that returns
    other values cannot change them. The sponsor address is recovered from the
    signature over those fields, for the final simulation.

    Returns `(raw_0x76_hex, sponsor, fee_token)`. Raises `InternalPaymentError`
    when the sponsor's answer is unusable.
    """
    from eth_account import Account
    from eth_hash.auto import keccak

    from mpp.methods.tempo import _rlp as rlp

    def fail(reason: str, error: Exception | None = None) -> RuntimeError:
        cause = RuntimeError(f"Invalid transaction: {reason}")
        cause.__cause__ = error
        return cause

    filled = result.get("tx") if is_dict(result) else None
    if not is_dict(filled) or not filled.get("feePayerSignature"):
        raise InternalPaymentError() from fail("hosted fee payer failed to sponsor transaction")
    signature = filled["feePayerSignature"]
    fee_token = filled.get("feeToken")
    if not isinstance(fee_token, str):
        raise InternalPaymentError() from fail("hosted fee payer did not return a feeToken")
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", fee_token) is None:
        raise InternalPaymentError() from fail("fee-sponsored transaction feeToken is invalid")
    if allowed_fee_tokens is not None and fee_token.lower() not in {
        token.lower() for token in allowed_fee_tokens
    }:
        raise InternalPaymentError() from fail("fee-sponsored transaction feeToken is not allowed")
    fee_token_bytes = bytes.fromhex(fee_token[2:])

    key_authorization_fields: list[Any] = (
        [] if key_authorization is None else [key_authorization.as_rlp_payload()]
    )
    fields = [*decoded[:10], fee_token_bytes, decoded[11], decoded[12], *key_authorization_fields]
    payload = keccak(b"\x78" + rlp.encode(fields))
    try:
        if not is_dict(signature):
            raise ValueError("feePayerSignature must be an object")
        r = _signature_int(signature.get("r"))
        s = _signature_int(signature.get("s"))
        y_parity = _signature_int(signature.get("yParity"))
        if not (0 < r < _SECP256K1_N and 0 < s < _SECP256K1_N and y_parity in (0, 1)):
            raise ValueError("feePayerSignature is out of range")
        sponsor: str = Account._recover_hash(payload, vrs=(y_parity, r, s))  # pyright: ignore[reportPrivateUsage]
    except Exception as error:
        raise InternalPaymentError() from fail(
            "hosted fee payer returned an invalid feePayerSignature", error
        )

    raw = b"\x76" + rlp.encode(
        [
            *decoded[:10],
            fee_token_bytes,
            [y_parity, r, s],
            decoded[12],
            *key_authorization_fields,
            sender_signature,
        ]
    )
    return "0x" + raw.hex(), sponsor, fee_token


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

    Sender signatures may be secp256k1 (recovered here) or keychain, P256,
    WebAuthn or multisig envelopes, which must name the envelope's sender. A
    key authorization is carried through; an authorization list is refused, as
    mppx does. With `require_remaining_validity=False` only an already expired `valid_before` is
    rejected; with `allow_expired=True` as well, an expired one is not either.
    `max_valid_before` further caps `valid_before` (such as the challenge expiry).
    """
    # pytempo ships no type information.
    from pytempo.models import as_address  # pyright: ignore[reportMissingTypeStubs]

    decoded, sender_addr_bytes, sender_sig, key_auth = decode_sponsored_envelope(raw_tx)

    assert_envelope_policy(
        decoded,
        policy=policy,
        allowed_fee_tokens=allowed_fee_tokens,
        require_remaining_validity=require_remaining_validity,
        allow_expired=allow_expired,
        max_valid_before=max_valid_before,
    )
    envelope_fee_token: bytes | None = decoded[10] or None

    tx_for_recovery = envelope_transaction(decoded, key_authorization=key_auth)
    calls = tuple(tx_for_recovery.calls)

    if validate_calls is not None:
        validate_calls(calls)

    recovered_address, sender_signature = envelope_sender(
        tx_for_recovery, sender_addr_bytes, sender_sig
    )

    tx_to_sign = attrs.evolve(
        tx_for_recovery,
        sender_signature=sender_signature,
        sender_address=as_address(recovered_address),
        fee_token=envelope_fee_token or fee_token or PATH_USD,
    )

    try:
        cosigned = tx_to_sign.sign(fee_payer.private_key, for_fee_payer=True)
    except Exception as err:
        raise InternalPaymentError() from err

    return "0x" + cosigned.encode().hex(), cosigned, recovered_address


def resolve_fee_payer(
    value: object,
) -> tuple[TempoAccount | None, RemoteFeePayer | None]:
    """Split a ``fee_payer`` option into a local account and a remote service."""
    from mpp.methods.tempo.account import TempoAccount
    from mpp.methods.tempo.remote_fee_payer import RemoteFeePayer

    if value is None:
        return None, None
    if isinstance(value, TempoAccount):
        return value, None
    remote = RemoteFeePayer.from_value(value)
    if remote is None:
        raise TypeError("fee_payer must be a TempoAccount, a URL, or a {url, headers} mapping")
    return None, remote
