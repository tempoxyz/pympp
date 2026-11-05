"""Malformed signature envelopes and key authorizations in local sponsorship helpers."""

from __future__ import annotations

from typing import Any

import pytest

from mpp.methods.tempo import _fee_payer as fp
from mpp.methods.tempo import _rlp as rlp

ADDR = b"\x11" * 20
P256 = b"\x01" + b"\x22" * 128 + b"\x00"
WEBAUTHN = b"\x02" + b"\x00" * 37 + b"{}" + b"\x33" * 128


@pytest.mark.parametrize(
    "signature",
    [
        pytest.param(b"\x01", id="too-short"),
        pytest.param(b"\x04" + ADDR + b"\x09" * 10, id="keychain-bad-inner"),
        pytest.param(b"\x01" + b"\x00" * 10, id="p256-wrong-length"),
        pytest.param(b"\x02" + b"\x00" * 10, id="webauthn-too-short"),
        pytest.param(b"\x05" + b"\xff\xff", id="multisig-bad-rlp"),
        pytest.param(b"\x05" + rlp.encode([b"\x01" * 5, [], []]), id="multisig-short-account"),
        pytest.param(b"\x09" + b"\x00" * 10, id="unknown-type"),
    ],
)
def test_signature_envelope_signer_rejects_malformed(signature: bytes) -> None:
    assert fp.signature_envelope_signer(signature) is None


def test_signature_envelope_signer_names_accounts() -> None:
    assert fp.signature_envelope_signer(b"\x04" + ADDR + P256) == "0x" + ADDR.hex()
    assert fp.signature_envelope_signer(b"\x05" + rlp.encode([ADDR, [], []])) == "0x" + ADDR.hex()


@pytest.mark.parametrize(
    "signature",
    [
        pytest.param(b"\x00" * 64 + b"\x05", id="bad-recovery-id"),
        pytest.param(b"\x09" + b"\x00" * 10, id="unknown-type"),
        pytest.param(b"\x05" + b"\xff", id="malformed-multisig"),
    ],
)
def test_signature_rpc_rejects_unsupported(signature: bytes) -> None:
    with pytest.raises(ValueError):
        fp._signature_rpc(signature)  # pyright: ignore[reportPrivateUsage]


def test_signature_rpc_renders_every_kind() -> None:
    render: Any = fp._signature_rpc  # pyright: ignore[reportPrivateUsage]
    assert render(b"\x00" * 64 + b"\x1c")["yParity"] == "0x1"
    assert render(P256)["type"] == "p256"
    assert render(WEBAUTHN)["type"] == "webAuthn"
    multisig = b"\x05" + rlp.encode([ADDR, [], []])
    assert render(multisig) == "0x" + multisig[1:].hex()


def _auth(*fields: object, signature: bytes = b"\x00" * 64 + b"\x1b") -> list[object]:
    return [list(fields), signature]


GOOD = (b"\x05\x39", b"", ADDR)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"", id="not-a-list"),
        pytest.param([[], b"\x00"], id="too-few-fields"),
        pytest.param(_auth(b"\x01", b"\x09", ADDR), id="unknown-key-type"),
        pytest.param(_auth(*GOOD, signature=b""), id="empty-signature"),
        pytest.param(_auth(b"\x01", b"", b"\x01"), id="short-key-id"),
        pytest.param(_auth(*GOOD, b"", b"x"), id="limits-not-list"),
        pytest.param(_auth(*GOOD, b"", [b"x"]), id="limit-not-list"),
        pytest.param(_auth(*GOOD, b"", [[ADDR, b"\x01", [b"x"]]]), id="limit-period-list"),
        pytest.param(_auth(*GOOD, b"", b"", b"x"), id="calls-not-list"),
        pytest.param(_auth(*GOOD, b"", b"", [[ADDR]]), id="scope-short"),
        pytest.param(_auth(*GOOD, b"", b"", [[ADDR, [[b"\x01"]]]]), id="rule-short"),
        pytest.param(_auth(*GOOD, b"", b"", [[ADDR, [[b"\x01", []]]]]), id="selector-short"),
        pytest.param(_auth(*GOOD, b"", b"", b"", b"\x01"), id="short-witness"),
        pytest.param(_auth(*GOOD, b"", b"", b"", b"", b"\x02"), id="bad-admin"),
        pytest.param(_auth(b"\x01", b"\x03", ADDR), id="multisig-without-account"),
    ],
)
def test_key_authorization_rpc_rejects_malformed(payload: object) -> None:
    with pytest.raises(ValueError):
        fp.key_authorization_rpc(payload)


def test_key_authorization_rpc_renders_optional_fields() -> None:
    rpc = fp.key_authorization_rpc(
        _auth(
            *GOOD,
            b"\x10",
            [[ADDR, b"\x05", b"\x3c"], [ADDR, b"\x01", b""]],
            [[ADDR, [[b"\xa9\x05\x9c\xbb", [ADDR]], [b"\x12\x34\x56\x78", []]]], [ADDR, []]],
            b"\x44" * 32,
            b"\x01",
            ADDR,
        )
    )
    assert rpc["limits"][0]["period"] == "0x3c"
    assert "period" not in rpc["limits"][1]
    assert rpc["allowedCalls"][0]["selectorRules"][0]["recipients"] == ["0x" + ADDR.hex()]
    assert "selectorRules" not in rpc["allowedCalls"][1]
    assert rpc["witness"] == "0x" + "44" * 32
    assert rpc["isAdmin"] is True
    assert rpc["account"] == "0x" + ADDR.hex()
    assert rpc["chainId"] == "0x539" and rpc["expiry"] == "0x10"


@pytest.mark.parametrize(
    ("recovery_id", "y_parity"), [(0, "0x0"), (1, "0x1"), (27, "0x0"), (28, "0x1")]
)
def test_fee_payer_signature_rpc_renders_parity(recovery_id: int, y_parity: str) -> None:
    """A yParity of 0 renders as `0x0`, as ox `Signature.toRpc` does."""
    rendered = fp.fee_payer_signature_rpc(recovery_id, 1, 2)
    assert rendered == {
        "r": "0x" + "00" * 31 + "01",
        "s": "0x" + "00" * 31 + "02",
        "yParity": y_parity,
    }


def test_fee_payer_signature_rpc_rejects_an_invalid_parity() -> None:
    with pytest.raises(ValueError, match="parity"):
        fp.fee_payer_signature_rpc(2, 1, 2)
