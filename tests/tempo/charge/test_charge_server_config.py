"""Configuration, defaults, memo binding and funding parity tests from mppx
``tempo/server/Charge.test.ts`` and ``Charge.funding.test.ts``."""

from __future__ import annotations

from typing import Any

import pytest
from _charge_node import (
    CURRENCY,
    REALM,
    SECRET_KEY,
    TESTNET_CHAIN_ID,
    FakeTempoNode,
    build_transaction,
    credential,
    memo_for,
    other,
    payer,
    receipt_json,
    recipient,
    sign,
    sponsor,
    transfer_call,
    transfer_logs,
)
from _charge_setup import (
    challenge_of,
    charge_client,
    create_credential,
    funded_node,
    make_client,
    make_server,
    server_method,
)

from mpp import store as _store
from mpp.method import RequestContext
from mpp.server import Mpp
from mpp.tempo import attribution, methods
from mpp.tempo._internal import abi
from mpp.tempo._internal.charge import TransactionRevertedError
from mpp.tempo.assets import PATH_USD_ADDRESS, USDC_ADDRESS
from mpp.tempo.server._charge import charge, charge_binding

USDC = "0x20C000000000000000000000b9537d11c60E8b50"


class TestRecipientAndFeePayerResolution:
    def test_string_recipient(self) -> None:
        method = server_method(funded_node(), account=recipient().address)
        assert method.defaults["recipient"] == recipient().address

    def test_account_resolves_to_address(self) -> None:
        method = server_method(funded_node(), account=recipient())
        assert method.defaults["recipient"] == recipient().address

    async def test_account_with_fee_payer_true(self) -> None:
        node = funded_node()
        node.fund(PATH_USD_ADDRESS, recipient().address, 10**8)
        handler = make_server(node, account=recipient(), fee_payer=True).charge(amount="1")
        assert (await challenge_of(handler)).request["methodDetails"]["feePayer"] is True
        response = await make_client(node, handler).fetch("https://api.example.com/paid")
        assert response.status_code == 200

    async def test_string_recipient_with_separate_fee_payer(self) -> None:
        node = funded_node()
        handler = make_server(node, account=recipient().address, fee_payer=sponsor()).charge(
            amount="1"
        )
        response = await make_client(node, handler).fetch("https://api.example.com/paid")
        assert response.status_code == 200

    async def test_no_fee_payer(self) -> None:
        handler = make_server(funded_node()).charge(amount="1")
        assert "feePayer" not in (await challenge_of(handler)).request["methodDetails"]

    async def test_request_keeps_explicit_fee_payer_false_during_verification(self) -> None:
        from mpp.challenge import Challenge
        from mpp.credential import Credential

        method = server_method(funded_node(), account=recipient(), fee_payer=recipient())
        fake = Credential(
            challenge=Challenge(id="x", realm=REALM, method="tempo", intent="charge", request={}),
            payload={},
        )
        normalized = await method.resolve_request(
            RequestContext(
                request={"amount": "1", "currency": CURRENCY, "decimals": 6, "feePayer": False},
                credential=fake,
            )
        )
        assert normalized["fee_payer"] is False
        challenge_request = await method.resolve_request(
            RequestContext(
                request={"amount": "1", "currency": CURRENCY, "decimals": 6, "feePayer": False}
            )
        )
        assert challenge_request["fee_payer"] is None

    async def test_request_level_fee_payer_account_is_passed_to_verification(self) -> None:
        from mpp.challenge import Challenge
        from mpp.credential import Credential

        method = server_method(funded_node())
        fake = Credential(
            challenge=Challenge(id="x", realm=REALM, method="tempo", intent="charge", request={}),
            payload={},
        )
        account = sponsor()
        resolved = await method.resolve_request(
            RequestContext(request={"amount": "1", "fee_payer": account}, credential=fake)
        )
        assert resolved["fee_payer"] is account
        resolved = await method.resolve_request(
            RequestContext(request={"amount": "1", "fee_payer": account})
        )
        assert resolved["fee_payer"] is True


class TestDefaultCurrency:
    def test_mainnet_default_is_usdc(self) -> None:
        method = charge(account=recipient().address, store=_store.memory())
        assert method.defaults["currency"] == USDC
        assert USDC == USDC_ADDRESS

    def test_testnet_defaults_to_path_usd(self) -> None:
        method = charge(account=recipient().address, testnet=True, store=_store.memory())
        assert method.defaults["currency"] == PATH_USD_ADDRESS

    def test_unknown_chain_defaults_to_path_usd(self) -> None:
        method = charge(account=recipient().address, chain_id=69420, store=_store.memory())
        assert method.defaults["currency"] == PATH_USD_ADDRESS

    def test_explicit_currency_overrides_default(self) -> None:
        method = charge(account=recipient().address, currency="0xcustom", store=_store.memory())
        assert method.defaults["currency"] == "0xcustom"

    def test_decimals_default_to_6(self) -> None:
        assert charge(store=_store.memory()).defaults["decimals"] == 6

    async def test_challenge_contains_usdc_on_mainnet(self) -> None:
        node = FakeTempoNode(chain_id=4217)
        rpc = node.client()
        server = Mpp(
            methods=[
                charge(account=recipient().address, get_client=lambda _: rpc, store=_store.memory())
            ],
            realm=REALM,
            secret_key=SECRET_KEY,
        )
        challenge = await challenge_of(server.charge(amount="1"))
        assert challenge.request["currency"] == USDC
        assert challenge.request["methodDetails"]["chainId"] == 4217

    async def test_challenge_contains_path_usd_on_testnet(self) -> None:
        server = make_server(funded_node(), currency=None)
        challenge = await challenge_of(server.charge(amount="1", chain_id=TESTNET_CHAIN_ID))
        assert challenge.request["currency"] == PATH_USD_ADDRESS

    async def test_challenge_contains_path_usd_on_unknown_chain(self) -> None:
        node = FakeTempoNode(chain_id=69420)
        rpc = node.client()
        server = Mpp(
            methods=[
                charge(
                    account=recipient().address,
                    chain_id=69420,
                    get_client=lambda _: rpc,
                    store=_store.memory(),
                )
            ],
            realm=REALM,
            secret_key=SECRET_KEY,
        )
        challenge = await challenge_of(server.charge(amount="1"))
        assert challenge.request["currency"] == PATH_USD_ADDRESS
        assert challenge.request["methodDetails"]["chainId"] == 69420
        assert node.methods == []

    async def test_default_client_chain_is_queried_when_unconfigured(self) -> None:
        node = FakeTempoNode(chain_id=31337)
        rpc = node.client()
        server = Mpp(
            methods=[
                charge(account=recipient().address, get_client=lambda _: rpc, store=_store.memory())
            ],
            realm=REALM,
            secret_key=SECRET_KEY,
        )
        challenge = await challenge_of(server.charge(amount="1"))
        assert challenge.request["methodDetails"]["chainId"] == 31337
        await challenge_of(server.charge(amount="1"))
        assert node.methods == ["eth_chainId"]

    async def test_explicit_currency_overrides_testnet_default(self) -> None:
        server = make_server(funded_node(), testnet=False, chain_id=TESTNET_CHAIN_ID)
        assert (await challenge_of(server.charge(amount="1"))).request["currency"] == CURRENCY

    async def test_supported_modes_from_route_and_defaults(self) -> None:
        server = make_server(funded_node())
        challenge = await challenge_of(server.charge(amount="1", supported_modes=["pull"]))
        assert challenge.request["methodDetails"]["supportedModes"] == ["pull"]
        server = make_server(funded_node(), supported_modes=["pull"])
        challenge = await challenge_of(server.charge(amount="1"))
        assert challenge.request["methodDetails"]["supportedModes"] == ["pull"]

    def test_stable_binding_contains_supported_modes(self) -> None:
        request = methods.charge.normalize_request(
            {"amount": "1", "currency": CURRENCY, "decimals": 6, "supportedModes": ["pull"]}
        )
        assert charge_binding(request)["supportedModes"] == ["pull"]
        assert "feePayer" not in charge_binding(
            {"methodDetails": {"feePayer": True}, "amount": "1"}
        )

    async def test_splits_from_method_defaults(self) -> None:
        split = {"amount": "0.2", "recipient": other().address}
        server = make_server(funded_node(), splits=[split])
        challenge = await challenge_of(server.charge(amount="1"))
        assert challenge.request["methodDetails"]["splits"] == [
            {"amount": "200000", "recipient": other().address}
        ]

    async def test_camel_case_route_options(self) -> None:
        server = make_server(funded_node())
        challenge = await challenge_of(
            server.charge(amount="1", supportedModes=["push"], externalId="order-1")
        )
        assert challenge.request["externalId"] == "order-1"
        assert challenge.request["methodDetails"]["supportedModes"] == ["push"]


# -- split memo binding matrix -----------------------------------------------------------------

MEMO_CASES = [
    (("bound", "plain"), True),
    (("plain", "bound"), True),
    (("bound", "bound"), True),
    (("bound", "other client"), True),
    (("bound", "uppercase"), True),
    (("bound", "custom"), True),
    (("custom", "bound"), True),
    (("bound", "other challenge"), False),
    (("other challenge", "bound"), False),
    (("bound", "other realm"), False),
    (("other realm", "bound"), False),
    (("other challenge", "plain"), False),
    (("other realm", "plain"), False),
    (("plain", "plain"), False),
    (("custom", "plain"), False),
]


@pytest.mark.parametrize("mode", ["hash", "transaction", "optimistic", "sponsored"])
@pytest.mark.parametrize(("memos", "accepted"), MEMO_CASES)
async def test_split_charge_memo_binding(mode: str, memos: tuple[str, str], accepted: bool) -> None:
    node = funded_node()
    server = make_server(
        node,
        fee_payer=sponsor() if mode == "sponsored" else None,
        wait_for_confirmation=mode != "optimistic",
    )
    challenge = await challenge_of(
        server.charge(
            amount="1", decimals=6, splits=[{"amount": "0.2", "recipient": other().address}]
        )
    )
    bound = memo_for(challenge)
    values: dict[str, str | None] = {
        "bound": bound,
        "other challenge": attribution.encode(challenge_id="other-challenge", server_id=REALM),
        "other realm": attribution.encode(challenge_id=challenge.id, server_id="other.example.com"),
        "other client": attribution.encode(
            challenge_id=challenge.id, server_id=REALM, client_id="another-client"
        ),
        "uppercase": "0x" + bound[2:].upper(),
        "custom": "0x" + "ab" * 32,
        "plain": None,
    }
    transaction = build_transaction(
        [
            transfer_call(CURRENCY, recipient().address, 800_000, values[memos[0]]),
            transfer_call(CURRENCY, other().address, 200_000, values[memos[1]]),
        ],
        fee_payer=mode == "sponsored",
    )
    signature = sign(payer(), transaction)
    if mode == "hash":
        payload = {"type": "hash", "hash": node.handle("eth_sendRawTransaction", [signature])}
    else:
        payload = {"type": "transaction", "signature": signature}
    value = credential(challenge, payload)
    node.methods.clear()
    if accepted:
        assert (await server.validate_credential(value)).intent == "charge"
        assert "eth_getTransactionByHash" not in node.methods
        assert (await server.verify_credential(value)).status == "success"
        assert node.count("eth_getTransactionByHash") == (1 if mode == "hash" else 0)
    else:
        with pytest.raises(Exception, match="memo is not bound to this challenge"):
            await server.validate_credential(value)
        with pytest.raises(Exception, match="memo is not bound to this challenge"):
            await server.verify_credential(value)
        assert "eth_sendRawTransaction" not in node.methods
        assert "eth_sendRawTransactionSync" not in node.methods
        assert "eth_call" not in node.methods


async def test_rejects_split_payment_for_both_challenges_across_marker_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import UTC, datetime, timedelta

    import mpp.store

    node = funded_node()
    server = make_server(node, store=_store.memory())
    now = datetime.now(UTC)
    challenges = [
        await server.challenge.tempo.charge(
            amount="1",
            decimals=6,
            expires=(now + timedelta(seconds=seconds)).isoformat(),
            splits=[{"amount": "0.2", "recipient": other().address}],
        )
        for seconds in (60, 120)
    ]
    signature = sign(
        payer(),
        build_transaction(
            [
                transfer_call(CURRENCY, recipient().address, 800_000, memo_for(challenges[0])),
                transfer_call(CURRENCY, other().address, 200_000, memo_for(challenges[1])),
            ]
        ),
    )
    tx_hash = node.handle("eth_sendRawTransaction", [signature])
    values = [credential(c, {"type": "hash", "hash": tx_hash}) for c in challenges]
    with pytest.raises(Exception, match="memo is not bound to this challenge"):
        await server.verify_credential(values[0])
    later = int((now + timedelta(seconds=61)).timestamp() * 1000)
    monkeypatch.setattr(mpp.store, "_now_ms", lambda: later)
    with pytest.raises(Exception, match="memo is not bound to this challenge"):
        await server.verify_credential(values[1])


# -- funding attribution (mppx Charge.funding.test.ts) -----------------------------------------


@pytest.mark.parametrize(
    "scenario", ["direct", "single", "unrelated", "missing", "sender", "reverted"]
)
async def test_push_funding_attribution(scenario: str) -> None:
    merchant = "0x2222222222222222222222222222222222222222"
    donor = "0x3333333333333333333333333333333333333333"
    payer_address = "0x1111111111111111111111111111111111111111"
    tx_hash = "0x" + "12" * 32
    node = FakeTempoNode()
    server = make_server(node, account=merchant)
    challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
    memo = memo_for(challenge)
    payment = abi.TRANSFER_WITH_MEMO.encode(merchant, 1_000_000, bytes.fromhex(memo[2:]))
    if scenario == "single":
        node.transactions[tx_hash] = {
            "hash": tx_hash,
            "from": payer_address,
            "type": "0x2",
            "to": CURRENCY,
            "input": payment,
        }
    elif scenario != "missing":
        calls: list[dict[str, Any]] = [{"to": CURRENCY, "data": payment}]
        if scenario == "unrelated":
            transfer_from = abi.Function("transferFrom", ("address", "address", "uint256"))
            calls += [
                {"to": CURRENCY, "data": transfer_from.encode(donor, payer_address, 1_000_000)},
                {"to": PATH_USD_ADDRESS, "data": abi.TRANSFER.encode(donor, 1)},
            ]
        node.transactions[tx_hash] = {
            "hash": tx_hash,
            "from": donor if scenario == "sender" else payer_address,
            "type": "0x76",
            "calls": calls,
        }
    logs = transfer_logs(CURRENCY, payer_address, merchant, 1_000_000, memo, 0)[1:]
    logs[0]["logIndex"] = "0x0"
    if scenario == "unrelated":
        logs += transfer_logs(CURRENCY, donor, payer_address, 1_000_000, None, 1)
        logs += transfer_logs(PATH_USD_ADDRESS, payer_address, donor, 1, None, 2)
    node.receipts[tx_hash] = receipt_json(
        transaction_hash=tx_hash,
        sender=payer_address,
        logs=logs,
        status="0x0" if scenario == "reverted" else "0x1",
    )
    value = credential(challenge, {"type": "hash", "hash": tx_hash})
    if scenario == "reverted":
        with pytest.raises(TransactionRevertedError, match="Transaction reverted"):
            await server.validate_credential(value)
        assert node.methods == ["eth_getTransactionReceipt"]
        return
    await server.validate_credential(value)
    assert node.methods == ["eth_getTransactionReceipt"]
    node.methods.clear()
    receipt = await server.verify_credential(value)
    assert receipt.status == "success"
    assert receipt.funding_currency == (CURRENCY if scenario in ("direct", "single") else None)
    assert node.methods == [
        "eth_getTransactionReceipt",
        "eth_getTransactionReceipt",
        "eth_getTransactionByHash",
    ]


@pytest.mark.parametrize("extra_transfer", [False, True])
async def test_funding_currency_requires_complete_payment_route(extra_transfer: bool) -> None:
    from mpp.tempo.chains import STABLECOIN_DEX

    node = funded_node()
    node.fund(PATH_USD_ADDRESS, payer().address, 10)
    server = make_server(node)
    challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
    calls = [transfer_call(CURRENCY, recipient().address, 1_000_000, memo_for(challenge))]
    if extra_transfer:
        calls.insert(0, transfer_call(PATH_USD_ADDRESS, STABLECOIN_DEX, 1))
    tx_hash = node.handle("eth_sendRawTransaction", [sign(payer(), build_transaction(calls))])
    receipt = await server.verify_credential(
        credential(challenge, {"type": "hash", "hash": tx_hash})
    )
    assert receipt.status == "success"
    assert receipt.funding_currency == (None if extra_transfer else CURRENCY)


async def test_client_credentials_round_trip_through_validate() -> None:
    node = funded_node()
    server = make_server(node)
    challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
    value = await create_credential(charge_client(node), challenge)
    validation = await server.validate_credential(value)
    assert validation.details.mode == "pull"
    assert validation.payer == payer().address
    assert validation.request == challenge.request


class TestFixedAttributionSplitMemos:
    # pympp#325: a fixed split memo in the MPP attribution format could also pay the challenge
    # it names, so it is refused before any challenge is issued.
    MEMO = attribution.encode(challenge_id="other-challenge", server_id=REALM)

    def split(self, memo: str) -> dict[str, Any]:
        return {"amount": "0.1", "memo": memo, "recipient": other().address}

    def test_rejected_at_construction(self) -> None:
        with pytest.raises(ValueError, match="Fixed split memos must not use MPP attribution"):
            server_method(funded_node(), splits=[self.split(self.MEMO)])

    def test_rejected_on_route(self) -> None:
        server = make_server(funded_node())
        with pytest.raises(ValueError, match="Fixed split memos must not use MPP attribution"):
            server.charge(amount="1", splits=[self.split(self.MEMO)])

    async def test_application_memos_remain_allowed(self) -> None:
        handler = make_server(funded_node()).charge(
            amount="1", splits=[self.split("0x" + "dd" * 32)]
        )
        challenge = await challenge_of(handler)
        assert challenge.request["methodDetails"]["splits"][0]["memo"] == "0x" + "dd" * 32
