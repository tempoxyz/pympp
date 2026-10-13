"""A charge must be settled on the chain advertised by its challenge."""

import json

import httpx
import pytest
from eth_account import Account
from pytempo import Call, TempoTransaction

from mpp import Challenge, Credential
from mpp.errors import VerificationError
from mpp.methods.tempo import ChargeIntent, tempo
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo._defaults import CHAIN_ID, PATH_USD, TESTNET_CHAIN_ID
from mpp.methods.tempo.intents import TRANSFER_WITH_MEMO_TOPIC
from mpp.server import Mpp

PAYER_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PAYER = Account.from_key(PAYER_KEY).address
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
RPC_URL = "https://rpc.test"
REALM = "example.com"


@pytest.mark.parametrize("credential_type", ["hash", "transaction"])
async def test_charge_rejects_settlement_on_other_chain(credential_type: str) -> None:
    methods: list[str] = []
    receipt: dict = {}

    def rpc(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        method = payload["method"]
        methods.append(method)
        if method == "eth_chainId":
            result = hex(TESTNET_CHAIN_ID)
        elif method == "eth_getTransactionReceipt":
            result = receipt
        elif method == "eth_sendRawTransactionSync":
            result = {**receipt, "transactionHash": "0x" + "ab" * 32}
        else:
            raise AssertionError(f"Unexpected RPC method: {method}")
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(rpc)) as client:
        server = Mpp.create(
            method=tempo(
                chain_id=TESTNET_CHAIN_ID,
                rpc_url=RPC_URL,
                currency=PATH_USD,
                recipient=RECIPIENT,
                intents={"charge": ChargeIntent(http_client=client)},
            ),
            realm=REALM,
            secret_key="test-secret",
        )
        options = {"amount": "0.000001", "chain_id": CHAIN_ID}
        challenge = await server.charge(None, **options)
        assert isinstance(challenge, Challenge)
        assert challenge.request["methodDetails"]["chainId"] == CHAIN_ID

        memo = encode_attribution(challenge.id, REALM)
        receipt = {
            "status": "0x1",
            "logs": [
                {
                    "address": challenge.request["currency"],
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        "0x" + PAYER[2:].lower().zfill(64),
                        "0x" + RECIPIENT[2:].lower().zfill(64),
                        memo,
                    ],
                    "data": "0x" + hex(1)[2:].zfill(64),
                }
            ],
        }

        if credential_type == "hash":
            payload = {"type": "hash", "hash": "0x" + "ab" * 32}
            reason = "RPC chain ID"
        else:
            data = "0x95777d59" + RECIPIENT[2:].lower().zfill(64) + hex(1)[2:].zfill(64) + memo[2:]
            tx = TempoTransaction.create(
                chain_id=TESTNET_CHAIN_ID,
                gas_limit=2_000_000,
                max_fee_per_gas=1,
                max_priority_fee_per_gas=1,
                nonce=0,
                fee_token=PATH_USD,
                calls=(Call.create(to=PATH_USD, value=0, data=data),),
            )
            payload = {"type": "transaction", "signature": "0x" + tx.sign(PAYER_KEY).encode().hex()}
            reason = "Transaction chain ID"

        credential = Credential(
            challenge=challenge.to_echo(),
            payload=payload,
            source=f"did:pkh:eip155:{CHAIN_ID}:{PAYER}",
        )
        with pytest.raises(VerificationError, match=reason):
            await server.validate_credential(credential)
        with pytest.raises(VerificationError, match=reason):
            await server.charge(credential.to_authorization(), **options)
        assert methods == (["eth_chainId", "eth_chainId"] if credential_type == "hash" else [])
