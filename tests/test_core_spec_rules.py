"""Core spec rules every SDK server shares.

The minimum length of the HMAC secret that binds challenge IDs.
"""

from __future__ import annotations

import pytest

from mpp import generate_challenge_id
from mpp.server import Mpp
from tests.test_behavior_contract import REALM, ContractMethod


class TestSecretKey:
    def test_challenge_ids_refuse_a_short_secret(self) -> None:
        with pytest.raises(ValueError, match="at least 32 bytes"):
            generate_challenge_id(
                secret_key="short",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000000"},
            )

    def test_server_refuses_a_short_secret(self) -> None:
        with pytest.raises(ValueError, match="at least 32 bytes"):
            Mpp(methods=ContractMethod().server[0], realm=REALM, secret_key="x" * 31)

    @pytest.mark.parametrize(
        ("header", "opaque", "expected"),
        [
            (None, None, "2S2NsFcCINq8QUKV8OZHdRm_JhhbJf5X8Cii4gZ_UyI"),
            ("Payment-Authorization", None, "CfIT3MTJbcDQ7kdEJD9GbLQPvlRZQLnEXyerMinsFMg"),
            (
                "Payment-Authorization",
                {"pi": "pi_123"},
                "fGVr3o_Ve1k0KQpddLKyEXRE7nk6chQOC5lN7Q54dR8",
            ),
        ],
    )
    def test_spec_hmac_vectors(
        self, header: str | None, opaque: dict[str, str] | None, expected: str
    ) -> None:
        assert (
            generate_challenge_id(
                secret_key="mpp-hmac-test-vector-secret-32by",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000000"},
                header=header,
                opaque=opaque,
            )
            == expected
        )
