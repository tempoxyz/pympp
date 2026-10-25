from typing import Any

import pytest


class RecordingSigner:
    """A typed-data signer test double recording every signing request."""

    def __init__(
        self,
        address: str = "0x1111111111111111111111111111111111111111",
        signature: str = "0x1234",
    ) -> None:
        self.address = address
        self.signature = signature
        self.calls: list[dict[str, Any]] = []

    def sign_typed_data(self, typed_data: dict[str, Any]) -> str:
        self.calls.append(typed_data)
        return self.signature


@pytest.fixture
def signer() -> RecordingSigner:
    return RecordingSigner()
