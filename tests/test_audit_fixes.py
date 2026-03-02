"""Tests for audit fixes PY-01 through PY-06.

Each test class maps to a specific audit finding and verifies both the
fix and regression scenarios.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import pytest

from mpp import (
    Challenge,
    Credential,
    Receipt,
    generate_challenge_id,
)
from mpp._body_digest import compute as body_digest_compute
from mpp._expires import _to_iso
from mpp.extensions.mcp.types import MCPChallenge, MCPCredential
from mpp.extensions.mcp.verify import verify_or_challenge
from mpp.server.verify import verify_or_challenge as http_verify_or_challenge
from tests import TEST_SECRET, make_bound_credential


# ---------------------------------------------------------------------------
# PY-01: MCP challenge ID verification must include digest & opaque
# ---------------------------------------------------------------------------
class TestPY01_MCPDigestOpaque:
    """PY-01: generate_challenge_id in MCP verify must pass digest/opaque."""

    def test_mcp_challenge_has_digest_and_opaque_fields(self) -> None:
        """MCPChallenge should accept digest and opaque fields."""
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={"amount": "1"},
            digest="sha-256=abc",
            opaque={"pi": "pi_123"},
        )
        assert ch.digest == "sha-256=abc"
        assert ch.opaque == {"pi": "pi_123"}

    def test_mcp_challenge_to_dict_includes_digest_opaque(self) -> None:
        """to_dict should serialize digest and opaque."""
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={},
            digest="sha-256=xyz",
            opaque={"k": "v"},
        )
        d = ch.to_dict()
        assert d["digest"] == "sha-256=xyz"
        assert d["opaque"] == {"k": "v"}

    def test_mcp_challenge_to_dict_omits_none_digest_opaque(self) -> None:
        """to_dict should omit digest/opaque when None."""
        ch = MCPChallenge(id="test", realm="r", method="tempo", intent="charge", request={})
        d = ch.to_dict()
        assert "digest" not in d
        assert "opaque" not in d

    def test_mcp_challenge_from_dict_parses_digest_opaque(self) -> None:
        """from_dict should parse digest and opaque."""
        data = {
            "id": "test",
            "realm": "r",
            "method": "tempo",
            "intent": "charge",
            "request": {},
            "digest": "sha-256=abc",
            "opaque": {"k": "v"},
        }
        ch = MCPChallenge.from_dict(data)
        assert ch.digest == "sha-256=abc"
        assert ch.opaque == {"k": "v"}

    @pytest.mark.asyncio
    async def test_mcp_verify_succeeds_with_digest(self) -> None:
        """MCP verification should succeed when challenge has digest field."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        digest_val = "sha-256=abc123"
        # Build a challenge with digest included in the HMAC
        challenge_id = generate_challenge_id(
            secret_key=TEST_SECRET,
            realm="r",
            method="tempo",
            intent="charge",
            request=request,
            digest=digest_val,
        )
        ch = MCPChallenge(
            id=challenge_id,
            realm="r",
            method="tempo",
            intent="charge",
            request=request,
            digest=digest_val,
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})

        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request=request,
            realm="r",
            secret_key=TEST_SECRET,
        )
        assert isinstance(result, tuple), "Should verify successfully with digest"

    @pytest.mark.asyncio
    async def test_mcp_verify_succeeds_with_opaque(self) -> None:
        """MCP verification should succeed when challenge has opaque field."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        opaque = {"pi": "pi_abc"}
        challenge_id = generate_challenge_id(
            secret_key=TEST_SECRET,
            realm="r",
            method="tempo",
            intent="charge",
            request=request,
            opaque=opaque,
        )
        ch = MCPChallenge(
            id=challenge_id,
            realm="r",
            method="tempo",
            intent="charge",
            request=request,
            opaque=opaque,
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})

        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request=request,
            realm="r",
            secret_key=TEST_SECRET,
        )
        assert isinstance(result, tuple), "Should verify successfully with opaque"

    @pytest.mark.asyncio
    async def test_mcp_verify_fails_without_matching_digest(self) -> None:
        """HMAC recomputation should fail if digest is tampered."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: object, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        request = {"amount": "1000"}
        # Create challenge with one digest
        challenge_id = generate_challenge_id(
            secret_key=TEST_SECRET,
            realm="r",
            method="tempo",
            intent="charge",
            request=request,
            digest="sha-256=original",
        )
        # But tamper the digest in the credential
        ch = MCPChallenge(
            id=challenge_id,
            realm="r",
            method="tempo",
            intent="charge",
            request=request,
            digest="sha-256=tampered",
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})

        result = await verify_or_challenge(
            meta=cred.to_meta(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request=request,
            realm="r",
            secret_key=TEST_SECRET,
        )
        # Should re-issue challenge because HMAC doesn't match
        assert isinstance(result, MCPChallenge)


# ---------------------------------------------------------------------------
# PY-03: server/verify.py must assert realm/method/intent after HMAC check
# ---------------------------------------------------------------------------
class TestPY03_CrossRealmPrevention:
    """PY-03: After HMAC verification, assert echoed realm/method/intent match."""

    @pytest.mark.asyncio
    async def test_rejects_credential_with_wrong_realm(self) -> None:
        """Credential issued for realm-A should be rejected at realm-B."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        shared_secret = "shared-key"
        request = {"amount": "1000"}

        # Create credential bound to realm-A
        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=request,
            realm="realm-A",
            secret_key=shared_secret,
        )

        # Present at realm-B (same secret)
        result = await http_verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request=request,
            realm="realm-B",
            secret_key=shared_secret,
        )
        # HMAC will already mismatch because realm is in the HMAC input,
        # but this test confirms the fix adds explicit assertions as defense-in-depth
        assert isinstance(result, Challenge), "Should reject cross-realm credential"

    @pytest.mark.asyncio
    async def test_rejects_credential_with_wrong_method(self) -> None:
        """Credential for method-A should be rejected when server expects method-B."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        secret = "test-secret"
        request = {"amount": "1000"}

        # Create credential bound to method "tempo"
        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=request,
            realm="r",
            method="tempo",
            secret_key=secret,
        )

        # Present to server expecting method "stripe"
        result = await http_verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request=request,
            realm="r",
            method="stripe",
            secret_key=secret,
        )
        assert isinstance(result, Challenge), "Should reject wrong method"

    @pytest.mark.asyncio
    async def test_rejects_credential_with_wrong_intent(self) -> None:
        """Credential for intent 'charge' should be rejected when server expects 'session'."""

        class ChargeIntent:
            name = "session"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0x123")

        secret = "test-secret"
        request = {"amount": "1000"}

        # Create credential bound to intent "charge"
        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=request,
            realm="r",
            intent="charge",
            secret_key=secret,
        )

        # Present to server expecting intent "session"
        result = await http_verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=ChargeIntent(),  # type: ignore[arg-type]
            request=request,
            realm="r",
            secret_key=secret,
        )
        assert isinstance(result, Challenge), "Should reject wrong intent"

    @pytest.mark.asyncio
    async def test_accepts_matching_realm_method_intent(self) -> None:
        """Credential should be accepted when realm/method/intent all match."""

        class MockIntent:
            name = "charge"

            async def verify(self, credential: Credential, request: dict) -> Receipt:
                return Receipt.success(reference="0xOK")

        secret = "test-secret"
        request = {"amount": "1000"}

        credential = make_bound_credential(
            payload={"sig": "0x"},
            request=request,
            realm="r",
            method="tempo",
            intent="charge",
            secret_key=secret,
        )

        result = await http_verify_or_challenge(
            authorization=credential.to_authorization(),
            intent=MockIntent(),  # type: ignore[arg-type]
            request=request,
            realm="r",
            method="tempo",
            secret_key=secret,
        )
        assert isinstance(result, tuple), "Should accept matching credential"
        _, receipt = result
        assert receipt.reference == "0xOK"


# ---------------------------------------------------------------------------
# PY-04: body digest must use sort_keys=True for deterministic output
# ---------------------------------------------------------------------------
class TestPY04_BodyDigestSortKeys:
    """PY-04: json.dumps for dict body digest must use sort_keys=True."""

    def test_key_order_independent(self) -> None:
        """Dict digests should be identical regardless of key insertion order."""
        d1 = {"z": "1", "a": "2", "m": "3"}
        d2 = {"a": "2", "m": "3", "z": "1"}
        assert body_digest_compute(d1) == body_digest_compute(d2)

    def test_matches_canonical_json(self) -> None:
        """Dict digest should match digest of canonical (sorted) JSON string."""
        d = {"b": "2", "a": "1"}
        canonical = json.dumps(d, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
        assert body_digest_compute(d) == body_digest_compute(canonical)

    def test_nested_dict_key_order(self) -> None:
        """Nested dict should also be sorted by keys."""
        d1 = {"outer_z": {"inner_b": 1, "inner_a": 2}, "outer_a": 3}
        d2 = {"outer_a": 3, "outer_z": {"inner_a": 2, "inner_b": 1}}
        assert body_digest_compute(d1) == body_digest_compute(d2)


# ---------------------------------------------------------------------------
# PY-05: _to_iso must properly handle timezone
# ---------------------------------------------------------------------------
class TestPY05_ExpiresTimezone:
    """PY-05: _to_iso should use isoformat() for robust timezone handling."""

    def test_utc_datetime_ends_with_z(self) -> None:
        """UTC datetime should produce timestamp ending with Z."""
        dt = datetime(2025, 6, 15, 12, 30, 45, 123456, tzinfo=UTC)
        result = _to_iso(dt)
        assert result.endswith("Z")
        assert "+00:00" not in result

    def test_millisecond_precision(self) -> None:
        """Output should have exactly millisecond precision."""
        dt = datetime(2025, 1, 1, 0, 0, 0, 500000, tzinfo=UTC)
        result = _to_iso(dt)
        # Should be 2025-01-01T00:00:00.500Z
        ms_part = result.split(".")[1].rstrip("Z")
        assert len(ms_part) == 3

    def test_zero_microseconds(self) -> None:
        """Zero microseconds should produce .000Z."""
        dt = datetime(2025, 1, 1, 0, 0, 0, 0, tzinfo=UTC)
        result = _to_iso(dt)
        assert result == "2025-01-01T00:00:00.000Z"

    def test_sub_millisecond_truncation(self) -> None:
        """Microseconds should be truncated to milliseconds."""
        # 123456 µs → 123 ms
        dt = datetime(2025, 6, 15, 10, 30, 0, 123456, tzinfo=UTC)
        result = _to_iso(dt)
        assert ".123Z" in result

    def test_roundtrip_parse(self) -> None:
        """Output should be parseable back to a datetime."""
        dt = datetime(2025, 3, 15, 8, 45, 30, 789000, tzinfo=UTC)
        result = _to_iso(dt)
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
        assert parsed.year == 2025
        assert parsed.month == 3
        assert parsed.second == 30


# ---------------------------------------------------------------------------
# PY-06: MCPCredential.to_core() must populate digest and opaque on echo
# ---------------------------------------------------------------------------
class TestPY06_MCPCredentialToCore:
    """PY-06: MCPCredential.to_core() must pass digest/opaque to ChallengeEcho."""

    def test_to_core_includes_digest(self) -> None:
        """ChallengeEcho should have digest from MCPChallenge."""
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={"amount": "1"},
            digest="sha-256=abc123",
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})
        core = cred.to_core()
        assert core.challenge.digest == "sha-256=abc123"

    def test_to_core_includes_opaque(self) -> None:
        """ChallengeEcho should have base64url-encoded opaque from MCPChallenge."""
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={"amount": "1"},
            opaque={"pi": "pi_123"},
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})
        core = cred.to_core()
        assert core.challenge.opaque is not None
        # Decode to verify contents
        decoded = json.loads(base64.urlsafe_b64decode(core.challenge.opaque + "==").decode())
        assert decoded == {"pi": "pi_123"}

    def test_to_core_opaque_is_sorted(self) -> None:
        """Opaque JSON encoding should use sort_keys for deterministic output."""
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={},
            opaque={"z": "last", "a": "first"},
        )
        cred = MCPCredential(challenge=ch, payload={})
        core = cred.to_core()
        decoded_json = base64.urlsafe_b64decode(core.challenge.opaque + "==").decode()
        # Keys should be sorted: "a" before "z"
        assert decoded_json.index('"a"') < decoded_json.index('"z"')

    def test_to_core_none_digest_opaque(self) -> None:
        """When digest/opaque are None, ChallengeEcho should also have None."""
        ch = MCPChallenge(
            id="test",
            realm="r",
            method="tempo",
            intent="charge",
            request={"amount": "1"},
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})
        core = cred.to_core()
        assert core.challenge.digest is None
        assert core.challenge.opaque is None

    def test_to_core_roundtrip_hmac_with_opaque(self) -> None:
        """Core credential from MCP should produce valid HMAC when opaque is set."""
        opaque = {"pi": "pi_abc"}
        request = {"amount": "1000"}
        # Generate challenge ID including opaque
        challenge_id = generate_challenge_id(
            secret_key=TEST_SECRET,
            realm="r",
            method="tempo",
            intent="charge",
            request=request,
            opaque=opaque,
        )
        ch = MCPChallenge(
            id=challenge_id,
            realm="r",
            method="tempo",
            intent="charge",
            request=request,
            opaque=opaque,
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})
        core = cred.to_core()

        # Recompute HMAC from core credential fields (as server verify does)
        from mpp._parsing import _b64_decode

        echo = core.challenge
        echo_request = _b64_decode(echo.request) if echo.request else {}
        echo_opaque = _b64_decode(echo.opaque) if echo.opaque else None
        recomputed_id = generate_challenge_id(
            secret_key=TEST_SECRET,
            realm=echo.realm,
            method=echo.method,
            intent=echo.intent,
            request=echo_request,
            expires=echo.expires,
            digest=echo.digest,
            opaque=echo_opaque,
        )
        assert recomputed_id == challenge_id, (
            "Core credential should produce matching HMAC when opaque is present"
        )

    def test_to_core_roundtrip_hmac_with_digest(self) -> None:
        """Core credential from MCP should produce valid HMAC when digest is set."""
        request = {"amount": "1000"}
        digest_val = "sha-256=test123"
        challenge_id = generate_challenge_id(
            secret_key=TEST_SECRET,
            realm="r",
            method="tempo",
            intent="charge",
            request=request,
            digest=digest_val,
        )
        ch = MCPChallenge(
            id=challenge_id,
            realm="r",
            method="tempo",
            intent="charge",
            request=request,
            digest=digest_val,
        )
        cred = MCPCredential(challenge=ch, payload={"sig": "0x"})
        core = cred.to_core()

        echo = core.challenge
        from mpp._parsing import _b64_decode

        echo_request = _b64_decode(echo.request) if echo.request else {}
        recomputed_id = generate_challenge_id(
            secret_key=TEST_SECRET,
            realm=echo.realm,
            method=echo.method,
            intent=echo.intent,
            request=echo_request,
            expires=echo.expires,
            digest=echo.digest,
            opaque=None,
        )
        assert recomputed_id == challenge_id
