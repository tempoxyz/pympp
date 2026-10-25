"""Conformance wire vectors (vendor/mpp-tools/conformance/vectors)."""

import json
import time
from pathlib import Path
from typing import Any

import pytest

from mpp import Challenge, Credential, Receipt, _base64url
from mpp.challenge import compute_id

VECTORS = Path(__file__).parents[2] / "vendor" / "mpp-tools" / "conformance" / "vectors"


def _scenarios(name: str) -> list[Any]:
    data = json.loads((VECTORS / f"{name}.json").read_text())
    return [pytest.param(s, id=s["name"]) for s in data["scenarios"]]


def _wire(scenario: dict[str, Any]) -> str:
    wire = scenario["wire"]
    if isinstance(wire, dict):
        return wire["prefix"] + wire["repeat"] * wire["count"] + wire.get("suffix", "")
    return wire


def _expects_error(test: Any) -> bool:
    return isinstance(test, dict) and test.get("success") is False


def _check_duration(scenario: dict[str, Any], started: float) -> None:
    limit = scenario.get("maxDurationMsByAdapter", {}).get("python", scenario.get("maxDurationMs"))
    if limit is not None:
        assert (time.monotonic() - started) * 1000 <= limit


def _challenge_object(challenge: Challenge) -> dict[str, Any]:
    return challenge.to_dict()


def _credential_object(credential: Credential[Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "challenge": _challenge_object(credential.challenge),
        "payload": credential.payload,
    }
    if credential.source is not None:
        result["source"] = credential.source
    return result


@pytest.mark.parametrize("scenario", _scenarios("www-authenticate"))
def test_www_authenticate(scenario: dict[str, Any]) -> None:
    tests = scenario["tests"]
    if "parse" in tests:
        started = time.monotonic()
        if _expects_error(tests["parse"]):
            with pytest.raises(ValueError, match=r".+"):
                Challenge.deserialize(_wire(scenario))
        else:
            parsed = Challenge.deserialize(_wire(scenario))
            assert _challenge_object(parsed) == scenario["object"]
        _check_duration(scenario, started)
    if "format" in tests:
        if _expects_error(tests["format"]):
            with pytest.raises(ValueError, match=r".+"):
                Challenge.from_dict(scenario["object"]).serialize()
        else:
            formatted = Challenge.from_dict(scenario["object"]).serialize()
            if tests["format"] == "exact":
                assert formatted == scenario["wire"]
            else:
                assert _challenge_object(Challenge.deserialize(formatted)) == _challenge_object(
                    Challenge.deserialize(_wire(scenario))
                )
    if tests.get("roundtrip"):
        challenge = Challenge.from_dict(scenario["object"])
        assert _challenge_object(Challenge.deserialize(challenge.serialize())) == scenario["object"]


@pytest.mark.parametrize("scenario", _scenarios("authorization"))
def test_authorization(scenario: dict[str, Any]) -> None:
    tests = scenario["tests"]
    if "parse" in tests:
        if _expects_error(tests["parse"]):
            with pytest.raises(ValueError, match=r".+"):
                Credential.deserialize(_wire(scenario))
        else:
            assert _credential_object(Credential.deserialize(_wire(scenario))) == scenario["object"]
    if "format" in tests:
        obj = scenario["object"]
        credential = Credential(
            challenge=Challenge.from_dict(obj["challenge"]),
            payload=obj["payload"],
            source=obj.get("source"),
        )
        formatted = credential.serialize()
        assert _credential_object(Credential.deserialize(formatted)) == _credential_object(
            Credential.deserialize(_wire(scenario))
        )
        if tests.get("roundtrip"):
            assert _credential_object(Credential.deserialize(formatted)) == obj


@pytest.mark.parametrize("scenario", _scenarios("receipt"))
def test_receipt(scenario: dict[str, Any]) -> None:
    tests = scenario["tests"]
    if "parse" in tests:
        if _expects_error(tests["parse"]):
            with pytest.raises(ValueError, match=r".+"):
                Receipt.deserialize(_wire(scenario))
        else:
            assert Receipt.deserialize(_wire(scenario)).to_dict() == scenario["object"]
    if "format" in tests:
        formatted = Receipt.from_dict(scenario["object"]).serialize()
        assert (
            Receipt.deserialize(formatted).to_dict()
            == Receipt.deserialize(_wire(scenario)).to_dict()
        )


@pytest.mark.parametrize("scenario", _scenarios("base64url"))
def test_base64url(scenario: dict[str, Any]) -> None:
    tests = scenario["tests"]
    if _expects_error(tests.get("parse")):
        with pytest.raises(ValueError, match=r".+"):
            _base64url.decode_text(scenario["encoded"])
        return
    assert _base64url.decode_text(scenario["encoded"]) == scenario["decoded"]
    assert _base64url.encode(scenario["decoded"]) == scenario["encoded"]


@pytest.mark.parametrize("scenario", _scenarios("challenge-id"))
def test_challenge_id(scenario: dict[str, Any]) -> None:
    params = dict(scenario["input"])
    secret_key = params.pop("secretKey")
    generate = scenario.get("tests", {}).get("generate")
    if _expects_error(generate):
        from mpp.server import assert_secret_key

        with pytest.raises(ValueError, match=r".+"):
            assert_secret_key(secret_key)
        return
    expected = scenario["expected"]
    binding = {key: value for key, value in params.items() if key != "description"}
    assert compute_id(secret_key, **binding) == expected
    # The same id via the high-level constructor (opaque is passed through verbatim).
    challenge = Challenge.create(secret_key=secret_key, **params)
    assert challenge.id == expected
    assert challenge.verify(secret_key)
