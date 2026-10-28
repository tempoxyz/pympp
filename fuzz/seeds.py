"""Write the fuzz targets' seed corpora to fuzz/seeds/<target>/.

Seeds come from mpp-tools' cross-SDK conformance vectors (the ``wire`` header
values and the JSON they encode), when ``--vectors`` points at a checkout's
conformance/vectors directory, and from transactions and bodies built here.

    uv run python fuzz/seeds.py --vectors ../mpp-tools/conformance/vectors
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from pytempo import Call, TempoTransaction

from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

SEEDS = Path(__file__).parent / "seeds"
VECTOR_TARGETS = {
    "www-authenticate.json": "fuzz_www_authenticate",
    "authorization.json": "fuzz_authorization",
    "receipt.json": "fuzz_receipt",
}
PRIVATE_KEY = "0x" + "11" * 32
CURRENCY = "0x20c0000000000000000000000000000000000000"
TRANSFER = "0xa9059cbb" + "742d35cc6634c0532925a3b844bc9e7595f8fe00".zfill(64) + "f4240".zfill(64)
BODIES = [b"", b"{}", b'{"b":1,"a":[1,{"2":true,"1":null}],"10":"x"}', "\u00e9\u2603".encode()]


def write(target: str, seed: bytes) -> None:
    directory = SEEDS / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / hashlib.sha1(seed).hexdigest()).write_bytes(seed)


def b64url_decode(value: str) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        return None


def vector_seeds(vectors: Path) -> None:
    """Seed the header parsers with each vector's wire value and the JSON it encodes."""
    for name, target in VECTOR_TARGETS.items():
        for scenario in json.loads((vectors / name).read_text())["scenarios"]:
            wire = scenario.get("wire")
            if not isinstance(wire, str):
                continue
            write(target, wire.encode("latin-1", "replace"))
            if target == "fuzz_www_authenticate":
                payload = wire.partition('request="')[2].partition('"')[0]
            else:
                payload = wire.removeprefix("Payment ")
            decoded = b64url_decode(payload)
            if decoded:
                write(target, decoded)


def transaction_seeds() -> None:
    """Seed the decoders with a sponsored 0x78 envelope and signed 0x76 transactions."""
    for awaiting_fee_payer, fee_token in ((True, None), (False, CURRENCY), (False, None)):
        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=100000,
            max_fee_per_gas=1,
            max_priority_fee_per_gas=1,
            nonce=0,
            nonce_key=(1 << 256) - 1,
            fee_token=fee_token,
            awaiting_fee_payer=awaiting_fee_payer,
            valid_before=9999999999,
            calls=(Call.create(to=CURRENCY, value=0, data=TRANSFER),),
        ).sign(PRIVATE_KEY)
        if awaiting_fee_payer:
            write("fuzz_tempo_transaction", encode_fee_payer_envelope(tx))
        else:
            write("fuzz_tempo_transaction", bytes(tx.encode()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--vectors", type=Path, help="mpp-tools conformance/vectors directory")
    args = parser.parse_args()
    if args.vectors:
        vector_seeds(args.vectors)
    transaction_seeds()
    for body in BODIES:
        write("fuzz_body_digest", body)
    for target in sorted(p.name for p in SEEDS.iterdir()):
        print(f"{target}: {len(list((SEEDS / target).iterdir()))} seeds")


if __name__ == "__main__":
    main()
