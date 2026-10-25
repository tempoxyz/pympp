"""Ported from mppx src/BodyDigest.test.ts."""

from mpp import body_digest


def test_compute() -> None:
    expected = "sha-256=Bxp4xJtbVfsB9npD5AEWUnIk76Cuv8Au4ECDA+F0biY="
    assert body_digest.compute('{"amount":"1000"}') == expected
    assert body_digest.compute({"amount": "1000"}) == expected
    assert body_digest.compute('{"a":"1"}') != body_digest.compute('{"a":"2"}')


def test_verify() -> None:
    digest = body_digest.compute('{"amount":"1000"}')
    assert body_digest.verify(digest, '{"amount":"1000"}')
    assert not body_digest.verify(digest, '{"amount":"2000"}')


def test_preserves_insertion_order_like_mppx() -> None:
    # pympp#309: mppx BodyDigest.compute({ z: '1', a: '2' })
    body = {"z": "1", "a": "2"}
    assert body_digest.compute(body) == "sha-256=WSxerte9Ij4rZhT5zPpISv1H2Sjidi2PaHo2Iu8d+Mc="
    assert body_digest.compute(body) != body_digest.compute({"a": "2", "z": "1"})
    nested = {"outer_z": {"inner_b": 1, "inner_a": 2}, "outer_a": 3}
    assert body_digest.compute(nested) == "sha-256=EVh89pgYAJz45/LcDMXKrGwCn8DVHGu3b28UfZw1dBE="


def test_integer_keys_first_like_json_stringify() -> None:
    # pympp#309: JSON.stringify enumerates integer-index keys first, ascending.
    compute = body_digest.compute
    assert compute({"b": 1, "1": 2}) == compute('{"1":2,"b":1}')
    assert compute({"z": "1", "10": "a", "2": "b", "a": "c"}) == compute(
        '{"2":"b","10":"a","z":"1","a":"c"}'
    )
    assert compute({"b": 1, "01": 2, "-1": 3, "4294967295": 4, "4294967294": 5}) == compute(
        '{"4294967294":5,"b":1,"01":2,"-1":3,"4294967295":4}'
    )
    assert compute({"x": [{"b": 1, "0": 2}], "5": {"a": 1, "3": 2}}) == compute(
        '{"5":{"3":2,"a":1},"x":[{"0":2,"b":1}]}'
    )
    key = "9" * 5000
    assert compute({"b": 1, key: 2}) == compute('{"b":1,"' + key + '":2}')


def test_verify_rejects_non_ascii_digest() -> None:
    assert not body_digest.verify("sha-256=é", "test")
    assert not body_digest.verify("sha-256=é", {"a": 1})
