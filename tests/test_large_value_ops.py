"""Large-value merk ops (0x20..0x23, 0x28..0x2b).

grovedb 3.1.0 writes a proof value's length as a u16, so a value of 64 KiB or
more could not be proven. The Willow GroveDB fork writes such values with
large-value ops (u32 length). The fixtures are real proofs from the fork's
prover: a 70,000-byte item (its merk op is 0x20) and a 65,530-byte item whose
65,535-byte merk value is the largest a 3.1.0 op (0x03) carries.
"""

import json
import os

import pytest

from willow.grovedb import (
    GroveDBVerificationError,
    decode_grovedb_proof,
    verify_grovedb_proof,
    verify_item_at_path,
)
from willow.grovedb.merk_decoder import decode_merk_ops

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(FIXTURES, f"grovedb_{name}.json")) as f:
        return json.load(f)


def _kat_value(n):
    return bytes((i * 7 + 3) % 256 for i in range(n))


def _leaf_merk_proof(proof_bytes):
    layer = decode_grovedb_proof(proof_bytes).proof.root_layer
    for seg in (b"apps", b"data"):
        layer = layer.lower_layers[seg.hex()]
    return layer.merk_proof


@pytest.mark.parametrize("name,opcode", [("large_value_item", 0x20), ("small_value_item", 0x03)])
def test_real_proof_decodes_and_verifies(name, opcode):
    fx = _load(name)
    assert fx["item_opcode"] == opcode
    proof = bytes.fromhex(fx["proof_hex"])
    root = bytes.fromhex(fx["expected_root_hex"])
    key = fx["key"].encode()

    merk = _leaf_merk_proof(proof)
    assert bytes([opcode, len(key)]) + key in merk
    nodes = [op.node for op in decode_merk_ops(merk) if getattr(op, "node", None) is not None]
    item = [n for n in nodes if getattr(n, "key", None) == key]
    assert len(item) == 1 and type(item[0]).__name__ == "KVNode"
    assert len(item[0].value) == fx["element_len"]

    result = verify_grovedb_proof(proof)
    assert result.root_hash == root

    got_root, proven = verify_item_at_path(proof, fx["path"], fx["key"], root)
    assert got_root == root
    assert proven.value == _kat_value(fx["value_len"])


def _kv_large(declared, carried=None):
    carried = declared if carried is None else carried
    return bytes([0x20, 1, 0x6B]) + declared.to_bytes(4, "big") + bytes([9]) * carried


def test_every_large_value_op_decodes_as_the_op_it_mirrors():
    value = bytes([1]) * 65536
    body = bytes([1, 0x6B]) + (65536).to_bytes(4, "big") + value
    h = bytes([5]) * 32
    cases = [
        (0x20, "PushOp", "KVNode", b""),
        (0x21, "PushOp", "KVValueHashNode", h),
        (0x22, "PushOp", "KVRefValueHashNode", h),
        (0x23, "PushOp", "KVValueHashFeatureTypeNode", h + b"\x00"),
        (0x28, "PushInvertedOp", "KVNode", b""),
        (0x29, "PushInvertedOp", "KVValueHashNode", h),
        (0x2A, "PushInvertedOp", "KVRefValueHashNode", h),
        (0x2B, "PushInvertedOp", "KVValueHashFeatureTypeNode", h + b"\x00"),
    ]
    for op, push, node, tail in cases:
        (decoded,) = decode_merk_ops(bytes([op]) + body + tail)
        assert type(decoded).__name__ == push
        assert type(decoded.node).__name__ == node
        assert decoded.node.value == value


def test_large_value_op_with_a_short_value_is_refused():
    with pytest.raises(GroveDBVerificationError):
        decode_merk_ops(_kv_large(100))
    with pytest.raises(GroveDBVerificationError, match="at least 65536"):
        decode_merk_ops(_kv_large(65535))
    assert len(decode_merk_ops(_kv_large(65536))) == 1


def test_oversized_or_truncated_large_value_op_is_refused():
    with pytest.raises(GroveDBVerificationError, match="limit"):
        decode_merk_ops(_kv_large(64 * 1024 * 1024 + 1, 0))
    with pytest.raises(GroveDBVerificationError):
        decode_merk_ops(_kv_large(0xFFFFFFFF, 0))
    with pytest.raises(GroveDBVerificationError):
        decode_merk_ops(_kv_large(70000, 69999))
    with pytest.raises(GroveDBVerificationError, match="u32"):
        decode_merk_ops(bytes([0x21, 1, 0x6B, 0, 1]))


def test_unassigned_opcodes_stay_unknown():
    for op in (0x24, 0x25, 0x26, 0x27, 0x2C, 0x2D, 0x2E, 0x2F):
        with pytest.raises(GroveDBVerificationError, match="Unknown op code"):
            decode_merk_ops(bytes([op, 1, 0x6B, 0, 1, 0, 0]))


def test_truncations_of_the_large_value_proof_are_refused():
    proof = bytes.fromhex(_load("large_value_item")["proof_hex"])
    for n in range(0, len(proof), 997):
        with pytest.raises(GroveDBVerificationError):
            verify_grovedb_proof(proof[:n])
