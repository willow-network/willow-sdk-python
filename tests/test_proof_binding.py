"""A proof binds a value only at the path and key it proves it at.

The proofs in ``fixtures/grovedb_proofs.json`` are grovedb 3.1.0's own
(``prove_query`` over real state), with the roots grovedb computes. The SDK
must decode them, reproduce those roots, and bind a value only to the exact
path and key a proof proves it at, with the bytes its root commits to.
"""

import json
import os
from types import SimpleNamespace

import pytest

from willow import ProofVerifier, UnsupportedError, subgrove_data_path
from willow.grovedb import (
    GroveDBVerificationError,
    decode_grovedb_proof,
    quick_verify,
    value_hash,
    verify_grovedb_proof,
    verify_item_at_path,
    verify_items_at_path,
    verify_proof_against_root,
)
from willow.grovedb.bincode import MAX_LAYER_DEPTH, BincodeReader
from willow.grovedb.element import deserialize_element
from willow.grovedb.hash import combine_hash, kv_digest_to_kv_hash, kv_hash, node_hash
from willow.grovedb.types import NULL_HASH, ItemElement, LayerProof, ReferenceElement, SumItemElement
from willow.light_client import LightClient
from willow.light_client.types import LightClientConfig, QueryProof
from willow.light_client.verifier import ProofVerifier as LightClientProofVerifier
from willow.proof import (
    GroveDBProofVerifier,
    ProofVerificationOptions,
    configure_proof_verification,
    get_verifier,
    json_values_equal,
)
from willow.types import QueryResponse

with open(os.path.join(os.path.dirname(__file__), "fixtures", "grovedb_proofs.json")) as f:
    FX = json.load(f)


@pytest.fixture(autouse=True)
def _default_global_verifier():
    configure_proof_verification(ProofVerificationOptions())
    yield
    configure_proof_verification(ProofVerificationOptions())


BOB = FX["single_key_subgrove_data"]
BOB_PROOF = bytes.fromhex(BOB["proof_hex"])
BOB_ROOT = bytes.fromhex(BOB["root_hex"])


# ---------------------------------------------------------------------------
# A bincode encoder for GroveDB proofs, to tamper with real ones.

def _varint(n):
    if n < 251:
        return bytes([n])
    if n < 1 << 16:
        return b"\xfb" + n.to_bytes(2, "big")
    return b"\xfc" + n.to_bytes(4, "big")


def _encode_layer(layer):
    out = _varint(len(layer.merk_proof)) + layer.merk_proof + _varint(len(layer.lower_layers))
    for key_hex in sorted(layer.lower_layers, key=bytes.fromhex):
        key = bytes.fromhex(key_hex)
        out += _varint(len(key)) + key + _encode_layer(layer.lower_layers[key_hex])
    return out


def _encode_proof(proof):
    return b"\x00" + _encode_layer(proof.proof.root_layer) + (
        b"\x01" if proof.proof.prove_options.decrease_limit_on_empty_sub_query_result else b"\x00"
    )


def _layer_at(proof, path):
    layer = proof.proof.root_layer
    for segment in path:
        layer = layer.lower_layers[segment.encode().hex()]
    return layer


def _item(payload):
    return b"\x00" + _varint(len(payload)) + payload + b"\x00"


def _kv_op(key, element):
    return b"\x03" + bytes([len(key)]) + key + len(element).to_bytes(2, "big") + element


def _kv_value_hash_op(key, element, vh):
    return b"\x04" + bytes([len(key)]) + key + len(element).to_bytes(2, "big") + element + vh


# ---------------------------------------------------------------------------
# Decoding grovedb's encoding


def test_real_proofs_decode_and_reproduce_grovedbs_roots():
    for name in ("single_key_subgrove_data", "single_key_siblings", "range_full", "single_key_deep_tree"):
        fx = FX[name]
        proof = bytes.fromhex(fx["proof_hex"])
        assert quick_verify(proof).hex() == fx["root_hex"], name
        assert verify_grovedb_proof(proof).root_hash.hex() == fx["root_hex"], name


def test_varints_take_every_width_and_refuse_wider_than_the_integer():
    reader = BincodeReader(b"\x07" + b"\xfb\x01\x00" + b"\xfc\x00\x01\x00\x00" + b"\xfd" + (1 << 40).to_bytes(8, "big"))
    assert [reader.read_varint() for _ in range(4)] == [7, 256, 65536, 1 << 40]
    with pytest.raises(GroveDBVerificationError, match="discriminant"):
        BincodeReader(b"\xfd" + bytes(8)).read_varint(max_bytes=4)
    with pytest.raises(GroveDBVerificationError, match="discriminant"):
        BincodeReader(b"\xff").read_varint()
    # zigzag: 0, -1, 1, -2
    reader = BincodeReader(bytes([0, 1, 2, 3]))
    assert [reader.read_signed_varint() for _ in range(4)] == [0, -1, 1, -2]


def test_elements_decode_from_grovedbs_encoding():
    assert deserialize_element(_item(b'{"a":1}')) == ItemElement(value=b'{"a":1}', flags=None)
    assert deserialize_element(b"\x03\x03\x00") == SumItemElement(value=-2, flags=None)
    tree = deserialize_element(b"\x02\x01\x04data\x00")
    assert tree.root_key == b"data"
    # An absolute reference to subgroves/x, max hop 2
    ref = deserialize_element(b"\x01\x00\x02\x09subgroves\x01x\x01\x02\x00")
    assert ref == ReferenceElement(path=[b"subgroves", b"x"], flags=None, reference_type=0, max_hop=2)
    with pytest.raises(GroveDBVerificationError, match="Trailing bytes"):
        deserialize_element(_item(b"x") + b"\x00")


def test_trailing_bytes_after_a_proof_are_refused():
    with pytest.raises(GroveDBVerificationError, match="Trailing bytes"):
        decode_grovedb_proof(BOB_PROOF + b"\x00")


@pytest.mark.parametrize("merk", [
    b"\x03", b"\x04", b"\x05", b"\x06", b"\x07", b"\x0a", b"\x0b", b"\x0c", b"\x0d", b"\x0e",
    b"\x07\x01k\x00\x00" + bytes(32),  # KVValueHashFeatureType without its feature type
])
def test_a_merk_op_cut_short_is_refused(merk):
    proof = b"\x00" + _varint(len(merk)) + merk + b"\x00\x01"
    for verify in (quick_verify, verify_grovedb_proof):
        with pytest.raises(GroveDBVerificationError, match="Unexpected end"):
            verify(proof)


def _nested(levels):
    """A proof of ``levels`` layers, each with an empty merk proof and one
    lower layer under "k"."""
    return b"\x00" + b"\x00\x01\x01k" * levels + b"\x00\x00" + b"\x01"


def test_layers_nested_past_the_limit_are_refused():
    decode_grovedb_proof(_nested(MAX_LAYER_DEPTH))
    for proof in (_nested(MAX_LAYER_DEPTH + 1), _nested(5000)):
        for verify in (decode_grovedb_proof, quick_verify, verify_grovedb_proof):
            with pytest.raises(GroveDBVerificationError, match="nest deeper"):
                verify(proof)
        with pytest.raises(GroveDBVerificationError, match="nest deeper"):
            verify_item_at_path(proof, ["k"], "k")
        assert not ProofVerifier.verify_item_proof(proof.hex(), "k", b"v", ["k"]).valid
        assert not LightClientProofVerifier().verify_inclusion_proof(b"k", b"v", proof, bytes(32), ["k"])


def test_any_error_checking_a_proof_is_a_verification_error():
    for verify in (quick_verify, verify_grovedb_proof):
        with pytest.raises(GroveDBVerificationError, match="Malformed proof"):
            verify("not bytes")
    v = LightClientProofVerifier()
    assert not v.verify_inclusion_proof(b"user:bob", "not bytes", BOB_PROOF, BOB_ROOT, BOB["path"])
    assert not v.verify_inclusion_proof(b"user:bob", b"v", "not bytes", BOB_ROOT, BOB["path"])
    deep = b"[" * 5000 + b"]" * 5000
    assert not ProofVerifier.verify_item_proof(
        _single_item_proof(_item(deep)).hex(), "k", {"a": 1}, ["d"]
    ).valid


def test_a_deep_partial_proof_is_not_refused_as_unbalanced():
    fx = FX["single_key_deep_tree"]
    root, item = verify_item_at_path(bytes.fromhex(fx["proof_hex"]), fx["path"], fx["key"])
    assert root.hex() == fx["root_hex"]
    assert json.loads(item.value)["block_number"]


# ---------------------------------------------------------------------------
# Binding a value to its path and key


def test_a_single_key_proof_binds_its_item_at_its_path_and_key():
    root, item = verify_item_at_path(BOB_PROOF, BOB["path"], BOB["key"])
    assert root == BOB_ROOT
    assert item.value == bytes.fromhex(BOB["value_hex"])
    root, item = verify_item_at_path(BOB_PROOF, subgrove_data_path("my-sub"), b"user:bob", BOB_ROOT)
    assert item.key == b"user:bob"


def test_a_proof_binds_nothing_at_another_key_path_or_root():
    with pytest.raises(GroveDBVerificationError, match="does not prove an Item"):
        verify_item_at_path(BOB_PROOF, BOB["path"], "user:alice")  # only its hash is in the proof
    with pytest.raises(GroveDBVerificationError, match="does not descend"):
        verify_item_at_path(BOB_PROOF, subgrove_data_path("other-sub"), BOB["key"])
    with pytest.raises(GroveDBVerificationError, match="unexpected lower layers"):
        verify_item_at_path(BOB_PROOF, ["subgroves", "my-sub"], "data")
    with pytest.raises(GroveDBVerificationError, match="Root hash mismatch"):
        verify_item_at_path(BOB_PROOF, BOB["path"], BOB["key"], bytes(32))
    with pytest.raises(GroveDBVerificationError, match="path is required"):
        verify_item_at_path(BOB_PROOF, [], BOB["key"])


def test_a_lone_root_hash_proves_no_key():
    merk = b"\x01" + BOB_ROOT
    lone = b"\x00" + _varint(len(merk)) + merk + b"\x00\x01"
    assert quick_verify(lone) == BOB_ROOT  # it "verifies" to any root it names
    with pytest.raises(GroveDBVerificationError, match="does not descend"):
        verify_item_at_path(lone, BOB["path"], BOB["key"])
    result = ProofVerifier.verify_item_proof(lone.hex(), BOB["key"], {"balance": 250}, BOB["path"])
    assert not result.valid


def test_a_value_beside_the_honest_value_hash_is_refused():
    # KVValueHash carries a value and the value hash the root commits to; only
    # the hash enters the root. Swap bob's KV node for one carrying a forged
    # value beside the honest hash: the root is unchanged, the value is not his.
    proof = decode_grovedb_proof(BOB_PROOF)
    data = _layer_at(proof, BOB["path"])
    honest = _item(bytes.fromhex(BOB["value_hex"]))
    kv = _kv_op(b"user:bob", honest)
    assert data.merk_proof.count(kv) == 1
    forged = _kv_value_hash_op(b"user:bob", _item(b'{"balance":999999}'), value_hash(honest))
    data.merk_proof = data.merk_proof.replace(kv, forged)
    tampered = _encode_proof(proof)

    assert quick_verify(tampered) == BOB_ROOT
    with pytest.raises(GroveDBVerificationError, match="does not hash to the value hash"):
        verify_item_at_path(tampered, BOB["path"], BOB["key"])

    # Even the honest value beside its hash is not returned: grovedb proves
    # an Item as a KV node, and a value hash binds no bytes beside it.
    data.merk_proof = data.merk_proof.replace(forged, _kv_value_hash_op(b"user:bob", honest, value_hash(honest)))
    beside = _encode_proof(proof)
    assert quick_verify(beside) == BOB_ROOT
    with pytest.raises(GroveDBVerificationError, match="beside a value hash"):
        verify_item_at_path(beside, BOB["path"], BOB["key"])
    assert verify_items_at_path(beside, BOB["path"])[1] == []


# A parent tree "p" holds, at key "t", a non-empty subtree. Its root key and
# content are ground so that t's value hash, combine_hash(A, B), is also the
# value hash of the 63 bytes (A + B)[1:], which decode as an Item.
FORGE_ROOT_KEY = bytes.fromhex("6b003a2c06")
FORGE_CONTENT = _item(b'{"n":42}')


def _tree(root_key):
    return b"\x02\x01" + _varint(len(root_key)) + root_key + b"\x00"


def _layer(merk, lowers=()):
    out = _varint(len(merk)) + merk + _varint(len(lowers))
    for key, lower in lowers:
        out += _varint(len(key)) + key + lower
    return out


def _tree_as_item(node_op):
    """The honest proof of the subtree at p/t, a proof that carries, at
    p/t, the 63 bytes that decode as an Item in the node ``node_op`` makes,
    their Item's payload, and the root both reproduce."""
    tree = _tree(FORGE_ROOT_KEY)
    a = value_hash(tree)
    b = node_hash(kv_hash(FORGE_ROOT_KEY, FORGE_CONTENT), NULL_HASH, NULL_HASH)
    vh = combine_hash(a, b)
    forged = (a + b)[1:]
    assert len(forged) == 63 and value_hash(forged) == vh
    payload = deserialize_element(forged).value
    parent = _tree(b"t")
    parent_vh = combine_hash(value_hash(parent), node_hash(kv_digest_to_kv_hash(b"t", vh), NULL_HASH, NULL_HASH))
    top = _kv_value_hash_op(b"p", parent, parent_vh)
    honest = b"\x00" + _layer(top, [(b"p", _layer(_kv_value_hash_op(b"t", tree, vh), [
        (b"t", _layer(_kv_op(FORGE_ROOT_KEY, FORGE_CONTENT)))]))]) + b"\x01"
    tampered = b"\x00" + _layer(top, [(b"p", _layer(node_op(b"t", forged, vh)))]) + b"\x01"
    root = verify_grovedb_proof(honest).root_hash
    assert verify_item_at_path(honest, ["p", "t"], FORGE_ROOT_KEY)[1].value == b'{"n":42}'
    assert verify_grovedb_proof(tampered).root_hash == root
    return tampered, payload, root


def _assert_no_item_at_p_t(tampered, payload, root, match):
    with pytest.raises(GroveDBVerificationError, match=match):
        verify_item_at_path(tampered, ["p"], "t", root)
    assert verify_items_at_path(tampered, ["p"], root)[1] == []
    assert not ProofVerifier.verify_item_proof(tampered.hex(), "t", payload, ["p"]).valid
    assert not LightClientProofVerifier().verify_inclusion_proof(b"t", payload, tampered, root, ["p"])


def test_a_subtree_carried_beside_its_value_hash_is_not_an_item():
    tampered, payload, root = _tree_as_item(_kv_value_hash_op)
    _assert_no_item_at_p_t(tampered, payload, root, "beside a value hash")


def test_a_subtree_carried_as_a_kv_node_is_not_an_item():
    # A KV node's hash is computed from its bytes, and these 63 bytes hash
    # to the subtree's value hash.
    tampered, payload, root = _tree_as_item(lambda key, element, _vh: _kv_op(key, element))
    _assert_no_item_at_p_t(tampered, payload, root, "63 bytes long")


def _kv_ref_value_hash_op(key, referenced, nvh):
    return b"\x06" + bytes([len(key)]) + key + len(referenced).to_bytes(2, "big") + referenced + nvh


# A subtree at "t" whose root node's kv hash starts with 0x5f (95), as 1 in
# 256 subtree roots do: its root, a hash over 96 bytes, is then the value hash
# of the 95 bytes after that first byte.
REF_CONTENT = _item(b'{"n":14}')


def test_a_subtree_carried_as_a_reference_is_not_returned_as_its_value():
    # A KVRefValueHash node's value hash is combine_hash(nvh, value_hash(V)),
    # with nvh carried beside V; a subtree's is combine_hash(value_hash(its
    # element), root). With V the 95 bytes above, the two are the same.
    kvh = kv_hash(b"r", REF_CONTENT)
    assert kvh[0] == 95
    sub_root = node_hash(kvh, NULL_HASH, NULL_HASH)
    tree = _tree(b"r")
    vh = combine_hash(value_hash(tree), sub_root)
    honest = b"\x00" + _layer(_kv_value_hash_op(b"t", tree, vh), [(b"t", _layer(_kv_op(b"r", REF_CONTENT)))]) + b"\x01"
    root = verify_grovedb_proof(honest).root_hash
    forged_value = kvh[1:] + NULL_HASH + NULL_HASH
    assert len(forged_value) == 95 and value_hash(forged_value) == sub_root
    forged = b"\x00" + _layer(_kv_ref_value_hash_op(b"t", forged_value, value_hash(tree))) + b"\x01"
    (entry,) = verify_proof_against_root(forged, root).results
    assert entry["key"] == b"t" and entry["node_type"] == "KVRefValueHash"
    assert entry["value"] is None and entry["element"] is None
    assert entry["ambiguous_value"] == forged_value
    # One byte either side, a reference's value is bound and returned.
    for size in (94, 96):
        referenced = b"v" * size
        nvh = value_hash(b"reference element")
        proof = b"\x00" + _layer(_kv_ref_value_hash_op(b"t", referenced, nvh)) + b"\x01"
        (entry,) = verify_grovedb_proof(proof).results
        assert entry["value"] == referenced and entry["ambiguous_value"] is None


def _single_item_proof(element):
    """A proof of key "k" holding ``element`` in the subtree at "d"."""
    data = _tree(b"k")
    data_vh = combine_hash(value_hash(data), node_hash(kv_hash(b"k", element), NULL_HASH, NULL_HASH))
    return b"\x00" + _layer(_kv_value_hash_op(b"d", data, data_vh), [(b"d", _layer(_kv_op(b"k", element)))]) + b"\x01"


def test_a_63_byte_element_is_not_proven_as_an_item():
    # An Item with a 60-byte payload and no flags is 63 bytes: a proof can't
    # tell it from a subtree. One byte either side is proven.
    for size in (59, 61):
        payload = b"x" * size
        _, item = verify_item_at_path(_single_item_proof(_item(payload)), ["d"], "k")
        assert item.value == payload
    element = _item(b"x" * 60)
    assert len(element) == 63
    proof = _single_item_proof(element)
    with pytest.raises(GroveDBVerificationError, match="63 bytes long"):
        verify_item_at_path(proof, ["d"], "k")
    assert verify_items_at_path(proof, ["d"])[1] == []


def test_tampered_envelopes_are_refused():
    fx = FX["envelope_tampering"]
    root, item = verify_item_at_path(bytes.fromhex(fx["proof_hex"]), fx["path"], fx["key"])
    assert root.hex() == fx["root_hex"]
    for name, match in (
        ("renamed_layer_hex", "does not descend"),
        ("dropped_layer_hex", "does not descend"),
        ("prove_options_flipped_hex", "prove_options"),
    ):
        with pytest.raises(GroveDBVerificationError, match=match):
            verify_item_at_path(bytes.fromhex(fx[name]), fx["path"], fx["key"])


# ---------------------------------------------------------------------------
# A Hash node is opaque: its hash is the whole subtree's, so it can't have
# children. A node attached under one would be proven while the root ignores it.

# Each op that attaches a node to a parent, with the pushes it pops: the KV
# node ``kv`` ends up a child of the Hash node ``h``.
_ATTACH_TO_HASH = {
    "Parent": lambda h, kv: kv + h + b"\x10",
    "Child": lambda h, kv: h + kv + b"\x11",
    "ParentInverted": lambda h, kv: kv + h + b"\x12",
    "ChildInverted": lambda h, kv: h + kv + b"\x13",
}

BOB_KEY = b"user:bob"
BOB_ITEM = _item(b'{"balance":250}')
BOB_DATA_ROOT = node_hash(kv_hash(BOB_KEY, BOB_ITEM), NULL_HASH, NULL_HASH)
FORGED_KV = _kv_op(BOB_KEY, _item(b'{"balance":999999}'))


def _under_subgrove(data_merk, data_root, top=lambda merk: merk):
    """A proof of the merk proof ``data_merk`` (whose root is ``data_root``)
    as the data layer of subgroves/my-sub, and the root it reproduces;
    ``top`` rewrites the root layer's merk proof."""
    layer, root, below = _layer(data_merk), data_root, BOB_KEY
    for segment in (b"data", b"my-sub", b"subgroves"):
        tree = _tree(below)
        vh = combine_hash(value_hash(tree), root)
        merk = _kv_value_hash_op(segment, tree, vh)
        layer = _layer(top(merk) if segment == b"subgroves" else merk, [(segment, layer)])
        root = node_hash(kv_digest_to_kv_hash(segment, vh), NULL_HASH, NULL_HASH)
        below = segment
    return b"\x00" + layer + b"\x01", root


HONEST_BOB, HONEST_BOB_ROOT = _under_subgrove(_kv_op(BOB_KEY, BOB_ITEM), BOB_DATA_ROOT)


def _assert_forgery_refused(forged, root):
    path = subgrove_data_path("my-sub")
    for only_items in (False, True):
        with pytest.raises(GroveDBVerificationError, match="Hash node can't have children"):
            verify_item_at_path(forged, path, BOB_KEY, root, only_items_at_path=only_items)
    with pytest.raises(GroveDBVerificationError, match="Hash node can't have children"):
        verify_items_at_path(forged, path, root)
    for verify in (quick_verify, verify_grovedb_proof):
        with pytest.raises(GroveDBVerificationError, match="Hash node can't have children"):
            verify(forged)
    assert not ProofVerifier.verify_item_proof(forged.hex(), BOB_KEY, {"balance": 999999}, path).valid
    assert not LightClientProofVerifier().verify_inclusion_proof(
        BOB_KEY, b'{"balance":999999}', forged, root, path
    )


@pytest.mark.parametrize("op", sorted(_ATTACH_TO_HASH))
def test_a_node_under_a_hash_node_is_refused_at_the_data_path(op):
    root, item = verify_item_at_path(HONEST_BOB, subgrove_data_path("my-sub"), BOB_KEY)
    assert root == HONEST_BOB_ROOT and item.value == b'{"balance":250}'
    # The data layer is the honest one's root as a Hash node, with a forged
    # Item attached under it: the same root.
    forged, root = _under_subgrove(_ATTACH_TO_HASH[op](b"\x01" + BOB_DATA_ROOT, FORGED_KV), BOB_DATA_ROOT)
    assert root == HONEST_BOB_ROOT
    _assert_forgery_refused(forged, root)


@pytest.mark.parametrize("op", sorted(_ATTACH_TO_HASH))
def test_a_node_under_a_hash_node_is_refused_at_the_root_layer(op):
    # The root layer is the real root as a Hash node with an invented
    # subgroves subtree under it, whose lower layers prove a forged Item.
    forged_data_root = node_hash(kv_hash(BOB_KEY, _item(b'{"balance":999999}')), NULL_HASH, NULL_HASH)
    forged, _ = _under_subgrove(
        FORGED_KV, forged_data_root,
        top=lambda merk: _ATTACH_TO_HASH[op](b"\x01" + HONEST_BOB_ROOT, merk),
    )
    _assert_forgery_refused(forged, HONEST_BOB_ROOT)


def test_a_kvhash_node_keeps_its_children():
    # A KVHash node's hash covers its children: a proof may attach to it.
    from willow.grovedb import execute_ops
    from willow.grovedb.types import ChildOp, KVHashNode, KVNode, ParentOp, PushOp

    kvh = bytes(range(32))
    left, right = KVNode(b"a", BOB_ITEM), KVNode(b"c", BOB_ITEM)
    tree = execute_ops([PushOp(left), PushOp(KVHashNode(kvh)), ParentOp(), PushOp(right), ChildOp()])
    leaf = lambda k: node_hash(kv_hash(k, BOB_ITEM), NULL_HASH, NULL_HASH)
    assert tree.hash() == node_hash(kvh, leaf(b"a"), leaf(b"c"))


def test_a_lower_layer_off_the_path_is_refused():
    proof = decode_grovedb_proof(BOB_PROOF)
    root_layer = proof.proof.root_layer
    root_layer.lower_layers[b"other".hex()] = LayerProof(merk_proof=b"", lower_layers={})
    with pytest.raises(GroveDBVerificationError, match="off the query path"):
        verify_item_at_path(_encode_proof(proof), BOB["path"], BOB["key"])


def test_a_range_proof_proves_each_item_at_its_path():
    fx = FX["range_full"]
    root, items = verify_items_at_path(bytes.fromhex(fx["proof_hex"]), fx["path"])
    assert root.hex() == fx["root_hex"]
    assert [i.key.decode() for i in items] == fx["keys"]
    assert [i.value.hex() for i in items] == fx["values_hex"]


# ---------------------------------------------------------------------------
# The public verifiers


@pytest.mark.asyncio
async def test_the_item_verifier_binds_key_value_and_path_inside_a_running_loop():
    value = {"balance": 250}
    # Synchronous, called inside this running event loop.
    result = ProofVerifier.verify_item_proof(BOB["proof_hex"], BOB["key"], value, BOB["path"])
    assert result.valid and result.root_hash == BOB["root_hex"]
    assert result.results[0]["value"] == bytes.fromhex(BOB["value_hex"])
    assert ProofVerifier.verify_item_proof(BOB["proof_hex"], BOB["key"], bytes.fromhex(BOB["value_hex"]), BOB["path"]).valid

    for key, val, path in (
        ("user:alice", value, BOB["path"]),
        (BOB["key"], {"balance": 251}, BOB["path"]),
        (BOB["key"], {"balance": 250.0}, BOB["path"]),
        (BOB["key"], {"balance": True}, BOB["path"]),
        (BOB["key"], value, subgrove_data_path("other-sub")),
        (BOB["key"], value, []),
        ("", value, BOB["path"]),
    ):
        assert not ProofVerifier.verify_item_proof(BOB["proof_hex"], key, val, path).valid, (key, val, path)

    result = await get_verifier().verify_item_proof(BOB["proof_hex"], BOB["key"], value, BOB["path"])
    assert result.valid

    pinned = GroveDBProofVerifier(ProofVerificationOptions(expected_root_hash="00" * 32))
    result = pinned.verify_item(BOB["proof_hex"], BOB["key"], value, BOB["path"])
    assert not result.valid and "Root hash mismatch" in result.error
    pinned = GroveDBProofVerifier(ProofVerificationOptions(expected_root_hash=BOB["root_hex"]))
    assert pinned.verify_item(BOB["proof_hex"], BOB["key"], value, BOB["path"]).valid

    with pytest.raises(TypeError):
        ProofVerifier.verify_item_proof(BOB["proof_hex"], BOB["key"], value)  # no path


@pytest.mark.asyncio
async def test_the_query_verifier_binds_each_document_to_an_item_at_the_path():
    fx = FX["range_full"]
    documents = [bytes.fromhex(v) for v in fx["values_hex"]]
    result = ProofVerifier.verify_query_proof(fx["proof_hex"], documents[::-1], fx["path"])
    assert result.valid and result.root_hash == fx["root_hex"]
    assert not ProofVerifier.verify_query_proof(fx["proof_hex"], documents + documents[:1], fx["path"]).valid
    assert not ProofVerifier.verify_query_proof(fx["proof_hex"], [b"forged"], fx["path"]).valid
    assert not ProofVerifier.verify_query_proof(fx["proof_hex"], documents, ["apps", "other"]).valid
    result = await get_verifier().verify_query_proof(fx["proof_hex"], [{"forged": True}])
    assert not result.valid and "path is required" in result.error
    response = QueryResponse(documents=[{"balance": 250}], total=1, proof=BOB["proof_hex"])
    assert ProofVerifier.verify_query_response(response, BOB["path"]).valid
    assert not ProofVerifier.verify_query_response(response, subgrove_data_path("other")).valid


def test_json_values_compare_by_type():
    assert json_values_equal({"a": [1, "x", None, {"b": False}]}, {"a": [1, "x", None, {"b": False}]})
    for a, b in ((1, 1.0), (True, 1), (0, False), ({"a": 1}, {"a": 1, "b": 2}), ([1], [1, 1]), (None, 0), ("1", 1)):
        assert not json_values_equal(a, b), (a, b)


def test_the_light_client_inclusion_check_binds_path_key_and_value():
    v = LightClientProofVerifier()
    value = bytes.fromhex(BOB["value_hex"])
    assert v.verify_inclusion_proof(b"user:bob", value, BOB_PROOF, BOB_ROOT, BOB["path"])
    assert not v.verify_inclusion_proof(b"user:bob", b'{"balance":1}', BOB_PROOF, BOB_ROOT, BOB["path"])
    assert not v.verify_inclusion_proof(b"user:alice", value, BOB_PROOF, BOB_ROOT, BOB["path"])
    assert not v.verify_inclusion_proof(b"user:bob", value, BOB_PROOF, bytes(32), BOB["path"])
    assert not v.verify_inclusion_proof(b"user:bob", value, BOB_PROOF, BOB_ROOT, subgrove_data_path("x"))
    with pytest.raises(UnsupportedError):
        v.verify_absence_proof(b"user:alice", BOB_PROOF, BOB_ROOT)


@pytest.mark.asyncio
async def test_the_light_client_checks_a_query_proof_against_the_next_header():
    # A proof made at block h proves the state after it: header h + 1's root.
    client = LightClient(LightClientConfig(
        chain_id="test", validator_endpoints=["http://validator.test"], min_validators_for_consensus=1
    ))
    asked = []

    async def header(height):
        asked.append(height)
        return SimpleNamespace(header=SimpleNamespace(app_hash=BOB_ROOT if height == 42 else bytes(32)))

    client.get_header_by_height = header
    value = bytes.fromhex(BOB["value_hex"])
    proof = QueryProof(proof=BOB_PROOF, path_query={"path": BOB["path"]}, height=41, query_result=[value])
    assert (await client.verify_query_proof(proof)).success
    assert (await client.verify_query_proof(proof, height=41)).success
    assert not (await client.verify_query_proof(proof, height=0)).success
    assert asked == [42, 42, 1]


def test_the_light_client_query_check_binds_its_results_to_the_path():
    v = LightClientProofVerifier()
    value = bytes.fromhex(BOB["value_hex"])
    bound = QueryProof(proof=BOB_PROOF, path_query={"path": BOB["path"]}, height=1, query_result=[value])
    assert v.verify_query_proof(bound, BOB_ROOT).success
    assert not v.verify_query_proof(bound, bytes(32)).success
    forged = QueryProof(proof=BOB_PROOF, path_query={"path": BOB["path"]}, height=1, query_result=[b"forged"])
    assert not v.verify_query_proof(forged, BOB_ROOT).success
    no_path = QueryProof(proof=BOB_PROOF, path_query={}, height=1, query_result=[value])
    assert not v.verify_query_proof(no_path, BOB_ROOT).success
