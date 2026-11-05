"""client.data.get returns a value only when its proof binds it to its key
under the subgrove's data and the root is the trusted header's; queries and
historical queries are not verified, and say so."""

import json
import os
from types import SimpleNamespace

import httpx
import pytest

from willow import ProofVerificationError, UnsupportedError, WillowClient
from willow.auth import generate_did
from willow.grovedb import GroveDBVerificationError, verify_item_at_path
from willow.grovedb.hash import combine_hash, kv_digest_to_kv_hash, kv_hash, node_hash, value_hash
from willow.grovedb.types import NULL_HASH
from willow.types import HistoricalQueryResponse, QueryResponse

with open(os.path.join(os.path.dirname(__file__), "fixtures", "grovedb_proofs.json")) as f:
    FX = json.load(f)

BOB = FX["single_key_subgrove_data"]
BOB_ROOT = bytes.fromhex(BOB["root_hex"])


def _envelope(data):
    return {"success": True, "data": data, "error": None}


def _get_client(proof=None, served=None, root=BOB_ROOT):
    """A client whose API serves bob's value and proof, and whose light
    client trusts ``root`` at the height asked."""
    seen = {"requests": [], "heights": []}
    proof_data = {"proof": BOB["proof_hex"], "path": [], "key": b"user:bob".hex(), "height": 41}
    if proof is not None:
        proof_data = proof

    def handler(request):
        seen["requests"].append(request.url.path)
        if request.url.path == "/data/my-sub/user:bob":
            return httpx.Response(200, json=_envelope({"balance": 250} if served is None else served))
        if request.url.path == "/proof/my-sub/user:bob":
            return httpx.Response(200, json=_envelope(proof_data))
        return httpx.Response(404, json={"success": False, "error": "not found"})

    client = WillowClient("http://api.test")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    d = generate_did()
    client.set_identity(d["did"], d["private_key"], d["public_key_id"])

    class FakeLightClient:
        async def get_header_by_height(self, height):
            seen["heights"].append(height)
            if root is None:
                return None
            return SimpleNamespace(header=SimpleNamespace(app_hash=root))

    client._light_client = FakeLightClient()
    return client, seen


@pytest.mark.asyncio
async def test_get_returns_the_value_its_proof_proves_under_the_trusted_root():
    client, seen = _get_client()
    assert await client.data.get("my-sub", "user:bob") == {"balance": 250}
    assert seen["requests"] == ["/data/my-sub/user:bob", "/proof/my-sub/user:bob"]
    # The proof is of the state after block 41: header 42 carries its root.
    assert seen["heights"] == [42]
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs,match", [
    ({"served": {"balance": 999999}}, "not the value its proof proves"),
    ({"served": {"balance": 250, "extra": 1}}, "not the value its proof proves"),
    ({"root": bytes(32)}, "Root hash mismatch"),
    ({"root": None}, "No trusted root"),
    ({"proof": {"proof": None}}, "no proof"),
    ({"proof": {}}, "no proof"),
    ({"proof": {"proof": BOB["proof_hex"]}}, "no block height"),
    ({"proof": {"proof": BOB["proof_hex"], "height": True}}, "no block height"),
    ({"proof": {"proof": "zz", "height": 1}}, "Proof verification failed"),
    ({"proof": {"proof": FX["single_key_siblings"]["proof_hex"], "height": 1}}, "does not descend"),
])
async def test_get_raises_unless_the_proof_binds_the_value_served(kwargs, match):
    client, _ = _get_client(**kwargs)
    with pytest.raises(ProofVerificationError, match=match):
        await client.data.get("my-sub", "user:bob")
    await client.close()


def _varint(n):
    return bytes([n]) if n < 251 else b"\xfb" + n.to_bytes(2, "big")


def _layer(merk, lowers=()):
    out = _varint(len(merk)) + merk + _varint(len(lowers))
    for key, lower in lowers:
        out += _varint(len(key)) + key + lower
    return out


def _bobs_proof(element, data_merk=None):
    """A proof that user:bob holds ``element`` under subgroves/my-sub/data
    (whose merk proof is ``data_merk`` when given), and its root."""
    key = b"user:bob"
    layer = _layer(data_merk or b"\x03" + bytes([len(key)]) + key + len(element).to_bytes(2, "big") + element)
    root = node_hash(kv_hash(key, element), NULL_HASH, NULL_HASH)
    below = key
    for segment in (b"data", b"my-sub", b"subgroves"):
        tree = b"\x02\x01" + bytes([len(below)]) + below + b"\x00"
        vh = combine_hash(value_hash(tree), root)
        merk = b"\x04" + bytes([len(segment)]) + segment + len(tree).to_bytes(2, "big") + tree + vh
        layer = _layer(merk, [(segment, layer)])
        root = node_hash(kv_digest_to_kv_hash(segment, vh), NULL_HASH, NULL_HASH)
        below = segment
    return b"\x00" + layer + b"\x01", root


@pytest.mark.asyncio
async def test_get_fails_closed_on_a_malformed_proof():
    payload = b'{"balance":250}'
    proof, root = _bobs_proof(b"\x00" + bytes([len(payload)]) + payload + b"\x00")
    client, _ = _get_client(proof={"proof": proof.hex(), "height": 1}, root=root)
    assert await client.data.get("my-sub", "user:bob") == {"balance": 250}
    await client.close()

    deep = b"[" * 5000 + b"]" * 5000
    deep_item, deep_root = _bobs_proof(b"\x00\xfb" + len(deep).to_bytes(2, "big") + deep + b"\x00")
    for proof, root, match in (
        (_bobs_proof(b"", data_merk=b"\x03")[0], BOB_ROOT, "Unexpected end"),  # a KV op cut short
        (b"\x00" + b"\x00\x01\x01k" * 5000 + b"\x00\x00\x01", BOB_ROOT, "nest deeper"),
        (deep_item, deep_root, "Proof verification failed"),  # JSON nested too deep to parse
    ):
        client, _ = _get_client(proof={"proof": proof.hex(), "height": 1}, root=root)
        with pytest.raises(ProofVerificationError, match=match):
            await client.data.get("my-sub", "user:bob")
        await client.close()


@pytest.mark.asyncio
async def test_get_refuses_an_item_attached_under_a_hash_node():
    # The data layer is the honest root as a Hash node with a forged Item
    # attached under it: the proof reproduces the trusted root.
    key = b"user:bob"
    real = b"\x00" + bytes([15]) + b'{"balance":250}' + b"\x00"
    forged = b"\x00" + bytes([18]) + b'{"balance":999999}' + b"\x00"
    real_data_root = node_hash(kv_hash(key, real), NULL_HASH, NULL_HASH)
    _, root = _bobs_proof(real)
    kv = b"\x03" + bytes([len(key)]) + key + len(forged).to_bytes(2, "big") + forged
    proof, forged_root = _bobs_proof(real, data_merk=b"\x01" + real_data_root + kv + b"\x11")
    assert forged_root == root
    client, _ = _get_client(proof={"proof": proof.hex(), "height": 41}, root=root, served={"balance": 999999})
    with pytest.raises(ProofVerificationError, match="Hash node can't have children"):
        await client.data.get("my-sub", "user:bob")
    await client.close()


@pytest.mark.asyncio
async def test_get_returns_a_value_whose_item_is_63_bytes():
    # A 60-byte JSON text is a 63-byte Item. A proof can't tell 63 bytes
    # from a subtree's or a reference's value hash, but a subgrove's data
    # tree holds only Items, so data.get returns it; the generic verifier
    # still refuses it.
    payload = b'{"note":"' + b"x" * 49 + b'"}'
    element = b"\x00" + bytes([len(payload)]) + payload + b"\x00"
    assert len(payload) == 60 and len(element) == 63
    proof, root = _bobs_proof(element)
    client, _ = _get_client(proof={"proof": proof.hex(), "height": 1}, root=root, served={"note": "x" * 49})
    assert await client.data.get("my-sub", "user:bob") == {"note": "x" * 49}
    await client.close()
    with pytest.raises(GroveDBVerificationError, match="63 bytes long"):
        verify_item_at_path(proof, ["subgroves", "my-sub", "data"], "user:bob", root)
    _, item = verify_item_at_path(proof, ["subgroves", "my-sub", "data"], "user:bob", root, only_items_at_path=True)
    assert item.value == payload


@pytest.mark.asyncio
async def test_get_raises_when_the_light_client_cant_start():
    client, _ = _get_client()

    async def no_light_client():
        raise RuntimeError("no validator answered")

    client._light_client = None
    client._get_or_create_light_client = no_light_client
    with pytest.raises(ProofVerificationError, match="No trusted root.*no validator answered"):
        await client.data.get("my-sub", "user:bob")
    await client.close()


@pytest.mark.asyncio
async def test_get_unverified_reads_only_the_value():
    client, seen = _get_client()
    assert await client.data.get_unverified("my-sub", "user:bob") == {"balance": 250}
    assert seen["requests"] == ["/data/my-sub/user:bob"]
    await client.close()


# ---------------------------------------------------------------------------
# Queries and historical queries are not verified


@pytest.mark.asyncio
async def test_a_verified_query_raises_without_a_request():
    sent = []
    client = WillowClient("http://api.test")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(500)))
    d = generate_did()
    client.set_identity(d["did"], d["private_key"], d["public_key_id"])
    with pytest.raises(UnsupportedError, match="query_unverified"):
        await client.data.query("sg", {})
    with pytest.raises(UnsupportedError, match="historical"):
        await client.data.query_historical_verified("sg", "cp", {"path": [[1]]})
    assert sent == []
    with pytest.raises(UnsupportedError):
        QueryResponse(documents=[{"a": 1}], total=1, proof="00").verify_proof()
    with pytest.raises(UnsupportedError):
        HistoricalQueryResponse(success=True, state_root="00" * 32, block_range=(1, 2), data={}, proof="00").verify_proof()
    await client.close()
