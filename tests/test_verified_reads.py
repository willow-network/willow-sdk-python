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
