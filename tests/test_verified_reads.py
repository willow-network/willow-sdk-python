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


RPC = "http://rpc.test:26657"


def _envelope(data):
    return {"success": True, "data": data, "error": None}


def _header(height, app_hash):
    """``GET /header``'s answer, as CometBFT 0.38 writes it (hashes as
    upper-case hex, heights as strings)."""
    return {"jsonrpc": "2.0", "id": -1, "result": {"header": {
        "version": {"block": "11", "app": "0"}, "chain_id": "willow-chain", "height": str(height),
        "time": "2026-01-01T00:00:00.000000000Z",
        "last_block_id": {"hash": "AB" * 32, "parts": {"total": 1, "hash": "CD" * 32}},
        "last_commit_hash": "", "data_hash": "", "validators_hash": "EF" * 32,
        "next_validators_hash": "EF" * 32, "consensus_hash": "01" * 32,
        "app_hash": app_hash.hex().upper(), "last_results_hash": "", "evidence_hash": "",
        "proposer_address": "02" * 20,
    }}}


def _rpc_error(message):
    return {"jsonrpc": "2.0", "id": -1, "error": {"code": -32603, "message": "Internal error", "data": message}}


def _consensus_rpc(seen, root_at, latest):
    """A CometBFT RPC serving, up to the height ``latest()``, header ``h``
    with app_hash ``root_at(h)`` (an error where that is None)."""
    def handler(request):
        assert "x-api-key" not in request.headers, "the consensus RPC got the API key"
        if request.url.path != "/header":
            return httpx.Response(404, json=_rpc_error("no route"))
        top = latest()
        asked = request.url.params.get("height")
        height = top if asked is None else int(asked)
        seen["heights"].append(None if asked is None else height)
        if height > top:
            return httpx.Response(500, json=_rpc_error(
                f"height {height} must be less than or equal to the current blockchain height {top}"
            ))
        root = root_at(height)
        if root is None:
            return httpx.Response(500, json=_rpc_error(f"height {height} is not available"))
        return httpx.Response(200, json=_header(height, root))
    return handler


def _get_client(proof=None, served=None, root=BOB_ROOT, latest=42, root_at=None, api_url="http://api.test"):
    """A client whose API serves bob's value and proof, and whose consensus
    RPC serves headers up to ``latest`` (an int, or a function read on each
    request), each carrying ``root`` (or ``root_at(height)``)."""
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

    client = WillowClient(api_url, api_key="wk_test", consensus_rpc_url=RPC)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client._rpc_http = httpx.AsyncClient(transport=httpx.MockTransport(_consensus_rpc(
        seen, root_at or (lambda height: root), latest if callable(latest) else (lambda: latest)
    )))
    d = generate_did()
    client.set_identity(d["did"], d["private_key"], d["public_key_id"])
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
async def test_get_raises_when_the_consensus_rpc_cant_be_reached():
    client, _ = _get_client()

    def unreachable(request):
        raise httpx.ConnectError("connection refused")

    client._rpc_http = httpx.AsyncClient(transport=httpx.MockTransport(unreachable))
    with pytest.raises(ProofVerificationError, match="No trusted root.*connection refused"):
        await client.data.get("my-sub", "user:bob")
    await client.close()


# ---------------------------------------------------------------------------
# The trusted root comes only from the consensus RPC the caller configures


@pytest.mark.asyncio
async def test_get_needs_a_consensus_rpc_and_sends_nothing_without_one():
    sent = []
    client = WillowClient("http://api.test")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(500)))
    client._rpc_http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(500)))
    d = generate_did()
    client.set_identity(d["did"], d["private_key"], d["public_key_id"])
    with pytest.raises(ProofVerificationError, match="no trusted header source: set consensus_rpc_url"):
        await client.data.get("my-sub", "user:bob")
    with pytest.raises(ProofVerificationError, match="no trusted header source: set consensus_rpc_url"):
        await client.get_root_hash()
    assert sent == []
    await client.close()


@pytest.mark.asyncio
async def test_get_trusts_no_header_the_api_serves(monkeypatch):
    # A hostile API serves a forged value with a proof of it, and would serve
    # a header carrying the forged root to anything that asks it for one (as
    # the light client did, at the API's own URL). The consensus RPC serves
    # the real root, so the forgery is refused.
    from willow.light_client import LightClient

    payload = b'{"balance":1000000000}'
    forged_proof, forged_root = _bobs_proof(b"\x00" + bytes([len(payload)]) + payload + b"\x00")
    asked_the_api = []

    async def trust_the_api(self):
        asked_the_api.extend(self.config.validator_endpoints)

    async def header_from_the_api(self, height):
        asked_the_api.extend(self.config.validator_endpoints)
        return SimpleNamespace(header=SimpleNamespace(app_hash=forged_root))

    monkeypatch.setattr(LightClient, "initialize_with_trust_on_first_use", trust_the_api)
    monkeypatch.setattr(LightClient, "get_header_by_height", header_from_the_api)
    client, seen = _get_client(
        proof={"proof": forged_proof.hex(), "height": 41}, served={"balance": 1000000000},
        api_url="https://api.example.com",
    )
    with pytest.raises(ProofVerificationError, match="Root hash mismatch"):
        await client.data.get("my-sub", "user:bob")
    assert asked_the_api == []
    assert 42 in seen["heights"]
    await client.close()


@pytest.mark.asyncio
async def test_get_waits_for_a_header_the_chain_hasnt_produced_yet():
    # The proof is of the state after the latest block, 41: header 42 comes next.
    reads = {"n": 0}

    def latest():
        reads["n"] += 1
        return 41 if reads["n"] < 4 else 42

    client, seen = _get_client(latest=latest)
    client._header_poll_interval = 0
    assert await client.data.get("my-sub", "user:bob") == {"balance": 250}
    assert seen["heights"][0] == 42 and seen["heights"][-1] == 42 and None in seen["heights"]
    await client.close()

    client, _ = _get_client(latest=41)
    client._header_poll_interval = 0
    client.timeout = 0
    with pytest.raises(ProofVerificationError, match="serves no header at height 42"):
        await client.data.get("my-sub", "user:bob")
    await client.close()


@pytest.mark.asyncio
async def test_get_refuses_a_header_at_another_height_or_without_an_app_hash():
    for body in (_header(43, BOB_ROOT), {"jsonrpc": "2.0", "id": -1, "result": {"header": None}},
                 {"jsonrpc": "2.0", "id": -1, "result": {"header": {"height": "42", "app_hash": ""}}}):
        client, _ = _get_client()
        asked = []
        client._rpc_http = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda r, b=body: asked.append(str(r.url)) or httpx.Response(200, json=b)
        ))
        with pytest.raises(ProofVerificationError, match="No trusted root: the consensus RPC answered"):
            await client.data.get("my-sub", "user:bob")
        assert asked == [f"{RPC}/header?height=42"]
        await client.close()


@pytest.mark.asyncio
async def test_get_root_hash_is_the_consensus_rpcs_latest_app_hash():
    client, seen = _get_client(root_at=lambda height: bytes([height]) * 32)
    assert await client.get_root_hash() == (bytes([42]) * 32).hex()
    assert seen["heights"] == [None]
    await client.close()


def test_completeness_reads_its_anchor_from_the_consensus_rpc():
    client = WillowClient("http://api.test:3031", consensus_rpc_url=RPC)
    assert client.completeness._rpc_url == RPC
    assert WillowClient("http://api.test:3031").completeness._rpc_url == "http://api.test:26657"


# ---------------------------------------------------------------------------
# The light client verifies no header


def _forged_light_block(height, app_hash, validators_hash, next_validators_hash, signer):
    """A header with one validator, the signer's, and its commit signed over
    the sign bytes the SDK used to check (its own JSON, not CometBFT's
    canonical vote encoding)."""
    import base64
    from datetime import datetime, timedelta, timezone
    from cryptography.hazmat.primitives import serialization
    from willow.light_client.types import LightBlock

    b64 = lambda b: base64.b64encode(b).decode()
    now = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=height - 100)
    stamp = now.isoformat().replace("+00:00", "Z")
    pub = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    block_hash, parts_hash = b"\x11" * 32, b"\x22" * 32
    sign_doc = {
        "type": "tendermint/SocketPV/SignVote", "height": str(height), "round": "0", "step": 3,
        "block_id": {"hash": block_hash.hex().upper(),
                     "part_set_header": {"total": 1, "hash": parts_hash.hex().upper()}},
        "timestamp": now.isoformat() + "Z",
    }
    signature = signer.sign(json.dumps(sign_doc, separators=(",", ":"), sort_keys=True).encode())
    return LightBlock.from_dict({
        "header": {
            "version": {"block": "11"}, "chain_id": "willow-chain", "height": str(height), "time": stamp,
            "last_block_id": None, "last_commit_hash": b64(b""), "data_hash": b64(b""),
            "validators_hash": b64(validators_hash), "next_validators_hash": b64(next_validators_hash),
            "consensus_hash": b64(b""), "app_hash": b64(app_hash), "last_results_hash": b64(b""),
            "evidence_hash": b64(b""), "proposer_address": b64(b""),
        },
        "commit": {
            "height": str(height), "round": "0",
            "block_id": {"hash": b64(block_hash), "part_set_header": {"total": "1", "hash": b64(parts_hash)}},
            "signatures": [{"block_id_flag": 2, "validator_address": b64(b"\x33" * 20),
                            "timestamp": stamp, "signature": b64(signature)}],
        },
        "validators": {"validators": [{"address": b64(b"\x33" * 20), "pub_key": {"value": b64(pub)},
                                       "voting_power": "10"}]},
    })


@pytest.mark.asyncio
async def test_a_header_signed_by_anyone_is_not_reported_verified():
    # A successor to a trusted header, carrying a forged app_hash, whose
    # validator set is the attacker's own key (never hashed against
    # validators_hash), signed over the SDK's own JSON sign bytes.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from willow.light_client import HeaderVerifier, LightClient
    from willow.light_client.types import LightClientConfig, TrustThreshold

    attacker = Ed25519PrivateKey.generate()
    trusted = _forged_light_block(100, bytes(32), b"REAL" * 8, b"NEXT" * 8, attacker)
    forged = _forged_light_block(101, BOB_ROOT, b"NEXT" * 8, b"NEXT" * 8, attacker)
    verifier = HeaderVerifier("willow-chain", TrustThreshold(2, 3))
    for result in (verifier.verify_header(forged, trusted, max_clock_drift_secs=300),
                   verifier.verify_header(forged, max_clock_drift_secs=300)):
        assert not result.success
        assert "not verified" in result.error

    light_client = LightClient(LightClientConfig(
        chain_id="willow-chain", validator_endpoints=["http://validator.test"], max_clock_drift_secs=300,
        min_validators_for_consensus=1,
    ))
    await light_client.initialize_with_trusted_header(trusted)

    async def serve_forged(height):
        return forged

    async def latest_is_the_forged_one():
        return 101

    light_client._fetch_header_from_validators = serve_forged
    light_client._get_latest_height_from_validators = latest_is_the_forged_one
    assert await light_client.get_header_by_height(101) is None
    assert not (await light_client.verify_header(forged)).success
    assert not (await light_client.sync_to_latest()).success
    assert await light_client.get_header_by_height(100) is trusted


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
