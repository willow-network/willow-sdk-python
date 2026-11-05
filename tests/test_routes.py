"""Each client method reads the API route that serves it, and decodes the
shape that route answers."""

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from willow import (
    WillowClient,
    delete_file_manifest_message,
    sign_challenge,
    store_file_manifest_message,
    verify_signature,
)
from willow.errors import TransactionError
from willow.files import DEFAULT_CHUNK_SIZE
from willow.types import SubgroveStatus

API = "http://api.test"


def _envelope(data):
    return {"success": True, "data": data, "error": None}


def _client(responses):
    """A client whose API answers ``responses[path]`` and records each request."""
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=_envelope(responses[request.url.path]))

    client = WillowClient(API)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client, seen


@pytest.mark.asyncio
async def test_subgrove_balance_reads_token_subgrove_balance():
    client, seen = _client({
        "/token/subgrove/balance/sg": {
            "subgrove_id": "sg", "balance": 7, "total_spent": 3, "last_funded": 1,
        },
    })
    balance = await client.token.get_subgrove_balance("sg")
    assert [r.url.path for r in seen] == ["/token/subgrove/balance/sg"]
    assert (balance.account, balance.balance) == ("sg", 7)


@pytest.mark.asyncio
async def test_balance_decodes_the_did_balance_shape():
    client, _ = _client({
        "/token/balance/did:willow:a": {
            "did": "did:willow:a", "available": 10, "staked": 2, "locked": 1,
        },
    })
    balance = await client.token.get_balance("did:willow:a")
    assert (balance.account, balance.balance, balance.staked, balance.unbonding) == (
        "did:willow:a", 10, 2, 1,
    )


@pytest.mark.asyncio
async def test_fee_schedule_reads_fees_schedule():
    client, seen = _client({
        "/fees/schedule": {
            "did_registration": 1, "subgrove_registration": 2,
            "blockchain_indexing_subgrove_registration": 3, "indexer_registration": 4,
            "submit_anchor": 5, "base_tx_cost": 6, "cost_per_byte": 7, "query_fee": 8,
            "transfer_fee_percentage": 9, "max_tx_size_bytes": 10, "max_data_payload_bytes": 11,
        },
    })
    fees = await client.token.get_fee_schedule()
    assert [r.url.path for r in seen] == ["/fees/schedule"]
    assert (fees.base_tx_cost, fees.query_fee) == (6, 8)


INDEXED_SUBGROVE = {
    "subgrove_id": "aave-v3-lending", "name": "aave-v3-lending",
    "owner_did": "did:willow:validator1", "status": "active", "latest_block": 26336268,
    "deployment_block": 24, "indexers": ["did:willow:zIdx"], "chain": "mainnet",
}
INDEXER = {
    "indexer_did": "did:willow:zIdx", "subgroves": ["aave-v3-lending"],
    "stake_amount": 1, "endpoint": "https://indexer.test", "status": "active",
    "performance_score": 1.0, "last_update": 5,
}


@pytest.mark.asyncio
async def test_indexing_reads_subgrove_and_indexer_routes():
    client, seen = _client({
        "/subgroves/indexed": [INDEXED_SUBGROVE],
        "/subgroves/aave-v3-lending": INDEXED_SUBGROVE,
        "/subgroves/aave-v3-lending/status": {
            "subgrove_id": "aave-v3-lending", "owner_did": "did:willow:validator1",
            "deployment_block": 24, "total_queries": 9, "active_indexers": 1,
            "status": "indexing",
        },
        "/indexers": [INDEXER],
        "/indexers/did:willow:zIdx": INDEXER,
        "/verification/stats": {
            "total_blocks": 4, "verified_blocks": 3, "unverified_blocks": 1,
            "finalized_blocks": 2, "failed_blocks": 0, "verification_rate": 0.75,
        },
    })

    subgroves = await client.indexing.list_subgroves()
    subgrove = await client.indexing.get_subgrove("aave-v3-lending")
    status = await client.indexing.get_indexing_status("aave-v3-lending")
    indexers = await client.indexing.list_indexers()
    indexer = await client.indexing.get_indexer("did:willow:zIdx")
    stats = await client.indexing.get_verification_stats()

    assert [r.url.path for r in seen] == [
        "/subgroves/indexed",
        "/subgroves/aave-v3-lending",
        "/subgroves/aave-v3-lending/status",
        "/indexers",
        "/indexers/did:willow:zIdx",
        "/verification/stats",
    ]
    assert subgroves[0].status == SubgroveStatus.ACTIVE
    assert (subgrove.latest_block, subgrove.chain, subgrove.deployment_block) == (26336268, "mainnet", 24)
    assert (status.status, status.active_indexers, status.progress_percentage) == ("indexing", 1, None)
    assert indexers[0].indexer_did == indexer.indexer_did == "did:willow:zIdx"
    assert stats.verification_rate == 0.75


# ---------------------------------------------------------------------------
# File transactions go to /tx/submit, which bincode-encodes the JSON
# Transaction and answers CheckTx's {tx_hash, code, log}.
# ---------------------------------------------------------------------------


@pytest.fixture
def tx_submit(monkeypatch):
    """Route the file client's httpx.AsyncClient through a mocked transport.

    ``state["code"]`` is the CheckTx code /tx/submit answers.
    """
    state = {"code": 0, "requests": []}
    real_async_client = httpx.AsyncClient

    def handler(request):
        state["requests"].append(request)
        if request.url.path == "/tx/submit":
            log = "" if state["code"] == 0 else "Invalid signature: refused"
            return httpx.Response(200, json=_envelope(
                {"tx_hash": "ABCD", "code": state["code"], "log": log}
            ))
        return httpx.Response(200, json={})

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return state


def _signing():
    return {
        "owner_did": "did:willow:a",
        "private_key": "unused",
        "public_key_id": "did:willow:a#key-1",
        "sign_function": lambda message, key: "0x" + "ab" * 64,
        "nonce": 3,
    }


_KAT = json.loads(
    (Path(__file__).parent / "fixtures" / "signed_messages_kat.json").read_text(encoding="utf-8")
)


def _ed25519_signing(nonce):
    """Signs for real with the known-answer key, recording each message."""
    signed = []

    def sign(message, key):
        signed.append(message)
        return sign_challenge(message, key, "Ed25519")

    return signed, {
        "owner_did": "did:willow:a",
        "private_key": _KAT["private_key_seed_hex"],
        "public_key_id": _KAT["public_key_id"],
        "sign_function": sign,
        "nonce": nonce,
    }


def _submitted(state, kind):
    tx = httpx.Response(200, content=state["requests"][0].content).json()
    assert list(tx) == [kind]
    return tx[kind]


def _verifies(message, body):
    signature = bytes(body["signature"]).hex()
    return verify_signature(message, signature, _KAT["ed25519_public_key_hex"], "Ed25519")


@pytest.mark.asyncio
async def test_file_upload_submits_the_manifest_to_tx_submit(tx_submit):
    client = WillowClient(API)
    await client.files.upload("sg", "f", "a.txt", b"hello", "http://storage.test", _signing())

    submit = tx_submit["requests"][0]
    assert (submit.method, str(submit.url)) == ("POST", f"{API}/tx/submit")
    body = httpx.Response(200, content=submit.content).json()["StoreFileManifest"]
    # Byte fields as JSON arrays of numbers, as /tx/submit decodes them.
    assert body["content_hash"] == list(hashlib.sha256(b"hello").digest())
    assert len(body["chunk_merkle_root"]) == 32
    assert body["signature"] == [0xAB] * 64
    # The chunks went to the storage node after the manifest was accepted.
    assert [r.url.host for r in tx_submit["requests"][1:]] == ["storage.test"]


@pytest.mark.asyncio
async def test_file_upload_refused_by_checktx_raises_and_uploads_nothing(tx_submit):
    tx_submit["code"] = 1
    client = WillowClient(API)
    with pytest.raises(TransactionError) as exc_info:
        await client.files.upload("sg", "f", "a.txt", b"hello", "http://storage.test", _signing())
    assert exc_info.value.error_code == 1
    assert exc_info.value.tx_hash == "ABCD"
    assert [r.url.path for r in tx_submit["requests"]] == ["/tx/submit"]


@pytest.mark.asyncio
async def test_file_delete_and_unregister_go_to_tx_submit(tx_submit):
    client = WillowClient(API)
    await client.files.delete("sg", "f", _signing())
    await client.files.unregister_storage_node("did:willow:node", _signing())
    assert [r.url.path for r in tx_submit["requests"]] == ["/tx/submit", "/tx/submit"]
    delete = httpx.Response(200, content=tx_submit["requests"][0].content).json()
    assert delete["DeleteFileManifest"]["signature"] == [0xAB] * 64

    tx_submit["code"] = 5
    with pytest.raises(TransactionError):
        await client.files.delete("sg", "f", _signing())
    with pytest.raises(TransactionError):
        await client.files.unregister_storage_node("did:willow:node", _signing())


@pytest.mark.asyncio
async def test_file_upload_signs_every_field_and_the_nonce_it_sends(tx_submit):
    data = bytes(range(256)) * (DEFAULT_CHUNK_SIZE // 256) + b"tail"
    signed, signing = _ed25519_signing(9)
    client = WillowClient(API)
    await client.files.upload("files-1", "photo.png", "photo.png", data, "http://storage.test", signing)

    body = _submitted(tx_submit, "StoreFileManifest")
    assert (body["nonce"], body["chunk_count"], body["content_type"]) == (9, 2, "image/png")
    assert "encryption" not in body
    message = store_file_manifest_message(
        body["subgrove_id"], body["file_key"], body["owner_did"], body["filename"],
        body["content_type"], body["total_size"], body["content_hash"], body["chunk_count"],
        body["chunk_size"], body["chunk_merkle_root"], body["nonce"],
    )
    assert signed == [message]
    assert message.startswith("StoreFileManifest\nSubgrove: files-1\nKey: photo.png\n")
    assert message.endswith("\nEncryption: none\nNonce: 9")
    assert _verifies(message, body)


@pytest.mark.asyncio
async def test_file_upload_with_a_line_break_is_not_sent(tx_submit):
    _, signing = _ed25519_signing(9)
    client = WillowClient(API)
    with pytest.raises(ValueError, match="line break"):
        await client.files.upload("files-1", "photo.png", "a\nb.png", b"x", "http://storage.test", signing)
    assert tx_submit["requests"] == []


@pytest.mark.asyncio
async def test_file_delete_signs_the_nonce_it_sends(tx_submit):
    vector = next(v for v in _KAT["vectors"] if v["name"] == "DeleteFileManifest")
    i = vector["inputs"]
    signed, signing = _ed25519_signing(i["nonce"])
    client = WillowClient(API)
    await client.files.delete(i["subgrove_id"], i["file_key"], signing)

    body = _submitted(tx_submit, "DeleteFileManifest")
    message = delete_file_manifest_message(
        body["subgrove_id"], body["file_key"], body["owner_did"], body["nonce"]
    )
    assert signed == [message] == [vector["message"]]
    assert bytes(body["signature"]).hex() == vector["ed25519_signature_hex"]
    assert _verifies(message, body)


# ---------------------------------------------------------------------------
# Writes the API serves only as transactions, and the shapes routes answer.
# ---------------------------------------------------------------------------


def _tx_api(seen, account_nonce=0):
    def handler(request):
        seen.append(request)
        if request.url.path.endswith("/nonce"):
            return httpx.Response(200, json=_envelope({"did": "did:willow:a", "nonce": account_nonce}))
        if request.url.path == "/tx/submit":
            return httpx.Response(200, json=_envelope({"tx_hash": "AB", "code": 0, "log": ""}))
        # The API serves no other write: POST /data and the rest answer 501 or 404.
        return httpx.Response(501, json={"success": False, "data": None, "error": "disabled"})

    return handler


@pytest.mark.asyncio
async def test_data_store_is_the_store_data_known_answer():
    vector = next(v for v in _KAT["vectors"] if v["name"] == "StoreData")
    i = vector["inputs"]
    seen = []
    client = WillowClient(API)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(_tx_api(seen, i["nonce"] - 1)))
    client.set_identity(i["owner_did"], _KAT["private_key_seed_hex"], _KAT["public_key_id"])

    result = await client.data.store_item(i["subgrove_id"], i["key"], json.loads(i["data_utf8"]))

    assert result == {"tx_hash": "AB", "code": 0, "log": "", "did": i["owner_did"], "nonce": i["nonce"]}
    assert [r.url.path for r in seen] == [f"/account/{i['owner_did']}/nonce", "/tx/submit"]
    body = json.loads(seen[1].content)["StoreData"]
    assert bytes(body["data"]).decode("utf-8") == i["data_utf8"]
    assert body["nonce"] == i["nonce"]
    assert bytes(body["signature"]).hex() == vector["ed25519_signature_hex"]
    await client.close()


@pytest.mark.asyncio
async def test_health_reads_the_health_object_the_api_answers():
    # GET /health answers no envelope: an RFC 3339 timestamp and its checks.
    health = {
        "status": "degraded", "timestamp": "1970-01-01T00:00:01+00:00", "version": "0.1.0",
        "checks": {
            "storage": {"status": "healthy", "message": "GroveDB is accessible"},
            "consensus": {"status": "degraded", "message": "CometBFT unreachable or unhealthy"},
            "system": {"uptime_seconds": 12},
        },
    }
    client = WillowClient(API)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=health)))
    status = await client.health()
    assert (status.status, status.version) == ("degraded", "0.1.0")
    assert status.components["consensus"].status == "degraded"
    assert status.components["system"].uptime_seconds == 12
    await client.close()


@pytest.mark.asyncio
async def test_key_grantees_are_dids():
    client, seen = _client({"/key-grants/sg": ["did:willow:a", "did:willow:b"]})
    client.set_identity("did:willow:a", _KAT["private_key_seed_hex"], _KAT["public_key_id"])
    assert await client.privacy.list_key_grantees("sg") == ["did:willow:a", "did:willow:b"]


@pytest.mark.asyncio
async def test_a_refusal_in_an_envelope_raises_its_error():
    client = WillowClient(API)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"success": False, "data": None, "error": "Data not found"})
    ))
    client.set_identity("did:willow:a", _KAT["private_key_seed_hex"], _KAT["public_key_id"])
    from willow.errors import WillowError
    from willow.indexers import QuerySource

    with pytest.raises(WillowError, match="Data not found"):
        await client.data.get_unverified("sg", "k")
    with pytest.raises(WillowError, match="Data not found"):
        await client.indexing.sql_query("sg", "SELECT 1", source=QuerySource.VALIDATOR)
    await client.close()


@pytest.mark.asyncio
async def test_a_plain_text_refusal_is_reported():
    from willow.errors import ValidationError

    client = WillowClient(API)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(400, text="Invalid URL: Cannot parse `k`")
    ))
    with pytest.raises(ValidationError, match="Cannot parse"):
        await client.proof.get("sg", "k")
    await client.close()


@pytest.mark.asyncio
async def test_tx_submit_reports_a_body_the_api_could_not_decode(monkeypatch):
    real_async_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(lambda r: httpx.Response(
            422, text="Failed to deserialize the JSON body into the target type: missing field `owner_did`"
        ))
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    client = WillowClient(API)
    with pytest.raises(TransactionError, match="missing field `owner_did`"):
        await client.files.delete("sg", "f", _signing())


@pytest.mark.asyncio
@pytest.mark.parametrize("status,body,match", [
    (403, {"success": False, "data": None, "error": "Private subgrove file data is not available"}, "Private subgrove"),
    (404, {"error": "File not found: missing"}, "File not found"),
    (451, {"error": "Unavailable For Legal Reasons", "code": 451}, "Legal Reasons"),
])
async def test_file_reads_raise_the_apis_error(monkeypatch, status, body, match):
    from willow.errors import WillowError

    real_async_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(lambda r: httpx.Response(status, json=body))
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    client = WillowClient(API)
    with pytest.raises(WillowError, match=match):
        await client.files.metadata("sg", "f")
    with pytest.raises(WillowError, match=match):
        await client.files.list("sg")


@pytest.mark.asyncio
async def test_file_reads_decode_the_raw_shape(monkeypatch):
    manifest = {
        "file_key": "f", "filename": "a.txt", "content_type": "text/plain", "total_size": 5,
        "content_hash": "11" * 32, "chunk_count": 1, "chunk_size": 262144,
        "chunk_merkle_root": "22" * 32, "owner_did": "did:willow:a", "created_at": 1,
        "updated_at": 1, "encrypted": False,
    }
    real_async_client = httpx.AsyncClient

    def handler(request):
        if request.url.path == "/files/sg":
            return httpx.Response(200, json={"files": [manifest], "limit": 50, "start_after": None, "has_more": False})
        return httpx.Response(200, json=dict(manifest, storage_nodes=["https://storage.test"]))

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    client = WillowClient(API)
    assert (await client.files.metadata("sg", "f")).storage_nodes == ["https://storage.test"]
    assert [m.file_key for m in await client.files.list("sg")] == ["f"]
