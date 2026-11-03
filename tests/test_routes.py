"""Each client method reads the API route that serves it, and decodes the
shape that route answers."""

import hashlib

import httpx
import pytest

from willow import WillowClient
from willow.errors import TransactionError
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
