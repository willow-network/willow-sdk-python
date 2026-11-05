"""Writes keep what a caller needs to follow them: a cancelled store its
progress, and file writes their ``{did, nonce}``; an upload waits for its
manifest before its chunks are taken."""

import asyncio

import httpx
import pytest

from willow import WillowClient
from willow.auth import generate_did


def _envelope(data):
    return {"success": True, "data": data, "error": None}


def _write_client(handler):
    client = WillowClient("http://api.test")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    d = generate_did()
    client.set_identity(d["did"], d["private_key"], d["public_key_id"])
    return client, d


@pytest.mark.asyncio
async def test_a_store_cancelled_mid_batch_carries_what_was_submitted():
    calls = {"n": 0}

    async def handler(request):
        if request.url.path.endswith("/nonce"):
            return httpx.Response(200, json=_envelope({"nonce": 0}))
        calls["n"] += 1
        if calls["n"] == 2:
            raise asyncio.CancelledError()
        return httpx.Response(200, json=_envelope({"tx_hash": "T1", "code": 0, "log": ""}))

    client, d = _write_client(handler)
    with pytest.raises(asyncio.CancelledError) as exc_info:
        await client.data.store("sg", {"a": {"n": 1}, "b": {"n": 2}, "c": {"n": 3}})
    error = exc_info.value
    assert [r["nonce"] for r in error.submitted] == [1]
    assert error.failed_key == "b"
    assert (error.did, error.nonce) == (d["did"], 2)
    await client.close()


def _storage_and_api(monkeypatch, chunk_answers):
    """Route file uploads' httpx clients through a mock: /tx/submit accepts,
    and the storage node answers each chunk POST from ``chunk_answers``."""
    state = {"requests": [], "answers": list(chunk_answers)}
    real_async_client = httpx.AsyncClient

    def handler(request):
        state["requests"].append(request)
        if request.url.path == "/tx/submit":
            return httpx.Response(200, json=_envelope({"tx_hash": "ABCD", "code": 0, "log": ""}))
        status = state["answers"].pop(0) if state["answers"] else 200
        return httpx.Response(status, json={"error": "No on-chain manifest found"} if status != 200 else {})

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return state


def _signing(nonce=7):
    return {
        "owner_did": "did:willow:a",
        "private_key": "unused",
        "public_key_id": "did:willow:a#key-1",
        "sign_function": lambda message, key: "ab" * 64,
        "nonce": nonce,
    }


@pytest.mark.asyncio
async def test_upload_returns_its_submission_and_waits_for_the_manifest(monkeypatch):
    state = _storage_and_api(monkeypatch, [403, 503, 200])
    client = WillowClient("http://api.test")
    manifest = await client.files.upload(
        "sg", "f", "a.txt", b"hello", "http://storage.test", _signing(), poll_interval=0
    )
    assert manifest.submission == {"tx_hash": "ABCD", "code": 0, "log": "", "did": "did:willow:a", "nonce": 7}
    assert [r.url.host for r in state["requests"]] == ["api.test"] + ["storage.test"] * 3
    await client.close()


@pytest.mark.asyncio
async def test_upload_raises_when_the_storage_node_never_takes_a_chunk(monkeypatch):
    _storage_and_api(monkeypatch, [403] * 1000)
    client = WillowClient("http://api.test")
    with pytest.raises(Exception) as exc_info:
        await client.files.upload(
            "sg", "f", "a.txt", b"hello", "http://storage.test", _signing(),
            landing_timeout=0, poll_interval=0,
        )
    assert "refused chunk 0" in str(exc_info.value)
    assert exc_info.value.chunk_index == 0
    assert exc_info.value.submission["nonce"] == 7
    await client.close()


@pytest.mark.asyncio
async def test_upload_raises_on_a_chunk_the_storage_node_refuses(monkeypatch):
    _storage_and_api(monkeypatch, [400])
    client = WillowClient("http://api.test")
    with pytest.raises(Exception, match="refused chunk 0"):
        await client.files.upload("sg", "f", "a.txt", b"hello", "http://storage.test", _signing(), poll_interval=0)
    await client.close()


@pytest.mark.asyncio
async def test_file_delete_and_unregister_return_their_submission(monkeypatch):
    _storage_and_api(monkeypatch, [])
    client = WillowClient("http://api.test")
    assert await client.files.delete("sg", "f", _signing(8)) == {
        "tx_hash": "ABCD", "code": 0, "log": "", "did": "did:willow:a", "nonce": 8,
    }
    result = await client.files.unregister_storage_node("did:willow:node", _signing(9))
    assert (result["did"], result["nonce"]) == ("did:willow:node", 9)
    await client.close()
