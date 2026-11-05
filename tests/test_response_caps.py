"""Each answer is read under a cap on its size, one per kind of route.

A hostile API, indexer, or node can stream an answer without end; the SDK
stops reading once it passes its route's cap and raises
``ResponseTooLargeError``, so memory stays bounded."""

import json

import httpx
from multidict import CIMultiDict
import pytest

from willow import NetworkError, ResponseTooLargeError, WillowClient
from willow._body import CHUNK, LARGE, SMALL, TX
from willow.auth import generate_did
from willow.consensus import ConsensusClient, ConsensusConfig, ConsensusError


def _padded(payload, size):
    """``payload`` as JSON, padded with trailing spaces to ``size`` bytes."""
    text = json.dumps(payload).encode()
    assert len(text) <= size
    return text + b" " * (size - len(text))


def _client(handler, **kwargs):
    client = WillowClient("http://api.test", **kwargs)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


@pytest.mark.asyncio
async def test_a_small_route_refuses_one_byte_over_its_cap():
    sizes = [SMALL, SMALL + 1]

    def handler(request):
        assert request.url.path == "/account/did:willow:a/nonce"
        return httpx.Response(200, content=_padded({"success": True, "data": {"nonce": 7}}, sizes.pop(0)))

    client = _client(handler)
    assert await client._account_nonce("did:willow:a") == 7  # exactly the cap
    with pytest.raises(ResponseTooLargeError) as exc_info:
        await client._account_nonce("did:willow:a")
    assert exc_info.value.limit == SMALL
    await client.close()


@pytest.mark.asyncio
async def test_an_answer_past_its_cap_is_not_read_to_its_end():
    read = []

    async def endless():
        for _ in range(LARGE >> 20):
            read.append(1 << 20)
            yield b" " * (1 << 20)

    client = _client(lambda request: httpx.Response(200, content=endless()))
    with pytest.raises(ResponseTooLargeError):
        await client.health()
    assert sum(read) <= SMALL + (1 << 20)
    await client.close()


@pytest.mark.asyncio
async def test_a_content_length_past_the_cap_is_refused_before_reading():
    client = _client(lambda request: httpx.Response(
        200, headers={"Content-Length": str(SMALL + 1)}, content=b"{}",
    ))
    with pytest.raises(ResponseTooLargeError):
        await client.health()
    await client.close()


@pytest.mark.asyncio
async def test_a_value_route_reads_past_the_small_cap_up_to_its_own():
    value = {"blob": "x" * (SMALL + 1)}
    sizes = [TX, TX + 1]

    def handler(request):
        return httpx.Response(200, content=_padded({"success": True, "data": value}, sizes.pop(0)))

    client = _client(handler)
    info = generate_did()
    client.set_identity(info["did"], info["private_key"], info["public_key_id"])
    assert await client.data.get_unverified("sg", "k") == value
    with pytest.raises(ResponseTooLargeError):
        await client.data.get_unverified("sg", "k")
    await client.close()


@pytest.mark.asyncio
async def test_a_submission_whose_answer_is_too_long_keeps_its_nonce_and_transaction():
    # The answer came back, so the transaction reached the API: it may run.
    submitted = []

    def handler(request):
        if request.url.path.endswith("/nonce"):
            return httpx.Response(200, json={"success": True, "data": {"nonce": 0}})
        submitted.append(json.loads(request.content))
        return httpx.Response(200, content=_padded({"success": True, "data": {"code": 0}}, SMALL + 1))

    client = _client(handler)
    info = generate_did()
    client.set_identity(info["did"], info["private_key"], info["public_key_id"])
    with pytest.raises(NetworkError) as exc_info:
        await client.data.store_item("sg", "k", {"v": 1})
    error = exc_info.value
    assert isinstance(error, ResponseTooLargeError)
    assert (error.did, error.nonce) == (info["did"], 1)
    assert error.transaction == submitted[0]
    assert client._nonces.handout(info["did"], 1) is not None
    await client.close()


@pytest.mark.asyncio
async def test_a_file_chunk_past_the_storage_nodes_body_limit_is_refused(monkeypatch):
    manifest = {
        "file_key": "f", "filename": "a.bin", "content_type": "application/octet-stream",
        "total_size": CHUNK + 1, "content_hash": "11" * 32, "chunk_count": 1,
        "chunk_size": CHUNK + 1, "chunk_merkle_root": "22" * 32, "owner_did": "did:willow:a",
        "created_at": 1, "updated_at": 1, "encrypted": False,
    }
    real_async_client = httpx.AsyncClient

    def handler(request):
        if request.url.path == "/files/sg/f":
            return httpx.Response(200, json=manifest)
        assert request.url.path == "/chunk/sg/f/0"
        return httpx.Response(200, content=b"\0" * (CHUNK + 1))

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    client = WillowClient("http://api.test")
    with pytest.raises(ResponseTooLargeError) as exc_info:
        await client.files.download("sg", "f", "http://storage.test")
    assert exc_info.value.limit == CHUNK


class _Body:
    def __init__(self, data):
        self._data = data

    async def read(self, n=-1):
        chunk, self._data = self._data[:n], self._data[n:]
        return chunk


class _Answer:
    """aiohttp's response, whose whole body ``json()`` and ``text()`` read."""

    def __init__(self, body, status=200):
        self.status = status
        self.headers = CIMultiDict()
        self.content = _Body(body)
        self._whole = body

    async def json(self, content_type="application/json"):
        return json.loads(self._whole)

    async def text(self):
        return self._whole.decode()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.mark.asyncio
async def test_a_consensus_submission_whose_answer_is_too_long_may_have_reached_the_node():
    client = ConsensusClient(ConsensusConfig(
        consensus_rpc_url="http://rpc.test", api_url="http://api.test", max_retries=0,
    ))

    class Session:
        def post(self, url, json):
            return _Answer(_padded({"success": True, "data": {"code": 0}}, SMALL + 1))

    client._session = Session()
    with pytest.raises(ConsensusError, match="limit for its route") as exc_info:
        await client._broadcast_transaction({"StoreData": {}})
    assert exc_info.value._sent


@pytest.mark.asyncio
async def test_a_list_the_api_does_not_page_reads_past_the_small_cap():
    # The chain bounds no data subgrove's schema or access lists, so one
    # registration can fill a transaction and any account can push a list
    # past 4 MiB.
    body = _padded({"success": True, "data": [], "error": None}, SMALL + 1)
    assert len(body) > SMALL

    def handler(request):
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    client = _client(handler)
    try:
        assert await client.registration.list_subgroves() == []
    finally:
        await client.close()
