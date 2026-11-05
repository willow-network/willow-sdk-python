"""Each request ends within a small multiple of the client's timeout.

httpx's timeout bounds each read, not the request: a server that sends one
byte at a time, each within the timeout, would keep a read or a write
pending without end. ``willow._body.send`` gives each request a total
deadline of ``DEADLINE_FACTOR`` times the client's timeout."""

import asyncio
import json
import time

import httpx
import pytest

from willow import NetworkError, WillowClient
from willow.auth import generate_did

TIMEOUT = 0.1


class _Drip(httpx.AsyncByteStream):
    """``body``, one byte every ``TIMEOUT / 2`` seconds: every read comes
    within the timeout, and the whole takes many times it."""

    def __init__(self, body):
        self._body = body

    async def __aiter__(self):
        for i in range(len(self._body)):
            await asyncio.sleep(TIMEOUT / 2)
            yield self._body[i:i + 1]


def _dripping(body):
    # 60 bytes at TIMEOUT / 2 each: 3 s, ten times the deadline.
    return httpx.Response(200, stream=_Drip(json.dumps(body).encode().ljust(60)))


def _client(handler):
    client = WillowClient("http://api.test", timeout=TIMEOUT)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=TIMEOUT)
    return client


@pytest.mark.asyncio
async def test_a_read_from_a_dripping_server_ends_at_the_deadline():
    client = _client(lambda request: _dripping({"status": "ok", "timestamp": 1}))
    started = time.monotonic()
    with pytest.raises(NetworkError, match="timed out"):
        await client.health()
    assert time.monotonic() - started < 1.0
    await client.close()


@pytest.mark.asyncio
async def test_a_write_whose_answer_drips_ends_at_the_deadline_and_keeps_its_transaction():
    # The answer started, so the transaction reached the API: it may run.
    submitted = []

    def handler(request):
        if request.url.path.endswith("/nonce"):
            return httpx.Response(200, json={"success": True, "data": {"nonce": 0}})
        submitted.append(json.loads(request.content))
        return _dripping({"success": True, "data": {"tx_hash": "AB", "code": 0, "log": ""}})

    client = _client(handler)
    info = generate_did()
    client.set_identity(info["did"], info["private_key"], info["public_key_id"])
    started = time.monotonic()
    with pytest.raises(NetworkError, match="timed out") as exc_info:
        await client.data.store_item("sg", "k", {"v": 1})
    assert time.monotonic() - started < 1.0
    error = exc_info.value
    assert (error.did, error.nonce) == (info["did"], 1)
    assert error.transaction == submitted[0]
    assert client._nonces.handout(info["did"], 1) is not None
    await client.close()
