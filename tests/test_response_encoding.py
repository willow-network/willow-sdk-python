"""The SDK asks for each answer unencoded and refuses an encoded one.

Decoding a ``Content-Encoding`` takes memory the byte cap on an answer
doesn't bound: a few hundred bytes of nested gzip decode to gigabytes. So
every request asks for ``identity``, the SDK reads the body as sent, and an
answer that names any other coding is refused before it is decoded."""

import asyncio
import tracemalloc
import zlib

import httpx
import pytest

from willow import NetworkError, WillowClient
from willow import _body
from willow.consensus import ConsensusClient, ConsensusConfig, ConsensusError

#: Zeros a bomb decodes to: small enough that decoding it in full can't
#: exhaust the machine running the tests, large against the caps below.
INNER = 64 << 20
#: The most memory reading a refused bomb may take.
PEAK = 4 << 20


def _gzip_zeros(size):
    """``size`` zeros, gzipped, without holding them in memory."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, 31)
    out = [compressor.compress(bytes(1 << 20)) for _ in range(size >> 20)]
    out.append(compressor.flush())
    return b"".join(out)


def _gzip(data):
    compressor = zlib.compressobj(9, zlib.DEFLATED, 31)
    return compressor.compress(data) + compressor.flush()


def _sent(body, **headers):
    """An answer as a network transport hands it over: its body not yet
    read (``content=`` would have httpx read, and decode, it at once)."""
    headers["Content-Length"] = str(len(body))
    return httpx.Response(200, headers=headers, stream=httpx.ByteStream(body))


ONE_LAYER = _gzip_zeros(INNER)
TWO_LAYERS = _gzip(ONE_LAYER)


async def _peak(awaitable):
    """What ``awaitable`` raised, and the most memory it took."""
    tracemalloc.start()
    try:
        try:
            await awaitable
        except Exception as e:  # noqa: BLE001 - the test inspects it
            raised = e
        else:
            raised = None
        return raised, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("coding, body", [("gzip", ONE_LAYER), ("gzip, gzip", TWO_LAYERS)])
async def test_an_encoded_answer_is_refused_without_decoding_it(coding, body):
    asked = []

    def handler(request):
        asked.append(request.headers.get("accept-encoding"))
        return _sent(body, **{"Content-Encoding": coding})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        error, peak = await _peak(_body.send(http, "GET", "http://api.test/health", limit=1 << 20))
    assert peak < PEAK, f"reading a {len(body)}-byte {coding} answer took {peak >> 20} MiB"
    assert asked == ["identity"]
    assert isinstance(error, NetworkError) and "Content-Encoding" in str(error), error


@pytest.mark.asyncio
async def test_a_route_refuses_an_encoded_answer_as_a_network_error():
    def handler(request):
        return _sent(_gzip(b'{"status": "ok"}'), **{"Content-Encoding": "gzip"})

    client = WillowClient("http://api.test")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(NetworkError, match="Content-Encoding"):
        await client.health()
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("coding", ["identity", "Identity", ""])
async def test_an_answer_in_the_identity_coding_is_read(coding):
    def handler(request):
        return _sent(b'{"ok": true}', **{"Content-Encoding": coding})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        response = await _body.send(http, "GET", "http://api.test/x", limit=1 << 20)
    assert response.json() == {"ok": True}


async def _serve(answer):
    """A local HTTP server answering each request with ``answer``, and the
    request heads it read."""
    heads = []

    async def handle(reader, writer):
        heads.append((await reader.readuntil(b"\r\n\r\n")).decode("latin-1").lower())
        writer.write(answer)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}", heads


@pytest.mark.asyncio
async def test_the_aiohttp_clients_ask_for_identity_and_refuse_an_encoded_answer():
    answer = (
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-encoding: gzip\r\n"
        b"content-length: %d\r\n\r\n" % len(ONE_LAYER)
    ) + ONE_LAYER
    server, url, heads = await _serve(answer)
    try:
        client = ConsensusClient(ConsensusConfig(consensus_rpc_url=url, max_retries=0))
        await client.start()
        try:
            error, peak = await _peak(client._rpc_request("status", {}))
        finally:
            await client.stop()
    finally:
        server.close()
    assert peak < PEAK, f"reading a {len(ONE_LAYER)}-byte gzip answer took {peak >> 20} MiB"
    assert len(heads) == 1 and "\r\naccept-encoding: identity\r\n" in heads[0], heads
    assert isinstance(error, ConsensusError) and "Content-Encoding" in str(error), error
