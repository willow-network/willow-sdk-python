"""Reading HTTP answers under a cap on their size, one per kind of answer.

The SDK streams each answer and stops reading once it passes its route's
cap, raising ``ResponseTooLargeError``: an API, indexer, or node that
streams an endless answer can't exhaust memory. Every request asks for the
answer unencoded (``Accept-Encoding: identity``), and an answer in any other
``Content-Encoding`` is refused before it is decoded
(``ResponseEncodingError``): decoding takes memory the cap doesn't bound, as
a few hundred bytes of nested gzip decode to gigabytes. So a cap bounds the
bytes of one answer as sent. It doesn't bound the memory parsing them takes:
``json.loads`` builds an object for each element it reads, so an answer at
its cap can take a multiple of the cap once parsed (a list of empty
objects, many times its length).

Each cap is the smallest that holds the largest honest answer of its routes
where the node bounds that answer; where the request sets an answer's size
(a query's limit, the slots asked for) and the node sets no maximum, the cap
is ``LARGE``, and an answer past it is refused: ask for less.
"""

import asyncio
import json
from typing import Any, Iterable, Optional

import httpx

from .errors import ResponseEncodingError, ResponseTooLargeError

#: An answer of fixed shape, or a list the node keeps short: an account's
#: nonce, a balance, the token's info, the fee schedule, validators,
#: indexers, the health check, a ``/tx/submit`` answer, a DID's permissions,
#: key grants, subgrove information, state roots, a file manifest or a page
#: of the file list (at most 100 files), ERC-8004 answers, and CometBFT's
#: headers, status, and ABCI queries. These answers are a few KB; 4 MiB is
#: the chain's ``max_tx_bytes``, the most one transaction writes. The subgrove,
#: validator, and indexer lists aren't paged, so they grow with the chain: a
#: subgrove's entry is about 1 KB unless its schema is long, so 4 MiB holds
#: thousands.
SMALL = 4 << 20
#: A file chunk: the storage node's upload route takes a body of at most
#: 2 MiB (axum's default body limit), so it stores no longer chunk.
CHUNK = 2 << 20
#: An answer that carries what one transaction holds: CometBFT's ``/tx`` (a
#: transaction of at most ``max_tx_bytes``, 4 MiB, is 5.4 MiB in base64,
#: with its result beside it), and the API's ``/data`` value and ``/proof``
#: of a key. A value is at most what one transaction writes, and a proof
#: carries it in hex, twice its length, beside the hashes on its path.
TX = 12 << 20
#: CometBFT's ``/block``: a block of at most ``block.max_bytes``, 21 MiB,
#: carries its transactions in base64, 28 MiB, with its header and last
#: commit.
BLOCK = 32 << 20
#: An answer whose size the request sets, with no maximum on the node: a
#: ``/query`` page (100 documents unless the query sets a limit, each at
#: most ``max_data_payload_bytes``, 512 KiB: 50 MiB), GraphQL and SQL
#: answers, a historical query, a block's matched logs, and Ethereum state
#: answers (proofs of as many slots as asked for).
LARGE = 64 << 20

#: A request through ``send`` ends within this many times its client's
#: timeout (the longest of its connect, read, write, and pool timeouts):
#: httpx's timeout bounds each step, not the request, so a server that sends
#: one byte at a time, each within the timeout, could keep it pending
#: without end.
DEADLINE_FACTOR = 3

_DROPPED_HEADERS = (b"content-encoding", b"content-length", b"transfer-encoding")


def _refuse_encoded(values: Iterable[str]) -> None:
    """Raise ``ResponseEncodingError`` unless the ``Content-Encoding``
    header values given name no coding but ``identity``."""
    codings = [c.strip() for value in values for c in value.split(",")]
    named = [c for c in codings if c and c.lower() != "identity"]
    if named:
        raise ResponseEncodingError(", ".join(named))


async def send(
    http: httpx.AsyncClient, method: str, url: str, *, limit: int, **kwargs: Any
) -> httpx.Response:
    """``http.request(method, url, **kwargs)``, asking for the answer
    unencoded and reading at most ``limit`` bytes of its body, within
    ``DEADLINE_FACTOR`` times ``http``'s timeout.

    The response returned holds the body as sent, so ``json()``, ``text``,
    and ``raise_for_status()`` work as on any response.

    Raises:
        httpx.ReadTimeout: No whole answer came within the deadline (the
            request may have reached the server).
        ResponseEncodingError: The answer names a ``Content-Encoding`` other
            than ``identity``. Nothing of its body is read.
        ResponseTooLargeError: The body is longer than ``limit`` bytes, as
            its ``Content-Length`` says or as read. Nothing past the cap is
            kept.
        httpx.HTTPError: As ``http.request`` raises.
    """
    headers = httpx.Headers(kwargs.pop("headers", None))
    headers["Accept-Encoding"] = "identity"
    request = http.build_request(method, url, headers=headers, **kwargs)
    deadline = _deadline(http)
    try:
        return await asyncio.wait_for(_read(http, request, limit), deadline)
    except asyncio.TimeoutError:
        raise httpx.ReadTimeout(
            f"no whole answer within {deadline:g} s", request=request
        ) from None


def _deadline(http: httpx.AsyncClient) -> Optional[float]:
    """``DEADLINE_FACTOR`` times ``http``'s longest timeout; ``None`` when it
    has none."""
    timeout = http.timeout
    steps = [t for t in (timeout.connect, timeout.read, timeout.write, timeout.pool) if t is not None]
    return DEADLINE_FACTOR * max(steps) if steps else None


async def _read(http: httpx.AsyncClient, request: httpx.Request, limit: int) -> httpx.Response:
    """``send``'s request sent and its answer read, with no deadline."""
    response = await http.send(request, stream=True)
    try:
        _refuse_encoded(response.headers.get_list("content-encoding"))
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            raise ResponseTooLargeError(limit)
        body = bytearray()
        if response.is_stream_consumed:
            # A transport that hands back a response already read (httpx's
            # MockTransport does): its body is in memory.
            body += response.content
        else:
            async for chunk in response.aiter_raw():
                body += chunk
                if len(body) > limit:
                    raise ResponseTooLargeError(limit)
        if len(body) > limit:
            raise ResponseTooLargeError(limit)
    finally:
        await response.aclose()
    headers = [(k, v) for k, v in response.headers.raw if k.lower() not in _DROPPED_HEADERS]
    return httpx.Response(
        response.status_code,
        headers=headers,
        content=bytes(body),
        request=request,
        extensions=response.extensions,
    )


def aiohttp_session(**kwargs: Any) -> Any:
    """An ``aiohttp.ClientSession(**kwargs)`` that asks for each answer
    unencoded (``Accept-Encoding: identity``) and decodes none
    (``auto_decompress=False``): ``read_aiohttp`` refuses an encoded one."""
    import aiohttp

    headers = dict(kwargs.pop("headers", None) or {})
    headers["Accept-Encoding"] = "identity"
    return aiohttp.ClientSession(headers=headers, auto_decompress=False, **kwargs)


async def read_aiohttp(response: Any, limit: int) -> bytes:
    """The body of an ``aiohttp`` response, as sent, reading at most
    ``limit`` bytes. Open the session with ``aiohttp_session``, which
    decodes no ``Content-Encoding``.

    Raises:
        ResponseEncodingError: The answer names a ``Content-Encoding`` other
            than ``identity``. Nothing of its body is read.
        ResponseTooLargeError: The body is longer than ``limit`` bytes.
    """
    _refuse_encoded(response.headers.getall("Content-Encoding", ()))
    body = bytearray()
    while True:
        chunk = await response.content.read(1 << 16)
        if not chunk:
            return bytes(body)
        body += chunk
        if len(body) > limit:
            raise ResponseTooLargeError(limit)


async def json_aiohttp(response: Any, limit: int) -> Any:
    """The JSON body of an ``aiohttp`` response, reading at most ``limit``
    bytes (see ``read_aiohttp``).

    Raises:
        ResponseEncodingError: The answer is encoded (see ``read_aiohttp``).
        ResponseTooLargeError: The body is longer than ``limit`` bytes.
        ValueError: It isn't JSON.
    """
    return json.loads(await read_aiohttp(response, limit))
