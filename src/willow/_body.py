"""Reading HTTP answers under a cap on their size, one per kind of answer.

The SDK streams each answer and stops reading once it passes its route's
cap, raising ``ResponseTooLargeError``: an API, indexer, or node that
streams an endless answer can't exhaust memory. A cap bounds the bytes read
of one answer, after any ``Content-Encoding`` is decoded, not the memory
decoding them takes: ``json.loads`` builds an object for each element it
reads, so an answer at its cap can take a multiple of the cap once decoded
(a list of empty objects, many times its length).

Each cap is the smallest that holds the largest honest answer of its routes
where the node bounds that answer; where the request sets an answer's size
(a query's limit, the slots asked for) and the node sets no maximum, the cap
is ``LARGE``, and an answer past it is refused: ask for less.
"""

import json
from typing import Any

import httpx

from .errors import ResponseTooLargeError

#: An answer of fixed shape, or a list the node keeps short: an account's
#: nonce, a balance, the token's info, the fee schedule, validators,
#: indexers, the health check, a ``/tx/submit`` answer, a DID's permissions,
#: key grants, subgrove information, state roots, a file manifest or the
#: file list, ERC-8004 answers, and CometBFT's headers, status, and ABCI
#: queries. These answers are a few KB; 4 MiB is the chain's
#: ``max_tx_bytes``, the most one transaction writes. The subgrove,
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

_DROPPED_HEADERS = (b"content-encoding", b"content-length", b"transfer-encoding")


async def send(
    http: httpx.AsyncClient, method: str, url: str, *, limit: int, **kwargs: Any
) -> httpx.Response:
    """``http.request(method, url, **kwargs)``, reading at most ``limit``
    bytes of the answer's body.

    The response returned holds the decoded body (its ``Content-Encoding``
    header dropped), so ``json()``, ``text``, and ``raise_for_status()``
    work as on any response.

    Raises:
        ResponseTooLargeError: The body is longer than ``limit`` bytes, as
            its ``Content-Length`` says or as read. Nothing past the cap is
            kept.
        httpx.HTTPError: As ``http.request`` raises.
    """
    request = http.build_request(method, url, **kwargs)
    response = await http.send(request, stream=True)
    try:
        declared = response.headers.get("content-length", "")
        if (
            "content-encoding" not in response.headers
            and declared.isdigit()
            and int(declared) > limit
        ):
            raise ResponseTooLargeError(limit)
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body += chunk
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


async def read_aiohttp(response: Any, limit: int) -> bytes:
    """The body of an ``aiohttp`` response, reading at most ``limit`` bytes.

    Raises:
        ResponseTooLargeError: The body is longer than ``limit`` bytes.
    """
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
        ResponseTooLargeError: The body is longer than ``limit`` bytes.
        ValueError: It isn't JSON.
    """
    return json.loads(await read_aiohttp(response, limit))
