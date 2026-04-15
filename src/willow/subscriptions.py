"""GraphQL subscriptions over WebSocket (``graphql-transport-ws``).

Python port of the TypeScript and Rust SDK subscription clients. Opens a
WebSocket to ``{api_url}/graphql/ws`` on the validator (default) or an
indexer (:attr:`SubscribeSource.INDEXER`), drives the
`graphql-transport-ws <https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md>`_
handshake, and exposes incoming ``next`` payloads as an async iterator.

See ``docs/QUERY_ROUTING.md`` for the validator-vs-indexer trust model.

Example
-------
.. code-block:: python

    from willow import SubscribeOptions, SubscribeSource, WillowClient

    async with WillowClient("http://validator:3031") as client:
        sub = await client.subscriptions.subscribe(
            "my-subgrove",
            "subscription { blockFinalized { height appHash } }",
        )
        async for payload in sub:
            print(payload)
        await sub.unsubscribe()

Or with explicit indexer source (for ``VerifyOnly`` subgroves)::

    sub = await client.subscriptions.subscribe(
        "verify-only-sg", "subscription { indexedDataStored { subgroveId } }",
        options=SubscribeOptions(source=SubscribeSource.INDEXER),
    )
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Dict, Optional

import websockets
from websockets.asyncio.client import ClientConnection

from .indexers import WillowIndexers


class SubscribeSource(str, Enum):
    """Which backend to open the subscription WebSocket against."""

    VALIDATOR = "validator"
    """``{api_url}/graphql/ws`` — consensus-verified chain-tip events.
    This is the default.
    """

    INDEXER = "indexer"
    """``{indexer.query_endpoint}/graphql/ws`` selected via discovery (or
    the explicit ``indexer_url`` override). Useful for ``VerifyOnly``
    subgroves where the validator has no tail data.
    """


@dataclass
class SubscribeOptions:
    """Optional subscription parameters."""

    variables: Optional[Dict[str, Any]] = None
    """GraphQL variables passed to the subscription."""

    operation_name: Optional[str] = None
    """GraphQL operation name (when the document has multiple)."""

    connection_payload: Optional[Dict[str, Any]] = None
    """Payload for the ``connection_init`` frame (e.g. auth tokens)."""

    source: SubscribeSource = SubscribeSource.VALIDATOR
    """Where to open the WebSocket. Defaults to :attr:`SubscribeSource.VALIDATOR`."""


@dataclass
class SubscriptionPayload:
    """A single payload pushed by the server over a ``next`` frame.

    Mirrors the ``graphql-transport-ws`` wire shape.
    """

    data: Optional[Dict[str, Any]] = None
    errors: Optional[Any] = None


class Subscription:
    """Async iterator over subscription payloads.

    Iterate with ``async for``; close with :meth:`unsubscribe` or by
    exiting the ``async with`` block. Safe to call ``unsubscribe`` more
    than once.
    """

    def __init__(
        self,
        ws: ClientConnection,
        sub_id: str,
        queue: asyncio.Queue,
        pump_task: asyncio.Task,
    ) -> None:
        self._ws = ws
        self._sub_id = sub_id
        self._queue: asyncio.Queue = queue
        self._pump_task = pump_task
        self._closed = False

    def __aiter__(self) -> AsyncIterator[SubscriptionPayload]:
        return self

    async def __anext__(self) -> SubscriptionPayload:
        payload = await self._queue.get()
        if payload is None:
            # Sentinel: pump_task finished.
            raise StopAsyncIteration
        return payload

    async def __aenter__(self) -> "Subscription":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.unsubscribe()

    async def unsubscribe(self) -> None:
        """Send ``complete`` to the server and close the socket.

        Subsequent ``async for`` iterations terminate immediately.
        """
        if self._closed:
            return
        self._closed = True
        # Best-effort: send `complete` then close. Any step may fail if
        # the socket is already torn down; in all such cases we still
        # want to cancel the pump task so the iterator terminates.
        try:
            await self._ws.send(
                json.dumps({"type": "complete", "id": self._sub_id})
            )
        except Exception:
            pass
        try:
            await self._ws.close()
        except Exception:
            pass
        if not self._pump_task.done():
            self._pump_task.cancel()
            try:
                await self._pump_task
            except (asyncio.CancelledError, Exception):
                pass


class WillowSubscriptions:
    """Subscription client wired to the same discovery layer as queries."""

    def __init__(self, api_url: str, indexers: WillowIndexers) -> None:
        self._api_url = api_url.rstrip("/")
        self._indexers = indexers
        self._counter = 0

    async def subscribe(
        self,
        subgrove_id: str,
        query: str,
        options: Optional[SubscribeOptions] = None,
    ) -> Subscription:
        """Open a subscription.

        Blocks until the ``connection_init`` → ``connection_ack`` →
        ``subscribe`` handshake completes, then returns a
        :class:`Subscription` that yields :class:`SubscriptionPayload`
        instances as the server streams them.

        For :attr:`SubscribeSource.INDEXER`, the discovery round-trip
        happens inside this call, so discovery errors surface here
        rather than through a later iteration.
        """
        opts = options or SubscribeOptions()
        ws_url = await self._resolve_ws_url(subgrove_id, opts.source)

        # Open the socket with the protocol negotiated.
        ws = await websockets.connect(ws_url, subprotocols=["graphql-transport-ws"])

        try:
            # connection_init
            await ws.send(
                json.dumps(
                    {
                        "type": "connection_init",
                        "payload": opts.connection_payload or {},
                    }
                )
            )

            # Wait for connection_ack. Tolerate ping/pong during handshake.
            while True:
                raw = await ws.recv()
                msg = json.loads(raw)
                msg_type = msg.get("type")
                if msg_type == "connection_ack":
                    break
                if msg_type == "ping":
                    await ws.send(json.dumps({"type": "pong"}))
                    continue
                if msg_type == "connection_error":
                    raise RuntimeError(f"Server refused connection: {msg.get('payload')}")
                # Ignore unknown pre-ack frames.

            # Subscribe
            self._counter += 1
            sub_id = f"sub-{self._counter}-{int(time.time() * 1e6)}"
            sub_payload: Dict[str, Any] = {"query": query}
            if opts.variables:
                sub_payload["variables"] = opts.variables
            if opts.operation_name:
                sub_payload["operationName"] = opts.operation_name
            await ws.send(
                json.dumps(
                    {
                        "type": "subscribe",
                        "id": sub_id,
                        "payload": sub_payload,
                    }
                )
            )
        except Exception:
            await ws.close()
            raise

        # Spawn the pump task that reads frames and pushes payloads into
        # a queue the caller iterates. A `None` sentinel signals end.
        queue: asyncio.Queue = asyncio.Queue()
        pump = asyncio.create_task(_pump(ws, sub_id, queue))
        return Subscription(ws=ws, sub_id=sub_id, queue=queue, pump_task=pump)

    async def _resolve_ws_url(
        self, subgrove_id: str, source: SubscribeSource
    ) -> str:
        if source == SubscribeSource.VALIDATOR:
            return _http_to_ws(self._api_url) + "/graphql/ws"

        # Indexer source: resolve via discovery (or explicit override).
        candidates = await self._indexers.for_subgrove(subgrove_id)
        if not candidates:
            raise RuntimeError(
                f'No indexer serves subgrove "{subgrove_id}" — cannot open '
                f"indexer subscription"
            )
        endpoint = candidates[0].effective_query_endpoint().rstrip("/")
        return _http_to_ws(endpoint) + "/graphql/ws"


async def _pump(
    ws: ClientConnection, sub_id: str, queue: asyncio.Queue
) -> None:
    """Read frames from the socket, fan out to the subscription queue.

    Ends when the server sends ``complete``/closes the socket, or the
    task is cancelled. In all cases a ``None`` sentinel is pushed so the
    iterator terminates cleanly.
    """
    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            msg_type = msg.get("type")
            if msg_type == "next":
                if msg.get("id") != sub_id:
                    continue
                payload = msg.get("payload") or {}
                await queue.put(
                    SubscriptionPayload(
                        data=payload.get("data"),
                        errors=payload.get("errors"),
                    )
                )
            elif msg_type == "complete":
                if msg.get("id") == sub_id:
                    break
            elif msg_type == "error":
                if msg.get("id") == sub_id:
                    # Deliver as a payload with `errors` set; callers
                    # inspect the field to distinguish.
                    await queue.put(
                        SubscriptionPayload(
                            data=None,
                            errors=msg.get("payload"),
                        )
                    )
            elif msg_type == "ping":
                try:
                    await ws.send(json.dumps({"type": "pong"}))
                except Exception:
                    break
            # Ignore unknown types (pong, etc.)
    except asyncio.CancelledError:
        pass
    except Exception:
        # Connection errors end the stream — deliver sentinel so the
        # caller's `async for` exits instead of hanging.
        pass
    finally:
        await queue.put(None)


def _http_to_ws(url: str) -> str:
    """Convert ``http(s)://host/path`` to ``ws(s)://host/path``."""
    if url.startswith("https://"):
        return "wss://" + url[len("https://"):]
    if url.startswith("http://"):
        return "ws://" + url[len("http://"):]
    return url
