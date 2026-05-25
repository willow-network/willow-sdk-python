"""GraphQL subscriptions over WebSocket (``graphql-transport-ws``).

Python port of the TypeScript and Rust SDK subscription clients. Opens a
WebSocket to ``{api_url}/graphql/ws`` on the validator (default) or an
indexer (:attr:`SubscribeSource.INDEXER`), drives the
`graphql-transport-ws <https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md>`_
handshake, and exposes incoming ``next`` payloads as an async iterator.

Reconnection: by default the subscription reconnects automatically on
unexpected disconnect with exponential backoff. For
:attr:`SubscribeSource.INDEXER`, reconnects pick the next-best indexer
via discovery (the failing indexer is evicted from the cache), so a dead
indexer won't keep the caller pinned to it. Set ``reconnect=False`` to
opt out.

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
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator, Callable, Dict, Optional, Tuple

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


OnReconnect = Callable[[int, float], Any]


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

    reconnect: bool = True
    """Automatically reconnect on unexpected disconnects.

    This is reconnect-only — messages that were in flight when the
    socket dropped are not replayed, and the new connection may
    redeliver events the old one already emitted. Callers that need
    exactly-once should dedupe by a stable field (e.g., block number
    or entity id) themselves.
    """

    max_reconnect_attempts: Optional[int] = None
    """Maximum consecutive reconnect attempts before giving up.

    ``None`` means retry forever. The counter resets only after a
    reconnection delivers at least one real payload — this avoids an
    infinite loop against a server that accepts the subscription but
    immediately drops the socket.
    """

    reconnect_backoff: float = 0.5
    """Initial reconnect delay, in seconds. Doubles on each consecutive
    failure up to :attr:`max_reconnect_backoff`."""

    max_reconnect_backoff: float = 30.0
    """Maximum reconnect delay, in seconds."""

    on_reconnect: Optional[OnReconnect] = None
    """Called when a reconnect attempt is scheduled. ``attempt`` is
    1-indexed; ``delay`` is in seconds. May be sync or async."""


@dataclass
class SubscriptionPayload:
    """A single payload pushed by the server over a ``next`` frame.

    Mirrors the ``graphql-transport-ws`` wire shape.
    """

    data: Optional[Dict[str, Any]] = None
    errors: Optional[Any] = None


class _PumpExitKind(str, Enum):
    SERVER_COMPLETE = "server_complete"
    DISCONNECTED = "disconnected"
    CANCELLED = "cancelled"


@dataclass
class _PumpExit:
    kind: _PumpExitKind
    delivered_payload: bool = False


class Subscription:
    """Async iterator over subscription payloads.

    Iterate with ``async for``; close with :meth:`unsubscribe` or by
    exiting the ``async with`` block. Safe to call ``unsubscribe`` more
    than once.

    Reconnects happen transparently in the background — the iterator
    simply pauses during the backoff and resumes when a new socket is
    up. Set ``reconnect=False`` on :class:`SubscribeOptions` for the
    classic "iteration ends on close" behavior.
    """

    def __init__(
        self,
        sub_id: str,
        queue: asyncio.Queue,
        pump_task: asyncio.Task,
        cancel_event: asyncio.Event,
    ) -> None:
        self._sub_id = sub_id
        self._queue: asyncio.Queue = queue
        self._pump_task = pump_task
        self._cancel_event = cancel_event
        self._closed = False

    def __aiter__(self) -> AsyncIterator[SubscriptionPayload]:
        return self

    async def __anext__(self) -> SubscriptionPayload:
        payload = await self._queue.get()
        if payload is None:
            # Sentinel: pump task finished.
            raise StopAsyncIteration
        return payload

    async def __aenter__(self) -> "Subscription":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.unsubscribe()

    async def unsubscribe(self) -> None:
        """End the subscription and close the underlying socket.

        Subsequent ``async for`` iterations terminate immediately. Safe
        to call more than once.
        """
        if self._closed:
            return
        self._closed = True
        # Signal every cancel-sensitive await inside the pump task.
        self._cancel_event.set()
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

        Blocks until the initial ``connection_init`` → ``connection_ack``
        → ``subscribe`` handshake completes on the first connection. The
        first attempt is eager-fail: discovery or handshake failures
        surface here rather than being retried silently. Once a socket
        is up, the returned :class:`Subscription` handles reconnection
        transparently (unless ``reconnect=False``).
        """
        opts = options or SubscribeOptions()

        # Allocate a stable sub_id — graphql-ws `id` is only meaningful
        # within a single socket, but reusing it on reconnect keeps
        # filtering consistent across pump invocations.
        self._counter += 1
        sub_id = f"sub-{self._counter}-{int(time.time() * 1e6)}"

        # Initial connect — eager-fail.
        ws, last_indexer_did = await _resolve_and_connect(
            subgrove_id=subgrove_id,
            query=query,
            sub_id=sub_id,
            opts=opts,
            api_url=self._api_url,
            indexers=self._indexers,
            skip_indexer_did=None,
        )

        queue: asyncio.Queue = asyncio.Queue()
        cancel_event = asyncio.Event()
        pump = asyncio.create_task(
            _subscription_loop(
                initial_ws=ws,
                initial_indexer_did=last_indexer_did,
                subgrove_id=subgrove_id,
                query=query,
                sub_id=sub_id,
                opts=opts,
                queue=queue,
                cancel_event=cancel_event,
                api_url=self._api_url,
                indexers=self._indexers,
            )
        )
        return Subscription(
            sub_id=sub_id, queue=queue, pump_task=pump, cancel_event=cancel_event
        )


async def _subscription_loop(
    initial_ws: ClientConnection,
    initial_indexer_did: Optional[str],
    subgrove_id: str,
    query: str,
    sub_id: str,
    opts: SubscribeOptions,
    queue: asyncio.Queue,
    cancel_event: asyncio.Event,
    api_url: str,
    indexers: WillowIndexers,
) -> None:
    """Pump → disconnect → backoff → reconnect, until done.

    Exits (pushing the ``None`` sentinel onto ``queue``) when:
      * the server sends ``complete`` for our ``sub_id``,
      * the caller unsubscribes,
      * ``reconnect=False`` and the socket dropped,
      * ``max_reconnect_attempts`` is exhausted.
    """
    ws: Optional[ClientConnection] = initial_ws
    last_indexer_did = initial_indexer_did
    attempts = 0
    try:
        while ws is not None:
            exit_info = await _pump(ws, sub_id, queue, cancel_event)
            try:
                await ws.close()
            except Exception:
                pass
            ws = None

            if exit_info.kind in (
                _PumpExitKind.SERVER_COMPLETE,
                _PumpExitKind.CANCELLED,
            ):
                return

            if not opts.reconnect:
                return

            # Reset the retry counter only when the just-ended connection
            # actually delivered data. A server that accepts the
            # subscription but immediately drops the socket without ever
            # forwarding a `next` frame would otherwise reset the counter
            # on every cycle and loop forever.
            if exit_info.delivered_payload:
                attempts = 0

            # Inner retry loop: backoff, then try to reconnect. Each
            # failed reconnect counts toward `max_reconnect_attempts`.
            while ws is None:
                if (
                    opts.max_reconnect_attempts is not None
                    and attempts >= opts.max_reconnect_attempts
                ):
                    return
                attempts += 1
                delay = min(
                    opts.reconnect_backoff * (2 ** (attempts - 1)),
                    opts.max_reconnect_backoff,
                )

                if opts.on_reconnect is not None:
                    try:
                        result = opts.on_reconnect(attempts, delay)
                        if asyncio.iscoroutine(result):
                            await result
                    except Exception:
                        # Callback errors must not kill the loop.
                        pass

                # Cancel-sensitive sleep: wake early if unsubscribe fires.
                try:
                    await asyncio.wait_for(cancel_event.wait(), timeout=delay)
                    return  # Cancelled during backoff.
                except asyncio.TimeoutError:
                    pass

                try:
                    ws, last_indexer_did = await _resolve_and_connect(
                        subgrove_id=subgrove_id,
                        query=query,
                        sub_id=sub_id,
                        opts=opts,
                        api_url=api_url,
                        indexers=indexers,
                        skip_indexer_did=last_indexer_did,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    ws = None
                    # Loop around for another backoff + retry.
                    continue
    except asyncio.CancelledError:
        pass
    finally:
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass
        # Terminate any waiting `async for` cleanly.
        try:
            queue.put_nowait(None)
        except Exception:
            pass


async def _resolve_and_connect(
    subgrove_id: str,
    query: str,
    sub_id: str,
    opts: SubscribeOptions,
    api_url: str,
    indexers: WillowIndexers,
    skip_indexer_did: Optional[str],
) -> Tuple[ClientConnection, Optional[str]]:
    """Pick an endpoint, open the socket, and drive the handshake.

    Returns ``(ws, indexer_did)`` — ``indexer_did`` is ``None`` for
    validator mode. On failure, closes any partially opened socket and
    re-raises. Evicts ``skip_indexer_did`` from the discovery cache
    first so indexer-mode reconnects pick a different candidate.
    """
    if opts.source == SubscribeSource.VALIDATOR:
        ws_url = _http_to_ws(api_url.rstrip("/")) + "/graphql/ws"
        ws = await _connect_and_handshake(ws_url, sub_id, query, opts)
        return ws, None

    # Indexer source. Evict the failed DID (if any) before re-resolving.
    if skip_indexer_did is not None:
        indexers.evict(skip_indexer_did)

    candidates = await indexers.for_subgrove(subgrove_id)
    if not candidates:
        raise RuntimeError(
            f'No indexer serves subgrove "{subgrove_id}" — cannot open '
            f"indexer subscription"
        )
    chosen = candidates[0]
    endpoint = chosen.effective_query_endpoint().rstrip("/")
    ws_url = _http_to_ws(endpoint) + "/graphql/ws"
    ws = await _connect_and_handshake(ws_url, sub_id, query, opts)
    return ws, chosen.indexer_did


async def _connect_and_handshake(
    ws_url: str, sub_id: str, query: str, opts: SubscribeOptions
) -> ClientConnection:
    """Open a socket and complete the graphql-transport-ws handshake.

    On any failure, closes the socket before propagating.
    """
    ws = await websockets.connect(
        ws_url, subprotocols=["graphql-transport-ws"]
    )
    try:
        await ws.send(
            json.dumps(
                {
                    "type": "connection_init",
                    "payload": opts.connection_payload or {},
                }
            )
        )

        # Wait for connection_ack. Tolerate server-originated ping during
        # handshake; reject a connection_error frame loudly.
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
                raise RuntimeError(
                    f"Server refused connection: {msg.get('payload')}"
                )
            # Ignore unknown pre-ack frames.

        sub_payload: Dict[str, Any] = {"query": query}
        if opts.variables:
            sub_payload["variables"] = opts.variables
        if opts.operation_name:
            sub_payload["operationName"] = opts.operation_name
        await ws.send(
            json.dumps(
                {"type": "subscribe", "id": sub_id, "payload": sub_payload}
            )
        )
        return ws
    except Exception:
        try:
            await ws.close()
        except Exception:
            pass
        raise


async def _pump(
    ws: ClientConnection,
    sub_id: str,
    queue: asyncio.Queue,
    cancel_event: asyncio.Event,
) -> _PumpExit:
    """Forward frames to ``queue`` until the socket ends or we're cancelled.

    Returns a :class:`_PumpExit` describing how it ended. The
    ``delivered_payload`` field is ``True`` iff at least one real
    ``next`` frame was forwarded before exit — the outer loop uses this
    to decide whether to reset the backoff counter.
    """
    delivered_payload = False
    cancel_task = asyncio.create_task(cancel_event.wait())

    try:
        while True:
            recv_task = asyncio.create_task(ws.recv())
            done, _ = await asyncio.wait(
                {recv_task, cancel_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancel_task in done:
                recv_task.cancel()
                return _PumpExit(
                    kind=_PumpExitKind.CANCELLED,
                    delivered_payload=delivered_payload,
                )

            try:
                raw = recv_task.result()
            except websockets.ConnectionClosed:
                return _PumpExit(
                    kind=_PumpExitKind.DISCONNECTED,
                    delivered_payload=delivered_payload,
                )
            except Exception:
                return _PumpExit(
                    kind=_PumpExitKind.DISCONNECTED,
                    delivered_payload=delivered_payload,
                )

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
                delivered_payload = True
            elif msg_type == "complete":
                if msg.get("id") == sub_id:
                    return _PumpExit(
                        kind=_PumpExitKind.SERVER_COMPLETE,
                        delivered_payload=delivered_payload,
                    )
            elif msg_type == "error":
                if msg.get("id") == sub_id:
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
                    return _PumpExit(
                        kind=_PumpExitKind.DISCONNECTED,
                        delivered_payload=delivered_payload,
                    )
            # Unknown types (pong, etc.) — ignore.
    except asyncio.CancelledError:
        return _PumpExit(
            kind=_PumpExitKind.CANCELLED,
            delivered_payload=delivered_payload,
        )
    finally:
        if not cancel_task.done():
            cancel_task.cancel()


def _http_to_ws(url: str) -> str:
    """Convert ``http(s)://host/path`` to ``ws(s)://host/path``."""
    if url.startswith("https://"):
        return "wss://" + url[len("https://") :]
    if url.startswith("http://"):
        return "ws://" + url[len("http://") :]
    return url
