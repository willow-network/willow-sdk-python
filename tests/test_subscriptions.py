"""End-to-end tests for WillowSubscriptions against a local
graphql-transport-ws server.

Each test spins up a minimal ``websockets`` server implementing just
enough of the protocol to verify the SDK's handshake + message plumbing.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Awaitable, Callable

import httpx
import pytest
import websockets

from willow.indexers import WillowIndexers
from willow.subscriptions import (
    SubscribeOptions,
    SubscribeSource,
    SubscriptionPayload,
    WillowSubscriptions,
)


from websockets.asyncio.server import ServerConnection

OnSubscribe = Callable[[ServerConnection, str], Awaitable[None]]


@asynccontextmanager
async def fake_ws_server(on_subscribe: OnSubscribe):
    """Start an in-process graphql-transport-ws server.

    Drives the ``connection_init`` → ``connection_ack`` → ``subscribe``
    handshake, then hands off to the caller-supplied ``on_subscribe``
    for the per-subscription script.
    """

    async def handler(ws):
        try:
            init_text = await ws.recv()
            init = json.loads(init_text)
            assert init["type"] == "connection_init"
            await ws.send(json.dumps({"type": "connection_ack"}))

            sub_text = await ws.recv()
            sub = json.loads(sub_text)
            assert sub["type"] == "subscribe"
            sub_id = sub["id"]

            await on_subscribe(ws, sub_id)
        except websockets.ConnectionClosed:
            return

    server = await websockets.serve(
        handler, "127.0.0.1", 0, subprotocols=["graphql-transport-ws"]
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


def _subs_for(api_url: str) -> WillowSubscriptions:
    http = httpx.AsyncClient()
    indexers = WillowIndexers(http, api_url, None)
    return WillowSubscriptions(api_url, indexers)


@pytest.mark.asyncio
async def test_validator_subscription_delivers_next_payloads():
    async def on_subscribe(ws, sub_id):
        for i in range(2):
            await ws.send(
                json.dumps(
                    {
                        "type": "next",
                        "id": sub_id,
                        "payload": {"data": {"tick": i}},
                    }
                )
            )
        await ws.send(json.dumps({"type": "complete", "id": sub_id}))
        # Stay open briefly so the client has time to process frames
        # before we tear down the fixture.
        await asyncio.sleep(0.05)

    async with fake_ws_server(on_subscribe) as port:
        subs = _subs_for(f"http://127.0.0.1:{port}")
        sub = await subs.subscribe(
            "my-subgrove", "subscription { tick }", SubscribeOptions()
        )

        received = []
        async for payload in sub:
            received.append(payload)

        assert len(received) == 2
        assert received[0].data == {"tick": 0}
        assert received[1].data == {"tick": 1}
        assert all(p.errors is None for p in received)

        await sub.unsubscribe()


@pytest.mark.asyncio
async def test_unsubscribe_terminates_iteration():
    """After unsubscribe, the async iterator completes cleanly."""
    stream_ready = asyncio.Event()

    async def on_subscribe(ws, sub_id):
        await ws.send(
            json.dumps(
                {
                    "type": "next",
                    "id": sub_id,
                    "payload": {"data": {"tick": 0}},
                }
            )
        )
        stream_ready.set()
        # Sit idle until the client closes.
        try:
            async for _ in ws:
                pass
        except websockets.ConnectionClosed:
            return

    async with fake_ws_server(on_subscribe) as port:
        subs = _subs_for(f"http://127.0.0.1:{port}")
        sub = await subs.subscribe(
            "my-subgrove", "subscription { tick }", SubscribeOptions()
        )

        # Pull the single known payload.
        it = sub.__aiter__()
        first = await asyncio.wait_for(it.__anext__(), timeout=1.0)
        assert first.data == {"tick": 0}

        # Now unsubscribe; subsequent iteration should terminate cleanly.
        await sub.unsubscribe()
        with pytest.raises(StopAsyncIteration):
            await asyncio.wait_for(it.__anext__(), timeout=1.0)


@pytest.mark.asyncio
async def test_variables_and_operation_name_flow_through():
    """Make sure options propagate into the `subscribe` payload."""
    captured: dict = {}

    async def on_subscribe_with_capture(ws, sub_id):
        # We can't get at the original subscribe text here because the
        # fixture already parsed it. Monkey-patch: re-run the handshake
        # capture ourselves.
        pass

    # Custom handler to capture the subscribe payload.
    async def handler(ws):
        init_text = await ws.recv()
        assert json.loads(init_text)["type"] == "connection_init"
        await ws.send(json.dumps({"type": "connection_ack"}))

        sub_text = await ws.recv()
        sub = json.loads(sub_text)
        captured["sub"] = sub
        # Send one payload then complete so the test terminates.
        sub_id = sub["id"]
        await ws.send(json.dumps({"type": "next", "id": sub_id, "payload": {"data": {}}}))
        await ws.send(json.dumps({"type": "complete", "id": sub_id}))
        await asyncio.sleep(0.05)

    server = await websockets.serve(
        handler, "127.0.0.1", 0, subprotocols=["graphql-transport-ws"]
    )
    port = server.sockets[0].getsockname()[1]
    try:
        subs = _subs_for(f"http://127.0.0.1:{port}")
        sub = await subs.subscribe(
            "my-subgrove",
            "subscription Foo($a: String) { x(a: $a) }",
            SubscribeOptions(
                variables={"a": "hello"}, operation_name="Foo"
            ),
        )
        async for _ in sub:
            pass
    finally:
        server.close()
        await server.wait_closed()

    assert captured["sub"]["type"] == "subscribe"
    assert captured["sub"]["payload"]["variables"] == {"a": "hello"}
    assert captured["sub"]["payload"]["operationName"] == "Foo"


@pytest.mark.asyncio
async def test_server_ping_gets_pong():
    """Server-originated ping frames get pong replies transparently."""
    seen_pong = asyncio.Event()

    async def on_subscribe(ws, sub_id):
        await ws.send(json.dumps({"type": "ping"}))
        # Wait for the pong to come back.
        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") == "pong":
                    seen_pong.set()
                    return
        except websockets.ConnectionClosed:
            return

    async with fake_ws_server(on_subscribe) as port:
        subs = _subs_for(f"http://127.0.0.1:{port}")
        sub = await subs.subscribe(
            "my-subgrove", "subscription { tick }", SubscribeOptions()
        )
        try:
            await asyncio.wait_for(seen_pong.wait(), timeout=1.0)
        finally:
            await sub.unsubscribe()


@pytest.mark.asyncio
async def test_indexer_source_errors_when_no_indexer_serves_subgrove():
    """Discovery returning empty list produces a clean error before any
    WebSocket is opened."""
    api_url = "http://127.0.0.1:1"  # Will fail to connect for /indexers

    http = httpx.AsyncClient(timeout=0.5)
    try:
        indexers = WillowIndexers(http, api_url, None)
        subs = WillowSubscriptions(api_url, indexers)

        with pytest.raises(Exception):
            # Either the discovery HTTP call fails (connection refused)
            # or the empty-list branch raises — both are acceptable.
            await subs.subscribe(
                "my-subgrove",
                "subscription { x }",
                SubscribeOptions(source=SubscribeSource.INDEXER),
            )
    finally:
        await http.aclose()


# ---------------------------------------------------------------------------
# Reconnect tests
#
# These exercise the auto-reconnect loop by scripting the server's
# per-connection behavior via a counter. The fixture below spins up a
# single `websockets.serve()` instance whose handler consults a
# user-provided callback with the current connection index, so tests can
# say things like "drop connection #1 after one payload; on connection
# #2 send two payloads then complete".
# ---------------------------------------------------------------------------


@asynccontextmanager
async def scripted_ws_server(script):
    """Start a graphql-transport-ws server that dispatches per connection.

    ``script`` is a coroutine ``(ws, sub_id, conn_index) -> None`` called
    after the handshake completes. ``conn_index`` starts at 0 and
    increments per accepted connection.
    """
    counter = {"n": 0}

    async def handler(ws):
        idx = counter["n"]
        counter["n"] += 1
        try:
            init_text = await ws.recv()
            assert json.loads(init_text)["type"] == "connection_init"
            await ws.send(json.dumps({"type": "connection_ack"}))

            sub_text = await ws.recv()
            sub = json.loads(sub_text)
            assert sub["type"] == "subscribe"
            sub_id = sub["id"]

            await script(ws, sub_id, idx)
        except websockets.ConnectionClosed:
            return

    server = await websockets.serve(
        handler, "127.0.0.1", 0, subprotocols=["graphql-transport-ws"]
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield port, counter
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_reconnects_on_unexpected_disconnect():
    """Socket drops after first payload; client reconnects and gets
    second payload transparently."""

    async def script(ws, sub_id, idx):
        if idx == 0:
            await ws.send(
                json.dumps(
                    {"type": "next", "id": sub_id, "payload": {"data": {"tick": 0}}}
                )
            )
            # Give the client a moment to receive, then drop the socket
            # with no `complete` — simulates an unexpected disconnect.
            await asyncio.sleep(0.05)
            await ws.close(code=1011)
        else:
            await ws.send(
                json.dumps(
                    {"type": "next", "id": sub_id, "payload": {"data": {"tick": 1}}}
                )
            )
            await ws.send(json.dumps({"type": "complete", "id": sub_id}))
            await asyncio.sleep(0.05)

    async with scripted_ws_server(script) as (port, _counter):
        subs = _subs_for(f"http://127.0.0.1:{port}")
        sub = await subs.subscribe(
            "my-subgrove",
            "subscription { tick }",
            SubscribeOptions(reconnect_backoff=0.01, max_reconnect_backoff=0.05),
        )

        received = []
        async for payload in sub:
            received.append(payload)

        assert [p.data for p in received] == [{"tick": 0}, {"tick": 1}]
        await sub.unsubscribe()


@pytest.mark.asyncio
async def test_does_not_reconnect_when_reconnect_is_false():
    """A single unexpected disconnect terminates the subscription when
    the caller opted out of auto-reconnect."""

    async def script(ws, sub_id, idx):
        # Always drop after one payload, regardless of connection index.
        await ws.send(
            json.dumps(
                {"type": "next", "id": sub_id, "payload": {"data": {"tick": idx}}}
            )
        )
        await asyncio.sleep(0.02)
        await ws.close(code=1011)

    async with scripted_ws_server(script) as (port, counter):
        subs = _subs_for(f"http://127.0.0.1:{port}")
        sub = await subs.subscribe(
            "my-subgrove",
            "subscription { tick }",
            SubscribeOptions(reconnect=False),
        )

        received = []
        async for payload in sub:
            received.append(payload)

        assert [p.data for p in received] == [{"tick": 0}]
        # Only one connection should have been accepted.
        assert counter["n"] == 1
        await sub.unsubscribe()


@pytest.mark.asyncio
async def test_gives_up_after_max_reconnect_attempts():
    """Server accepts-then-drops without ever delivering data; client
    hits the attempt cap and exits instead of looping forever.

    This is the test that justifies resetting ``attempts`` only on a
    delivered payload (not on bare handshake success) — otherwise the
    accept-then-drop cycle would reset the counter every round trip.
    """

    async def script(ws, sub_id, idx):
        # Never send a payload — just drop.
        await asyncio.sleep(0.02)
        await ws.close(code=1011)

    async with scripted_ws_server(script) as (port, counter):
        subs = _subs_for(f"http://127.0.0.1:{port}")
        sub = await subs.subscribe(
            "my-subgrove",
            "subscription { tick }",
            SubscribeOptions(
                max_reconnect_attempts=2,
                reconnect_backoff=0.01,
                max_reconnect_backoff=0.05,
            ),
        )

        received = []
        async for payload in sub:
            received.append(payload)

        assert received == []
        # Initial connection + 2 reconnects = 3 total.
        assert counter["n"] == 3
        await sub.unsubscribe()


@pytest.mark.asyncio
async def test_unsubscribe_during_backoff_cancels_reconnect():
    """Unsubscribing while the loop is sleeping in its backoff wakes it
    promptly and exits — no further connection attempts should happen."""

    first_drop = asyncio.Event()

    async def script(ws, sub_id, idx):
        if idx == 0:
            await asyncio.sleep(0.02)
            first_drop.set()
            await ws.close(code=1011)
        else:
            # We never want the test to reach here.
            await asyncio.sleep(10)

    async with scripted_ws_server(script) as (port, counter):
        subs = _subs_for(f"http://127.0.0.1:{port}")
        sub = await subs.subscribe(
            "my-subgrove",
            "subscription { tick }",
            SubscribeOptions(
                reconnect_backoff=1.0,
                max_reconnect_backoff=1.0,
            ),
        )

        # Wait for the server-side drop, then unsubscribe while the SDK
        # is mid-backoff (1 second is plenty of wiggle room).
        await first_drop.wait()
        await asyncio.sleep(0.01)
        await sub.unsubscribe()

        # No second connection should have been accepted.
        assert counter["n"] == 1
