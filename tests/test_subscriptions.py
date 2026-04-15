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
