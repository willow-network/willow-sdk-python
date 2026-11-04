"""Nonces handed out per signing DID.

The node accepts a nonce in base+1 … base+24 that is not used and not held by
another pending transaction; the base advances only over used nonces with no
gap. ``FakeNode`` applies those rules to the transactions the client sends, so
each test shows what CheckTx would answer."""

import asyncio
import base64
import json

import httpx
import pytest

import aiohttp

from willow import (
    NonceWindowFullError,
    NotLandedError,
    WillowClient,
    generate_did,
    register_did_message,
    store_data_message,
    verify_signature,
)
from willow.consensus import ConsensusClient, ConsensusConfig, ConsensusError
from willow.errors import NetworkError, TransactionError, WillowError
from willow.nonces import (
    FREE,
    HELD,
    LEASE_SECONDS,
    UNKNOWN,
    USED,
    WINDOW,
    NonceTracker,
    already_in_cache,
    parse_nonce_state,
    refusal_outcome,
)


# ---------------------------------------------------------------------------
# The tracker.
# ---------------------------------------------------------------------------


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_hands_out_the_lowest_free_nonce_once():
    tracker = NonceTracker()
    assert [tracker.take("did:a", 6) for _ in range(3)] == [7, 8, 9]
    assert tracker.take("did:b", 0) == 1  # per DID


def test_a_nonce_given_back_is_handed_out_again_first():
    tracker = NonceTracker()
    first, second = tracker.take("did:a", 0), tracker.take("did:a", 0)
    tracker.settle("did:a", first, FREE)
    assert tracker.take("did:a", 0) == first
    assert tracker.take("did:a", 0) == second + 1


@pytest.mark.parametrize("outcome", [HELD, UNKNOWN])
def test_a_held_or_unknown_nonce_stays_taken(outcome):
    tracker = NonceTracker()
    nonce = tracker.take("did:a", 0)
    tracker.settle("did:a", nonce, outcome)
    assert tracker.take("did:a", 0) == nonce + 1


def test_a_used_nonce_is_never_handed_out_again():
    clock = _Clock()
    tracker = NonceTracker(clock)
    nonce = tracker.take("did:a", 0)
    tracker.settle("did:a", nonce, USED)
    clock.now += LEASE_SECONDS * 10
    assert tracker.take("did:a", 0) == nonce + 1


def test_a_nonce_handed_out_past_its_lease_is_free_again():
    clock = _Clock()
    tracker = NonceTracker(clock)
    nonce = tracker.take("did:a", 0)
    clock.now += LEASE_SECONDS - 1
    assert tracker.take("did:a", 0) == nonce + 1
    clock.now += 1
    assert tracker.take("did:a", 0) == nonce


def test_never_hands_out_past_the_window():
    tracker = NonceTracker()
    assert [tracker.take("did:a", 10) for _ in range(WINDOW)] == list(range(11, 11 + WINDOW))
    assert tracker.take("did:a", 10) is None
    # The base advanced over three: three more are free.
    assert [tracker.take("did:a", 13) for _ in range(4)] == [35, 36, 37, None]


def test_a_lower_base_read_later_does_not_hand_out_a_used_nonce():
    tracker = NonceTracker()
    assert tracker.take("did:a", 10) == 11
    assert tracker.take("did:a", 4) == 12
    assert tracker.observe("did:a", 4) == 10


def test_register_did_holds_nonce_one():
    tracker = NonceTracker()
    tracker.hold("did:a", 1)
    assert tracker.take("did:a", 0) == 2


def _checktx(log, code=1):
    return TransactionError(log, error_code=code, raw_log=log)


def _mismatch(message):
    # The node's signature-mismatch refusal quotes the whole expected message.
    return _checktx(
        "Signature mismatch: the signature does not match the expected signing message. "
        f'Expected message to sign: "{message}"'
    )


@pytest.mark.parametrize("error,status,nonce,outcome", [
    (_checktx("Nonce 7 of did:willow:a is held by a pending transaction; sign this one with another nonce"), 200, 7, HELD),
    (_checktx("Invalid nonce: 7 already used (replay)"), 200, 7, USED),
    (_checktx("Invalid nonce: 7 <= base nonce 9"), 200, 7, USED),
    (_checktx("Data not found (nonce 7 spent)"), 200, 7, USED),
    (_checktx("Invalid nonce: 40 is too far ahead (base=7, max=31)"), 200, 40, FREE),
    (_checktx("Signature mismatch: the signature does not match the expected signing message."), 200, 7, FREE),
    (_checktx("Insufficient balance"), 200, 7, FREE),
    # Another nonce's refusal says nothing about this one.
    (_checktx("Invalid nonce: 8 already used (replay)"), 200, 7, FREE),
    (_checktx("Nonce 70 of did:willow:a is held by a pending transaction; sign this one with another nonce"), 200, 7, FREE),
    # User data a refusal quotes says nothing either.
    (_mismatch("StoreData\nSubgrove: sg\nKey: Invalid nonce: 7 already used\nOwner: did:willow:a\nDataHash: 00\nNonce: 7"), 200, 7, FREE),
    (_mismatch("StoreData\nSubgrove: sg\nKey: x <= base nonce\nOwner: did:willow:a\nDataHash: 00\nNonce: 7"), 200, 7, FREE),
    (_mismatch("StoreData\nSubgrove: Nonce 7 of did:willow:a is held by a pending transaction\nKey: k\nNonce: 7"), 200, 7, FREE),
    (_mismatch("StoreData\nSubgrove: sg\nKey: (nonce 7 spent)\nNonce: 7"), 200, 7, FREE),
    (_checktx("Subgrove not found: sg (nonce 7 spent) for x"), 200, 7, FREE),
    (TransactionError("Failed to deserialize the JSON body"), 422, 7, FREE),
    (TransactionError("Failed to reach CometBFT RPC: timed out"), 502, 7, UNKNOWN),
    (NetworkError("Network error: reset"), None, 7, UNKNOWN),
])
def test_what_a_refusal_leaves_its_nonce_as(error, status, nonce, outcome):
    assert refusal_outcome(error, status, nonce) == outcome


def test_a_refusal_matches_any_nonce_when_none_is_given():
    assert refusal_outcome(_checktx("Invalid nonce: 8 already used (replay)")) == USED
    assert refusal_outcome(_mismatch("Key: Invalid nonce: 8 already used")) == FREE


def test_the_mempool_cache_answer_is_recognized():
    assert already_in_cache("CometBFT RPC error -32603: Internal error tx already exists in cache")
    assert not already_in_cache("CometBFT RPC error -32603: Internal error mempool is full")
    assert not already_in_cache(None)


def test_the_nonce_state_reads_the_base_and_the_used_bitmap():
    assert parse_nonce_state(b"") == (0, frozenset())
    assert parse_nonce_state((7).to_bytes(8, "big")) == (7, frozenset())
    # Bit i % 8 of byte i / 8 is base + 1 + i.
    state = (7).to_bytes(8, "big") + bytes([0b0000_0101, 0, 0b1000_0000])
    assert parse_nonce_state(state) == (7, frozenset({8, 10, 31}))
    with pytest.raises(ValueError):
        parse_nonce_state(b"\x00" * 9)


def test_take_skips_the_nonces_the_node_reports_used():
    tracker = NonceTracker()
    assert tracker.take("did:a", 4, {5, 6, 8}) == 7
    assert tracker.take("did:a", 4) == 9
    assert tracker.is_used("did:a", 8) and not tracker.is_used("did:a", 7)


def test_reclaim_refuses_a_nonce_handed_to_another_transaction():
    clock = _Clock()
    tracker = NonceTracker(clock)
    nonce = tracker.take("did:a", 0)
    first = tracker.handed_at("did:a", nonce)
    assert tracker.reclaim("did:a", nonce, first)  # still its own lease
    renewed = tracker.handed_at("did:a", nonce)
    clock.now += LEASE_SECONDS
    assert tracker.take("did:a", 0) == nonce  # the lease ran out: handed to another
    assert not tracker.reclaim("did:a", nonce, renewed)
    clock.now += LEASE_SECONDS
    assert tracker.reclaim("did:a", nonce, renewed)  # nobody holds it now
    assert tracker.take("did:a", 0) == nonce + 1


# ---------------------------------------------------------------------------
# WillowClient flows against the node's nonce rules.
# ---------------------------------------------------------------------------


def _ok(data):
    return httpx.Response(200, json={"success": True, "data": data, "error": None})


class FakeNode:
    """One account's nonce state as CheckTx and the nonce route see it."""

    def __init__(self, did, base=0, used=()):
        self.did = did
        self.base = base
        self.used = set(used)  # used above the base
        self.pending = {}  # nonce -> signature
        self.sent = []  # (kind, body) of each submission
        self.nonce_reads = 0
        self.refusals = []  # logs for the next submissions, in order (None admits)
        self.on_nonce_read = None
        self.cache = set()  # the exact bytes of each transaction CheckTx admitted

    _IN_CACHE = "CometBFT RPC error -32603: Internal error tx already exists in cache"

    def handler(self, request):
        if request.url.path.endswith("/nonce"):
            self.nonce_reads += 1
            if self.on_nonce_read is not None:
                self.on_nonce_read(self)
            return _ok({"did": self.did, "nonce": self.base})
        assert request.url.path == "/tx/submit"
        ((kind, body),) = json.loads(request.content).items()
        self.sent.append((kind, body))
        if request.content in self.cache:
            return httpx.Response(502, json={"success": False, "data": None, "error": self._IN_CACHE})
        log = self.refusals.pop(0) if self.refusals else None
        log = log or self._check(body)
        if log:
            return _ok({"tx_hash": "", "code": 1, "log": log})
        self.pending[body["nonce"]] = bytes(body["signature"])
        self.cache.add(request.content)
        return _ok({"tx_hash": f"T{len(self.sent)}", "code": 0, "log": ""})

    def nonce_state(self):
        """The ABCI query ``/store/account_nonce_state/{did}``'s value."""
        bitmap = sum(1 << (n - self.base - 1) for n in self.used)
        return self.base.to_bytes(8, "big") + bitmap.to_bytes(3, "little")

    def _check(self, body):
        n = body["nonce"]
        if n <= self.base:
            return f"Invalid nonce: {n} <= base nonce {self.base}"
        if n > self.base + WINDOW:
            return f"Invalid nonce: {n} is too far ahead (base={self.base}, max={self.base + WINDOW})"
        if n in self.used:
            return f"Invalid nonce: {n} already used (replay)"
        if n in self.pending and self.pending[n] != bytes(body["signature"]):
            return (
                f"Nonce {n} of {self.did} is held by a pending transaction; "
                "sign this one with another nonce"
            )
        return None

    def land(self):
        """Every pending transaction lands in a block."""
        self.used |= set(self.pending)
        self.pending.clear()
        while self.base + 1 in self.used:
            self.base += 1
            self.used.discard(self.base)

    def nonces_sent(self):
        return [body["nonce"] for _, body in self.sent]


def _client(node=None, base=0, used=()):
    info = generate_did()
    node = node or FakeNode(info["did"], base, used)
    node.did = info["did"]
    client = WillowClient("http://api.test")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(node.handler))
    client.set_identity(info["did"], info["private_key"], info["public_key_id"])
    client._nonce_poll_interval = 0
    return client, node, info


@pytest.mark.asyncio
async def test_writes_sent_before_earlier_ones_land_take_their_own_nonces():
    # The README's data example: store, then store_item, then batch_store,
    # each before the ones before it land.
    client, node, info = _client(base=4)
    await client.data.store("sg", {"a": {"n": 1}, "b": {"n": 2}})
    await client.data.store_item("sg", "c", {"n": 3})
    await client.data.batch_store("sg", [{"key": "d", "value": {"n": 4}}])
    assert node.nonces_sent() == [5, 6, 7, 8]
    assert len(node.pending) == 4  # CheckTx admitted every one
    for _, body in node.sent:
        message = store_data_message(
            body["subgrove_id"], body["key"], body["owner_did"], bytes(body["data"]), body["nonce"]
        )
        assert verify_signature(message, bytes(body["signature"]).hex(), info["public_key"], "Ed25519")
    await client.close()


@pytest.mark.asyncio
async def test_concurrent_writes_take_distinct_nonces():
    client, node, _ = _client()
    await asyncio.gather(*(client.data.store_item("sg", f"k{i}", {"i": i}) for i in range(10)))
    assert sorted(node.nonces_sent()) == list(range(1, 11))
    assert len(node.pending) == 10
    await client.close()


@pytest.mark.asyncio
async def test_a_batch_past_the_window_waits_for_earlier_writes_to_land():
    client, node, _ = _client()

    def land_when_full(n):
        if len(n.pending) == WINDOW:
            n.land()

    node.on_nonce_read = land_when_full
    results = await client.data.store("sg", {f"k{i}": {"i": i} for i in range(30)})
    assert node.nonces_sent() == list(range(1, 31))
    assert [r["nonce"] for r in results] == list(range(1, 31))
    assert all(code == 0 for code in (r["code"] for r in results))
    await client.close()


@pytest.mark.asyncio
async def test_a_full_window_that_never_advances_says_which_keys_went_through():
    client, node, _ = _client()
    client._nonce_wait_timeout = 0
    with pytest.raises(NonceWindowFullError) as exc_info:
        await client.data.store("sg", {f"k{i}": {"i": i} for i in range(30)})
    assert node.nonces_sent() == list(range(1, WINDOW + 1))  # nothing past the window
    assert [r["nonce"] for r in exc_info.value.submitted] == list(range(1, WINDOW + 1))
    assert exc_info.value.failed_key == f"k{WINDOW}"
    await client.close()


@pytest.mark.asyncio
async def test_a_refused_write_says_which_keys_went_through_and_frees_its_nonce():
    client, node, _ = _client()
    node.refusals = [None, "Insufficient balance for the write fee"]
    with pytest.raises(TransactionError) as exc_info:
        await client.data.store("sg", {"a": {}, "b": {}, "c": {}})
    assert exc_info.value.failed_key == "b"
    assert [r["nonce"] for r in exc_info.value.submitted] == [1]
    assert node.nonces_sent() == [1, 2]  # "c" was not sent
    # The refused write's nonce leaves no gap: the next write takes it.
    await client.data.store_item("sg", "b", {})
    assert node.nonces_sent() == [1, 2, 2]
    await client.close()


@pytest.mark.asyncio
async def test_a_nonce_used_out_of_order_is_signed_again_under_a_fresh_one():
    # Nonce 1 landed out of order (sent by an earlier run); the base is still 0.
    client, node, info = _client(base=0, used={1, 3})
    result = await client.data.store_item("sg", "k", {"v": 1})
    assert node.nonces_sent() == [1, 2]
    assert result["nonce"] == 2
    _, body = node.sent[-1]
    message = store_data_message("sg", "k", info["did"], bytes(body["data"]), 2)
    assert verify_signature(message, bytes(body["signature"]).hex(), info["public_key"], "Ed25519")
    # Nonce 3 is used too: learned when refused, then skipped.
    await client.data.store_item("sg", "k2", {"v": 2})
    await client.data.store_item("sg", "k3", {"v": 3})
    assert node.nonces_sent() == [1, 2, 3, 4, 5]
    await client.close()


@pytest.mark.asyncio
async def test_a_nonce_held_by_a_pending_transaction_is_not_retried_or_reused():
    client, node, _ = _client()
    node.refusals = [f"Nonce 1 of {node.did} is held by a pending transaction; sign this one with another nonce"]
    with pytest.raises(TransactionError, match="held by a pending transaction"):
        await client.data.store_item("sg", "a", {})
    await client.data.store_item("sg", "b", {})
    assert node.nonces_sent() == [1, 2]
    await client.close()


@pytest.mark.asyncio
async def test_register_did_holds_nonce_one_and_wait_until_landed_waits_for_it():
    client, node, info = _client()
    registration = await client.register_did(info["did_document"])
    assert (registration["did"], registration["nonce"]) == (info["did"], 1)
    reads = node.nonce_reads

    def land_on_second_read(n):
        if n.nonce_reads == reads + 2:
            n.land()

    node.on_nonce_read = land_on_second_read
    await client.wait_until_landed(registration, poll_interval=0)
    assert node.base == 1
    write = await client.data.store_item("sg", "k", {})
    assert write["nonce"] == 2
    await client.close()


@pytest.mark.asyncio
async def test_a_write_right_after_register_did_does_not_take_nonce_one():
    client, node, info = _client()
    await client.register_did(info["did_document"])
    await client.data.store_item("sg", "k", {})
    assert node.nonces_sent() == [1, 2]
    await client.close()


@pytest.mark.asyncio
async def test_wait_until_landed_takes_a_batch_and_times_out():
    client, node, _ = _client()
    results = await client.data.store("sg", {"a": {}, "b": {}})
    with pytest.raises(NotLandedError, match="nonce 1, 2 of"):
        await client.wait_until_landed(results, timeout=0)
    node.land()
    await client.wait_until_landed(results, timeout=0)
    with pytest.raises(ValueError):
        await client.wait_until_landed({"tx_hash": "AB"})
    await client.close()


def _flaky(client, node, failures):
    """Fail the next submissions as ``failures`` says: an exception raised
    before the node sees the request, or ``("after", exc)`` to raise once the
    node has answered it (the answer lost in transit)."""
    real = node.handler

    def handler(request):
        if request.url.path == "/tx/submit" and failures:
            failure = failures.pop(0)
            if isinstance(failure, tuple):
                real(request)
                raise failure[1]
            raise failure
        return real(request)

    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [httpx.ConnectError("refused"), httpx.ConnectTimeout("timed out")])
async def test_a_write_that_never_left_gives_its_nonce_back(failure):
    # The account's base is 1; the connection fails before anything is sent.
    client, node, _ = _client(base=1)
    _flaky(client, node, [failure])
    with pytest.raises(NetworkError) as exc_info:
        await client.data.store("sg", {"a": {}})
    error = exc_info.value
    assert error.submitted == [] and error.failed_key == "a"
    assert (error.did, error.nonce, error.transaction) == (node.did, 2, None)
    with pytest.raises(ValueError):
        await client.resubmit(error)
    # Sent again as a write, it takes the same nonce: no gap is left.
    result = await client.data.store_item("sg", "a", {})
    assert result["nonce"] == 2
    node.land()
    await client.wait_until_landed(result, timeout=0)
    assert node.base == 2
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [httpx.ReadTimeout("timed out"), httpx.RemoteProtocolError("disconnected")])
async def test_a_write_that_may_have_reached_the_node_is_resubmitted_under_its_nonce(failure):
    client, node, _ = _client(base=1)
    _flaky(client, node, [failure])  # it never reached the node
    with pytest.raises(NetworkError) as exc_info:
        await client.data.store_item("sg", "a", {"v": 1})
    error = exc_info.value
    assert (error.did, error.nonce) == (node.did, 2)
    assert error.transaction["StoreData"]["nonce"] == 2
    # Its nonce stays taken: another write takes the next one.
    assert (await client.data.store_item("sg", "b", {}))["nonce"] == 3
    result = await client.resubmit(error)
    assert (result["code"], result["did"], result["nonce"]) == (0, node.did, 2)
    assert node.sent[-1] == ("StoreData", error.transaction["StoreData"])  # the same bytes
    node.land()
    await client.wait_until_landed(result, timeout=0)
    assert node.base == 3
    await client.close()


@pytest.mark.asyncio
async def test_a_resubmitted_copy_of_a_pending_write_counts_as_accepted():
    client, node, _ = _client(base=1)
    _flaky(client, node, [("after", httpx.ReadTimeout("timed out"))])  # it reached the node
    with pytest.raises(NetworkError) as exc_info:
        await client.data.store_item("sg", "a", {"v": 1})
    result = await client.resubmit(exc_info.value)
    assert (result["tx_hash"], result["code"], result["nonce"]) == (None, 0, 2)
    assert "already exists in cache" in result["log"]
    assert len(node.pending) == 1  # one copy: the write runs once
    node.land()
    await client.wait_until_landed(result, timeout=0)
    await client.close()


@pytest.mark.asyncio
async def test_a_resubmitted_copy_of_a_write_that_landed_is_refused_and_its_nonce_counts_as_used():
    client, node, _ = _client(base=1)
    _flaky(client, node, [("after", httpx.ReadTimeout("timed out"))])
    with pytest.raises(NetworkError) as exc_info:
        await client.data.store_item("sg", "a", {"v": 1})
    node.land()
    node.cache.clear()  # evicted from the mempool cache
    with pytest.raises(TransactionError, match="Invalid nonce: 2 <= base nonce 2") as refused:
        await client.resubmit(exc_info.value)
    assert (refused.value.did, refused.value.nonce) == (node.did, 2)
    await client.wait_until_landed(refused.value, timeout=0)
    # Never signed again under another nonce: it ran once.
    assert node.nonces_sent() == [2, 2]
    await client.close()


@pytest.mark.asyncio
async def test_a_gateway_error_keeps_the_nonce_and_can_be_resubmitted():
    client, node, _ = _client(base=1)
    real = node.handler
    gateway = [httpx.Response(502, json={"success": False, "data": None, "error": "Failed to reach CometBFT RPC: timed out"})]

    def handler(request):
        if request.url.path == "/tx/submit" and gateway:
            return gateway.pop()
        return real(request)

    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(TransactionError, match="Failed to reach CometBFT") as exc_info:
        await client.data.store_item("sg", "a", {})
    assert exc_info.value.nonce == 2 and exc_info.value.transaction is not None
    assert (await client.data.store_item("sg", "b", {}))["nonce"] == 3
    assert (await client.resubmit(exc_info.value))["nonce"] == 2
    await client.close()


@pytest.mark.asyncio
async def test_a_write_resubmitted_after_its_nonce_went_to_another_write_is_not_sent():
    clock = _Clock()
    client, node, _ = _client(base=1)
    client._nonces = NonceTracker(clock)
    _flaky(client, node, [httpx.ReadTimeout("timed out")])
    with pytest.raises(NetworkError) as exc_info:
        await client.data.store_item("sg", "a", {})
    clock.now += LEASE_SECONDS  # its lease runs out; the next write takes nonce 2
    assert (await client.data.store_item("sg", "b", {}))["nonce"] == 2
    sent = len(node.sent)
    with pytest.raises(WillowError, match="handed to another write"):
        await client.resubmit(exc_info.value)
    assert len(node.sent) == sent
    await client.close()


@pytest.mark.asyncio
async def test_a_write_resubmitted_after_its_lease_ran_out_takes_its_nonce_again():
    clock = _Clock()
    client, node, _ = _client(base=1)
    client._nonces = NonceTracker(clock)
    _flaky(client, node, [httpx.ReadTimeout("timed out")])
    with pytest.raises(NetworkError) as exc_info:
        await client.data.store_item("sg", "a", {})
    clock.now += LEASE_SECONDS
    assert (await client.resubmit(exc_info.value))["nonce"] == 2
    assert (await client.data.store_item("sg", "b", {}))["nonce"] == 3
    await client.close()


@pytest.mark.asyncio
async def test_a_resubmission_that_fails_again_keeps_its_transaction():
    client, node, _ = _client(base=1)
    _flaky(client, node, [httpx.ReadTimeout("timed out"), httpx.ConnectError("refused")])
    with pytest.raises(NetworkError) as first:
        await client.data.store_item("sg", "a", {})
    with pytest.raises(NetworkError) as second:
        await client.resubmit(first.value)
    # The first copy may still have reached the node: the nonce stays taken.
    assert second.value.transaction == first.value.transaction
    assert (await client.data.store_item("sg", "b", {}))["nonce"] == 3
    assert (await client.resubmit(second.value))["nonce"] == 2
    await client.close()


@pytest.mark.asyncio
async def test_register_did_that_may_have_reached_the_node_is_resubmitted():
    client, node, info = _client()
    _flaky(client, node, [("after", httpx.ReadTimeout("timed out"))])
    with pytest.raises(NetworkError) as exc_info:
        await client.register_did(info["did_document"])
    assert exc_info.value.nonce == 1
    result = await client.resubmit(exc_info.value)
    assert (result["code"], result["nonce"]) == (0, 1)
    await client.close()


def _with_rpc(client, node, fail=False):
    """Serve the ABCI nonce-state query from ``node`` at http://rpc.test."""
    api = client._http._transport.handler if hasattr(client._http._transport, "handler") else node.handler
    reads = []

    def handler(request):
        if request.url.host == "rpc.test":
            reads.append(json.loads(request.content)["params"]["path"])
            if fail:
                return httpx.Response(503)
            value = base64.b64encode(node.nonce_state()).decode()
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"response": {"code": 0, "value": value}}})
        return api(request)

    client.consensus_rpc_url = "http://rpc.test"
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return reads


@pytest.mark.asyncio
async def test_wait_until_landed_sees_a_nonce_above_a_gap_with_the_rpc_url():
    # Nonce 2 was abandoned (never landed); nonce 3 landed. The base stays 1.
    client, node, _ = _client(base=1)
    node.used = {3}
    write = {"did": node.did, "nonce": 3}
    with pytest.raises(NotLandedError, match="nonce 3 of .* base nonce is 1"):
        await client.wait_until_landed(write, timeout=0)
    reads = _with_rpc(client, node)
    await client.wait_until_landed(write, timeout=0)
    assert reads == [f"/store/account_nonce_state/{node.did}"]
    with pytest.raises(NotLandedError, match="nonce 2 of"):
        await client.wait_until_landed({"did": node.did, "nonce": 2}, write, timeout=0)
    # A write takes the free nonce below, not one the node reports used.
    assert (await client.data.store_item("sg", "a", {}))["nonce"] == 2
    assert (await client.data.store_item("sg", "b", {}))["nonce"] == 4
    await client.close()


@pytest.mark.asyncio
async def test_without_the_nonce_state_query_the_base_is_read_from_the_api():
    client, node, _ = _client(base=1)
    node.used = {3}
    _with_rpc(client, node, fail=True)
    with pytest.raises(NotLandedError):
        await client.wait_until_landed({"did": node.did, "nonce": 3}, timeout=0)
    node.used, node.base = set(), 3
    await client.wait_until_landed({"did": node.did, "nonce": 3}, timeout=0)
    await client.close()


# ---------------------------------------------------------------------------
# ConsensusClient.
# ---------------------------------------------------------------------------


class _Response:
    def __init__(self, payload, status=200):
        self.status = status
        self._payload = payload

    async def json(self, content_type="application/json"):
        return self._payload

    async def text(self):
        return json.dumps(self._payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Session:
    """aiohttp's session over a ``FakeNode``."""

    def __init__(self, node):
        self.node = node
        self.failures = []  # as in ``_flaky``

    def get(self, url):
        assert url.endswith("/nonce")
        self.node.nonce_reads += 1
        return _Response({"success": True, "data": {"nonce": self.node.base}})

    def post(self, url, json):
        request = httpx.Request("POST", "http://api.test/tx/submit", content=_dumps(json))
        if self.failures:
            failure = self.failures.pop(0)
            if isinstance(failure, tuple):
                self.node.handler(request)
                failure = failure[1]
            raise failure
        response = self.node.handler(request)
        return _Response(response.json(), response.status_code)


class _Refused(aiohttp.ClientConnectorError):
    """aiohttp's error for a connection that was never made."""

    def __init__(self):
        OSError.__init__(self, 61, "Connection refused")

    def __str__(self):
        return "Cannot connect to host api.test:80 [Connection refused]"


def _dumps(value):
    return json.dumps(value).encode()


def _consensus_client(node):
    client = ConsensusClient(ConsensusConfig(consensus_rpc_url="http://rpc.test", api_url="http://api.test"))
    client._session = _Session(node)
    client._nonce_poll_interval = 0
    return client


@pytest.mark.asyncio
async def test_consensus_register_did_signs_nonce_one_without_reading_the_account():
    info = generate_did()
    node = FakeNode(info["did"])
    client = _consensus_client(node)
    result = await client.register_did(
        info["did_document"].model_dump(by_alias=True), info["private_key"], info["public_key_id"]
    )
    assert result.success
    assert node.nonces_sent() == [1]
    assert node.nonce_reads == 0
    # A write from the DID before the registration lands takes nonce 2.
    await client.store_data("sg", "k", {}, info["did"], info["private_key"], info["public_key_id"])
    assert node.nonces_sent() == [1, 2]


@pytest.mark.asyncio
async def test_consensus_writes_take_distinct_nonces_and_give_back_refused_ones():
    info = generate_did()
    node = FakeNode(info["did"], base=9)
    client = _consensus_client(node)
    args = (info["did"], info["private_key"], info["public_key_id"])
    assert (await client.store_data("sg", "a", {}, *args)).success
    assert (await client.store_data("sg", "b", {}, *args)).success
    node.refusals = ["Insufficient balance"]
    assert not (await client.store_data("sg", "c", {}, *args)).success
    assert (await client.store_data("sg", "c", {}, *args)).success
    assert node.nonces_sent() == [10, 11, 12, 12]


@pytest.mark.asyncio
async def test_consensus_write_on_a_used_nonce_is_signed_again():
    info = generate_did()
    node = FakeNode(info["did"], base=0, used={1})
    client = _consensus_client(node)
    result = await client.store_data("sg", "a", {}, info["did"], info["private_key"], info["public_key_id"])
    assert result.success
    assert node.nonces_sent() == [1, 2]


@pytest.mark.asyncio
async def test_consensus_retry_of_a_copy_the_node_admitted_counts_as_accepted():
    info = generate_did()
    node = FakeNode(info["did"], base=4)
    client = _consensus_client(node)
    client._session.failures = [("after", aiohttp.ServerDisconnectedError())]
    result = await client.store_data("sg", "a", {}, info["did"], info["private_key"], info["public_key_id"])
    assert result.success and result.resent and result.tx_hash is None
    assert (result.did, result.nonce) == (info["did"], 5)
    assert node.nonces_sent() == [5, 5]  # the same bytes, never signed again
    assert len(node.pending) == 1


@pytest.mark.asyncio
async def test_consensus_retry_refused_as_used_after_a_transit_failure_is_not_signed_again():
    info = generate_did()
    node = FakeNode(info["did"], base=4)
    client = _consensus_client(node)

    def landed_and_evicted(request):
        FakeNode.handler(node, request)
        node.land()
        node.cache.clear()
        raise aiohttp.ServerDisconnectedError()

    real_post = client._session.post
    calls = []

    def post(url, json):
        calls.append(json)
        if len(calls) == 1:
            landed_and_evicted(httpx.Request("POST", url, content=_dumps(json)))
        return real_post(url, json)

    client._session.post = post
    with pytest.raises(ConsensusError, match="may have landed") as exc_info:
        await client.transfer(info["did"], "did:willow:b", 5, info["private_key"], info["public_key_id"])
    assert (exc_info.value.did, exc_info.value.nonce) == (info["did"], 5)
    assert node.nonces_sent() == [5, 5]  # no copy under another nonce


@pytest.mark.asyncio
async def test_consensus_refusal_by_the_api_frees_the_nonce_by_its_http_status():
    info = generate_did()
    node = FakeNode(info["did"], base=4)
    client = _consensus_client(node)
    real_post = client._session.post
    answers = [_Response({"success": False, "data": None, "error": "Failed to deserialize the JSON body"}, 422)]

    def post(url, json):
        if answers:
            node.sent.append(next(iter(json.items())))
            return answers.pop()
        return real_post(url, json)

    client._session.post = post
    args = (info["did"], info["private_key"], info["public_key_id"])
    refused = await client.store_data("sg", "a", {}, *args)
    assert (refused.success, refused.http_status, refused.nonce) == (False, 422, 5)
    assert (await client.store_data("sg", "a", {}, *args)).nonce == 5


@pytest.mark.asyncio
async def test_consensus_write_that_never_left_gives_its_nonce_back():
    info = generate_did()
    node = FakeNode(info["did"], base=4)
    client = _consensus_client(node)
    client.config.max_retries = 1
    client._session.failures = [_Refused(), _Refused()]
    args = (info["did"], info["private_key"], info["public_key_id"])
    with pytest.raises(ConsensusError) as exc_info:
        await client.store_data("sg", "a", {}, *args)
    assert (exc_info.value.did, exc_info.value.nonce, exc_info.value.transaction) == (info["did"], 5, None)
    assert (await client.store_data("sg", "a", {}, *args)).nonce == 5


@pytest.mark.asyncio
async def test_consensus_write_that_may_have_reached_the_node_is_resubmitted():
    info = generate_did()
    node = FakeNode(info["did"], base=4)
    client = _consensus_client(node)
    client.config.max_retries = 1
    client._session.failures = [_Refused(), aiohttp.ServerDisconnectedError()]
    args = (info["did"], info["private_key"], info["public_key_id"])
    with pytest.raises(ConsensusError) as exc_info:
        await client.store_data("sg", "a", {}, *args)
    error = exc_info.value
    assert (error.did, error.nonce) == (info["did"], 5) and error.transaction is not None
    assert (await client.store_data("sg", "b", {}, *args)).nonce == 6
    result = await client.resubmit(error)
    assert result.success and result.nonce == 5
    assert node.sent[-1] == next(iter(error.transaction.items()))


@pytest.mark.asyncio
async def test_consensus_register_did_signs_with_the_algorithm_its_key_type_names():
    info = generate_did("secp256k1")
    node = FakeNode(info["did"])
    client = _consensus_client(node)
    result = await client.register_did(
        info["did_document"].model_dump(by_alias=True), info["private_key"], info["public_key_id"]
    )
    assert result.success
    ((_, body),) = node.sent
    message = register_did_message(body["did_document"])
    assert verify_signature(message, bytes(body["signature"]).hex(), info["public_key"], "secp256k1")
    assert not verify_signature(message, bytes(body["signature"]).hex(), info["public_key"], "Ed25519")
