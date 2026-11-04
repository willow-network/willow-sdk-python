"""Nonces handed out per signing DID.

The node accepts a nonce in base+1 … base+24 that is not used and not held by
another pending transaction; the base advances only over used nonces with no
gap. ``FakeNode`` applies those rules to the transactions the client sends, so
each test shows what CheckTx would answer."""

import asyncio
import json

import httpx
import pytest

from willow import (
    NonceWindowFullError,
    NotLandedError,
    WillowClient,
    generate_did,
    store_data_message,
    verify_signature,
)
from willow.consensus import ConsensusClient, ConsensusConfig
from willow.errors import NetworkError, TransactionError
from willow.nonces import (
    FREE,
    HELD,
    LEASE_SECONDS,
    UNKNOWN,
    USED,
    WINDOW,
    NonceTracker,
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


@pytest.mark.parametrize("error,status,outcome", [
    (_checktx("Nonce 7 of did:willow:a is held by a pending transaction; sign this one with another nonce"), 200, HELD),
    (_checktx("Invalid nonce: 7 already used (replay)"), 200, USED),
    (_checktx("Invalid nonce: 5 <= base nonce 7"), 200, USED),
    (_checktx("Data not found (nonce 7 spent)"), 200, USED),
    (_checktx("Invalid nonce: 40 is too far ahead (base=7, max=31)"), 200, FREE),
    (_checktx("Signature mismatch: the signature does not match the expected signing message."), 200, FREE),
    (_checktx("Insufficient balance"), 200, FREE),
    (TransactionError("Failed to deserialize the JSON body"), 422, FREE),
    (TransactionError("Failed to reach CometBFT RPC: timed out"), 502, UNKNOWN),
    (NetworkError("Network error: reset"), None, UNKNOWN),
])
def test_what_a_refusal_leaves_its_nonce_as(error, status, outcome):
    assert refusal_outcome(error, status) == outcome


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

    def handler(self, request):
        if request.url.path.endswith("/nonce"):
            self.nonce_reads += 1
            if self.on_nonce_read is not None:
                self.on_nonce_read(self)
            return _ok({"did": self.did, "nonce": self.base})
        assert request.url.path == "/tx/submit"
        ((kind, body),) = json.loads(request.content).items()
        self.sent.append((kind, body))
        log = self.refusals.pop(0) if self.refusals else None
        log = log or self._check(body)
        if log:
            return _ok({"tx_hash": "", "code": 1, "log": log})
        self.pending[body["nonce"]] = bytes(body["signature"])
        return _ok({"tx_hash": f"T{len(self.sent)}", "code": 0, "log": ""})

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
    with pytest.raises(NotLandedError, match="nonce 2"):
        await client.wait_until_landed(results, timeout=0)
    node.land()
    await client.wait_until_landed(results, timeout=0)
    with pytest.raises(ValueError):
        await client.wait_until_landed({"tx_hash": "AB"})
    await client.close()


@pytest.mark.asyncio
async def test_a_write_that_fails_in_transit_keeps_its_nonce():
    client, node, _ = _client()
    real = node.handler
    calls = []

    def flaky(request):
        if request.url.path == "/tx/submit" and not calls:
            calls.append(request)
            raise httpx.ConnectError("reset")
        return real(request)

    client._http = httpx.AsyncClient(transport=httpx.MockTransport(flaky))
    with pytest.raises(NetworkError) as exc_info:
        await client.data.store("sg", {"a": {}})
    assert exc_info.value.submitted == [] and exc_info.value.failed_key == "a"
    assert (exc_info.value.did, exc_info.value.nonce) == (node.did, 1)
    # It may have reached the node: the next write takes another nonce.
    assert (await client.data.store_item("sg", "b", {}))["nonce"] == 2
    await client.close()


# ---------------------------------------------------------------------------
# ConsensusClient.
# ---------------------------------------------------------------------------


class _Response:
    def __init__(self, payload):
        self.status = 200
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

    def get(self, url):
        assert url.endswith("/nonce")
        self.node.nonce_reads += 1
        return _Response({"success": True, "data": {"nonce": self.node.base}})

    def post(self, url, json):
        request = httpx.Request("POST", "http://api.test/tx/submit", content=_dumps(json))
        return _Response(self.node.handler(request).json())


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
