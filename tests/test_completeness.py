"""Tests for client-side completeness verification.

The two vectors below are the cross-language correctness gate — they MUST match
the canonical Rust ``canonical_event_set_hash`` byte-for-byte.
"""

import base64
import json

import httpx
import pytest

from willow.completeness import (
    CompletenessError,
    CompletenessOperations,
    Log,
    canonical_event_set_hash,
    logs_from_matched_logs_response,
    verify_served_events,
)

# Vector A — the empty matched set at block 0.
VECTOR_A_BLOCK = 0
VECTOR_A_LOGS: list = []
VECTOR_A_HASH = "0x52089e4c924fbab0475d310d7f74bf8cae542d006a45d3c5d94adacda6937da5"

# Vector B — two logs at block 7.
VECTOR_B_BLOCK = 7
VECTOR_B_LOGS = [
    Log(
        address=bytes([0x42]) * 20,
        topics=[bytes([0xDD]) * 32, bytes([0x11]) * 32],
        data=bytes([0x01, 0x02, 0x03, 0x04]),
    ),
    Log(
        address=bytes([0x43]) * 20,
        topics=[bytes([0xAA]) * 32],
        data=b"",
    ),
]
VECTOR_B_HASH = "0xe1544ae919458663e8fce14bdcd06df6a777410c068302c0584dff1587524dfd"


class TestCanonicalEventSetHash:
    """The hash must match the on-chain ``canonical_event_set_hash`` exactly."""

    def test_vector_a_empty_set(self):
        """Vector A: block 0, no matched logs."""
        digest = canonical_event_set_hash(VECTOR_A_BLOCK, VECTOR_A_LOGS)
        assert digest.hex() == VECTOR_A_HASH[2:]

    def test_vector_b_two_logs(self):
        """Vector B: block 7, two logs (one with data, one empty)."""
        digest = canonical_event_set_hash(VECTOR_B_BLOCK, VECTOR_B_LOGS)
        assert digest.hex() == VECTOR_B_HASH[2:]

    def test_deterministic(self):
        """Hashing the same input twice yields the same digest."""
        a = canonical_event_set_hash(VECTOR_B_BLOCK, VECTOR_B_LOGS)
        b = canonical_event_set_hash(VECTOR_B_BLOCK, VECTOR_B_LOGS)
        assert a == b

    def test_accepts_hex_string_fields(self):
        """Hex-string fields encode identically to raw bytes."""
        hex_logs = [
            Log(
                address="0x" + "42" * 20,
                topics=["0x" + "dd" * 32, "0x" + "11" * 32],
                data="0x01020304",
            ),
            Log(address="43" * 20, topics=["aa" * 32], data="0x"),
        ]
        assert (
            canonical_event_set_hash(VECTOR_B_BLOCK, hex_logs)
            == canonical_event_set_hash(VECTOR_B_BLOCK, VECTOR_B_LOGS)
        )

    def test_block_number_must_fit_u64(self):
        """Out-of-range block numbers are rejected."""
        with pytest.raises(ValueError):
            canonical_event_set_hash(1 << 64, [])
        with pytest.raises(ValueError):
            canonical_event_set_hash(-1, [])


class TestVerifyServedEvents:
    """Re-hash the served preimage and compare to the on-chain anchor."""

    def test_vector_a_verifies(self):
        assert verify_served_events(VECTOR_A_HASH, VECTOR_A_BLOCK, VECTOR_A_LOGS)

    def test_vector_b_verifies(self):
        assert verify_served_events(VECTOR_B_HASH, VECTOR_B_BLOCK, VECTOR_B_LOGS)

    def test_commitment_accepts_raw_bytes(self):
        anchor = bytes.fromhex(VECTOR_B_HASH[2:])
        assert verify_served_events(anchor, VECTOR_B_BLOCK, VECTOR_B_LOGS)

    def test_tamper_wrong_block_number(self):
        """Changing the block number fails verification."""
        assert not verify_served_events(
            VECTOR_B_HASH, VECTOR_B_BLOCK + 1, VECTOR_B_LOGS
        )

    def test_tamper_dropped_log(self):
        """Dropping a log from the served set fails verification."""
        dropped = VECTOR_B_LOGS[:1]
        assert not verify_served_events(VECTOR_B_HASH, VECTOR_B_BLOCK, dropped)

    def test_tamper_added_log(self):
        """Adding an extra log to the served set fails verification."""
        added = VECTOR_B_LOGS + [
            Log(address=bytes([0x44]) * 20, topics=[], data=b"")
        ]
        assert not verify_served_events(VECTOR_B_HASH, VECTOR_B_BLOCK, added)

    def test_tamper_mutated_data(self):
        """Mutating a single data byte fails verification."""
        mutated = [
            Log(
                address=VECTOR_B_LOGS[0].address,
                topics=VECTOR_B_LOGS[0].topics,
                data=bytes([0x01, 0x02, 0x03, 0x05]),
            ),
            VECTOR_B_LOGS[1],
        ]
        assert not verify_served_events(VECTOR_B_HASH, VECTOR_B_BLOCK, mutated)

    def test_tamper_reordered_logs(self):
        """Reordering the served set fails verification (order is committed)."""
        reordered = list(reversed(VECTOR_B_LOGS))
        assert not verify_served_events(VECTOR_B_HASH, VECTOR_B_BLOCK, reordered)


# The authoritative indexer ``matched-logs`` response body for vector B. This is
# the exact JSON contract from willow PR #676 — the JSON->Log parse must reduce
# it to the canonical set that hashes to VECTOR_B_HASH.
MATCHED_LOGS_BODY = {
    "subgrove_id": "sg",
    "block_number": 7,
    "count": 2,
    "matched_logs": [
        {
            "block_number": 7,
            "block_hash": "0x" + "00" * 32,
            "transaction_hash": "0x" + "00" * 32,
            "transaction_index": 0,
            "log_index": "0x0",
            "address": "0x4242424242424242424242424242424242424242",
            "topics": [
                "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "0x1111111111111111111111111111111111111111111111111111111111111111",
            ],
            "data": "0x01020304",
            "removed": False,
        },
        {
            "block_number": 7,
            "block_hash": "0x" + "00" * 32,
            "transaction_hash": "0x" + "00" * 32,
            "transaction_index": 0,
            "log_index": "0x1",
            "address": "0x4343434343434343434343434343434343434343",
            "topics": [
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ],
            "data": "0x",
            "removed": False,
        },
    ],
}


class TestParseMatchedLogsBody:
    """Gate the JSON->Log parse against the authoritative indexer body."""

    def test_parsed_body_verifies_against_anchor(self):
        """Parsing the real response body yields logs that hash to the anchor.

        This is the cross-implementation gate: only ``address``/``topics``/
        ``data`` are part of the commitment, so dropping block_hash, tx_hash,
        log_index, removed, etc. must still reproduce VECTOR_B_HASH exactly.
        """
        logs = logs_from_matched_logs_response(MATCHED_LOGS_BODY)
        assert verify_served_events(VECTOR_B_HASH, 7, logs)

    def test_parse_preserves_order_and_count(self):
        logs = logs_from_matched_logs_response(MATCHED_LOGS_BODY)
        assert len(logs) == 2
        assert logs[0].data == "0x01020304"
        assert logs[1].data == "0x"


def _anchor_rpc_response(commitment_hex: str) -> dict:
    """Build a CometBFT ``abci_query`` envelope carrying the anchor value.

    The chain JSON-encodes ``{subgrove_id, block_number, events_commitment}``
    into ResponseQuery.value; CometBFT base64s it into ``result.response.value``.
    """
    value = json.dumps(
        {
            "subgrove_id": "sg",
            "block_number": 7,
            "events_commitment": commitment_hex,
        }
    ).encode()
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"response": {"code": 0, "value": base64.b64encode(value).decode()}},
    }


class TestVerifyBlockCompletenessMocked:
    """Full fetch-anchor + fetch-preimage + verify path over a mock transport."""

    def _ops(self, handler) -> CompletenessOperations:
        transport = httpx.MockTransport(handler)
        http = httpx.AsyncClient(transport=transport)
        return CompletenessOperations(
            http,
            "http://validator:26657",
            "http://indexer:9090",
        )

    async def test_verify_block_completeness_true(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/matched-logs"):
                assert request.url.path == "/completeness/sg/7/matched-logs"
                return httpx.Response(200, json=MATCHED_LOGS_BODY)
            # CometBFT abci_query JSON-RPC POST.
            assert request.method == "POST"
            return httpx.Response(200, json=_anchor_rpc_response(VECTOR_B_HASH[2:]))

        ops = self._ops(handler)
        assert await ops.verify_block_completeness("sg", 7) is True
        await ops._http.aclose()

    async def test_verify_block_completeness_tampered_false(self):
        """A served set that doesn't match the anchor verifies False (not an error)."""
        tampered = json.loads(json.dumps(MATCHED_LOGS_BODY))
        tampered["matched_logs"][0]["data"] = "0x01020305"

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/matched-logs"):
                return httpx.Response(200, json=tampered)
            return httpx.Response(200, json=_anchor_rpc_response(VECTOR_B_HASH[2:]))

        ops = self._ops(handler)
        assert await ops.verify_block_completeness("sg", 7) is False
        await ops._http.aclose()

    async def test_missing_anchor_raises(self):
        """ABCI code != 0 surfaces as not-verifiable (CompletenessError)."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "response": {
                            "code": 1,
                            "log": "No events commitment for block 7",
                        }
                    },
                },
            )

        ops = self._ops(handler)
        with pytest.raises(CompletenessError):
            await ops.verify_block_completeness("sg", 7)
        await ops._http.aclose()

    async def test_missing_preimage_raises(self):
        """A 404 from the indexer surfaces as not-verifiable (CompletenessError)."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/matched-logs"):
                return httpx.Response(404, text="no retained matched logs")
            return httpx.Response(200, json=_anchor_rpc_response(VECTOR_B_HASH[2:]))

        ops = self._ops(handler)
        with pytest.raises(CompletenessError):
            await ops.verify_block_completeness("sg", 7)
        await ops._http.aclose()

    async def test_no_indexer_configured_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_anchor_rpc_response(VECTOR_B_HASH[2:]))

        transport = httpx.MockTransport(handler)
        http = httpx.AsyncClient(transport=transport)
        ops = CompletenessOperations(http, "http://validator:26657", None)
        with pytest.raises(CompletenessError):
            await ops.fetch_matched_logs("sg", 7)
        await http.aclose()
