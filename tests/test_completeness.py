"""Tests for client-side completeness verification.

The two vectors below are the cross-language correctness gate — they MUST match
the canonical Rust ``canonical_event_set_hash`` byte-for-byte.
"""

import pytest

from willow.completeness import (
    Log,
    canonical_event_set_hash,
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
