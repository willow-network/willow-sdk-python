"""Client-side completeness verification.

Counterpart to Willow's on-chain ``events_commitment``: a domain-separated
keccak-256 commitment over the filter-matched event set for a ``(subgrove,
block)``. The chain stores this 32-byte hash; an indexer serves the matched-log
preimage; the client re-hashes the preimage here and compares. A match proves
the served set is the complete, untampered set the chain attests to — without
trusting the indexer.

Canonical Rust source:
``willow-network::data_sources::types::canonical_event_set_hash`` (mirrored from
``willow-consensus``'s ``full_block_auth::canonical_event_set_hash``). The
preimage binds only ``(address, topics, data)`` — the consensus-derivable,
root-bound fields — length-prefixed so no boundary is ambiguous.

The optional ``verify_block_completeness`` end-to-end helper (fetch the anchor
from the validator ABCI store + the preimage from the indexer, then verify) is
intentionally NOT included: this SDK has no generic ABCI store-query client for
the ``events_commitment`` path nor an indexer HTTP client for the
``/completeness/{subgrove}/{block}/matched-logs`` route. Once those land, wire
them up and call :func:`verify_served_events` with the fetched values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence, Union

from eth_hash.auto import keccak

# Domain separator — must match the on-chain tag byte-for-byte (23 ASCII bytes,
# no null terminator).
DOMAIN_TAG = b"WILLOW_CRYPTO_EVENTS_V1"

HexOrBytes = Union[str, bytes, bytearray]


def _to_bytes(value: HexOrBytes, *, name: str, length: Optional[int] = None) -> bytes:
    """Coerce hex string (``0x``-optional) or raw bytes to ``bytes``."""
    if isinstance(value, str):
        out = bytes.fromhex(value[2:] if value.startswith("0x") else value)
    elif isinstance(value, (bytes, bytearray)):
        out = bytes(value)
    else:
        raise TypeError(f"{name} must be hex str or bytes, got {type(value).__name__}")
    if length is not None and len(out) != length:
        raise ValueError(f"{name} must be {length} bytes, got {len(out)}")
    return out


@dataclass
class Log:
    """A filter-matched Ethereum log, as committed by ``events_commitment``.

    Only the consensus-derivable, root-bound fields are part of the commitment.

    Args:
        address: 20-byte contract address (hex str or raw bytes).
        topics: ordered list of 32-byte topics (hex str or raw bytes each).
        data: raw log data bytes (hex str or raw bytes).
    """

    address: HexOrBytes
    topics: Sequence[HexOrBytes] = field(default_factory=list)
    data: HexOrBytes = b""

    def canonical_bytes(self) -> bytes:
        """Encode this log into its canonical commitment preimage fragment.

        Layout (all integers big-endian, no separators):
            - address                          (20 bytes)
            - topics.length as u32 big-endian  (4 bytes)
            - each topic                       (32 bytes each)
            - data.length as u32 big-endian    (4 bytes)
            - data                             (raw bytes)
        """
        addr = _to_bytes(self.address, name="address", length=20)
        topics = [_to_bytes(t, name="topic", length=32) for t in self.topics]
        data = _to_bytes(self.data, name="data")

        buf = bytearray()
        buf += addr
        buf += len(topics).to_bytes(4, "big")
        for topic in topics:
            buf += topic
        buf += len(data).to_bytes(4, "big")
        buf += data
        return bytes(buf)


def canonical_event_set_hash(block_number: int, matched_logs: Sequence[Log]) -> bytes:
    """Domain-separated keccak-256 commitment over the filter-matched event set.

    Mirrors the on-chain ``canonical_event_set_hash``. The preimage is, with all
    integers big-endian and no separators:
        - ``b"WILLOW_CRYPTO_EVENTS_V1"``       (23 bytes)
        - ``block_number`` as u64 big-endian   (8 bytes)
        - ``len(matched_logs)`` as u64 big-endian (8 bytes)
        - then each log's :meth:`Log.canonical_bytes`, in order.

    Args:
        block_number: the block the matched set belongs to.
        matched_logs: the filter-matched logs, in canonical (chain) order.

    Returns:
        The 32-byte keccak-256 commitment.
    """
    if block_number < 0 or block_number >= (1 << 64):
        raise ValueError("block_number must fit in u64")

    buf = bytearray()
    buf += DOMAIN_TAG
    buf += block_number.to_bytes(8, "big")
    buf += len(matched_logs).to_bytes(8, "big")
    for log in matched_logs:
        buf += log.canonical_bytes()
    return keccak(bytes(buf))


def verify_served_events(
    commitment: HexOrBytes,
    block_number: int,
    matched_logs: Sequence[Log],
) -> bool:
    """Verify served matched-logs against the on-chain ``events_commitment``.

    Re-hashes the served preimage and compares it to the trusted anchor. ``True``
    means the served set is exactly the complete, untampered set the chain
    attests to; ``False`` means it was tampered with (a log added, dropped, or
    mutated) or the block number is wrong.

    Args:
        commitment: the 32-byte on-chain anchor (hex str or raw bytes).
        block_number: the block the served set claims to cover.
        matched_logs: the matched logs served by the indexer.

    Returns:
        ``True`` if the recomputed hash equals ``commitment``.
    """
    anchor = _to_bytes(commitment, name="commitment", length=32)
    computed = canonical_event_set_hash(block_number, matched_logs)
    return computed == anchor
