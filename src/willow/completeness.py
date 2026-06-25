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

The end-to-end :meth:`CompletenessOperations.verify_block_completeness` helper
fetches the anchor from the validator's CometBFT ABCI store
(``/store/events_commitment/{subgrove}/{block}``) and the matched-log preimage
from the indexer (``/completeness/{subgrove}/{block}/matched-logs``), then calls
:func:`verify_served_events`. Reachable as ``client.completeness`` on
:class:`~willow.client.WillowClient`.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Mapping, Optional, Sequence, Union

from eth_hash.auto import keccak

if TYPE_CHECKING:  # pragma: no cover
    import httpx

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


# --- Wire decoding: the two on-the-wire shapes from willow PR #676 ----------


class CompletenessError(Exception):
    """A completeness check could not be performed (no anchor, no preimage)."""


def log_from_indexer_json(obj: Mapping[str, Any]) -> Log:
    """Build a :class:`Log` from one ``IndexedLog`` JSON object.

    The indexer serves many fields per log (block_number, block_hash,
    transaction_hash, transaction_index, log_index, removed); only the three
    root-bound, consensus-derivable fields are part of the commitment, so only
    those are read here — ``address``, ``topics``, ``data``, all ``0x``-hex.
    """
    return Log(
        address=obj["address"],
        topics=list(obj.get("topics") or []),
        data=obj.get("data") or b"",
    )


def logs_from_matched_logs_response(body: Mapping[str, Any]) -> list[Log]:
    """Parse an indexer ``matched-logs`` response body into ordered ``Log``s.

    Body shape: ``{"subgrove_id", "block_number", "count", "matched_logs": [...]}``.
    Order is preserved — the commitment binds it.
    """
    return [log_from_indexer_json(entry) for entry in body.get("matched_logs", [])]


def commitment_from_anchor_value(value: bytes) -> bytes:
    """Decode the 32-byte commitment from an ABCI store-query value.

    ``value`` is the raw bytes of the ABCI ``ResponseQuery.value`` (already
    base64-decoded from the CometBFT RPC envelope). On success the chain encodes
    it as JSON ``{"subgrove_id", "block_number", "events_commitment": "<64-hex>"}``.
    """
    obj = json.loads(value)
    return _to_bytes(obj["events_commitment"], name="events_commitment", length=32)


class CompletenessOperations:
    """End-to-end client-side completeness checks for a ``(subgrove, block)``.

    Fetches the on-chain anchor from the validator's CometBFT ABCI store and the
    matched-log preimage from the indexer, then re-hashes and compares via
    :func:`verify_served_events`. The indexer it queries is configured by
    ``indexer_url`` on the client (or :class:`~willow.client.WillowClientBuilder`).
    """

    def __init__(
        self,
        http: "httpx.AsyncClient",
        cometbft_rpc_url: str,
        indexer_url: Optional[str],
    ):
        """
        Args:
            http: shared httpx client (carries any ``X-API-Key`` default header).
            cometbft_rpc_url: validator CometBFT RPC base (e.g. ``:26657``), used
                for the ``abci_query`` that reads the on-chain anchor.
            indexer_url: indexer base URL serving ``/completeness/...``. ``None``
                until configured; the wrapper raises if it's needed unset.
        """
        self._http = http
        self._rpc_url = cometbft_rpc_url.rstrip("/")
        self._indexer_url = indexer_url.rstrip("/") if indexer_url else None

    async def fetch_anchor(self, subgrove_id: str, block_number: int) -> bytes:
        """Read the on-chain ``events_commitment`` (32 bytes) via ABCI store query.

        Raises :class:`CompletenessError` if the chain has no commitment for the
        block (ABCI ``code != 0``).
        """
        path = f"/store/events_commitment/{subgrove_id}/{block_number}"
        rpc_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "abci_query",
            "params": {"path": path, "data": "", "height": "0", "prove": False},
        }
        resp = await self._http.post(self._rpc_url, json=rpc_request)
        resp.raise_for_status()
        envelope = resp.json()
        if "error" in envelope and envelope["error"]:
            raise CompletenessError(f"abci_query RPC error: {envelope['error']}")
        response = envelope.get("result", {}).get("response", {})
        code = response.get("code", 0)
        if code != 0:
            log = response.get("log") or f"code {code}"
            raise CompletenessError(
                f"no anchor for {subgrove_id} block {block_number}: {log}"
            )
        value_b64 = response.get("value")
        if not value_b64:
            raise CompletenessError(
                f"empty anchor value for {subgrove_id} block {block_number}"
            )
        return commitment_from_anchor_value(base64.b64decode(value_b64))

    async def fetch_matched_logs(
        self, subgrove_id: str, block_number: int
    ) -> list[Log]:
        """GET the indexer's matched-log preimage and parse it into ``Log``s.

        Raises :class:`CompletenessError` on a non-200 (e.g. 404 "no retained
        matched logs" / "block not finalized") or if no indexer is configured.
        """
        if not self._indexer_url:
            raise CompletenessError(
                "no indexer_url configured; set it on WillowClient to fetch "
                "matched logs"
            )
        url = (
            f"{self._indexer_url}/completeness/{subgrove_id}/{block_number}/"
            "matched-logs"
        )
        resp = await self._http.get(url)
        if resp.status_code != 200:
            detail = ""
            try:
                detail = resp.text
            except Exception:  # pragma: no cover - defensive
                pass
            raise CompletenessError(
                f"matched-logs unavailable for {subgrove_id} block {block_number}:"
                f" HTTP {resp.status_code} {detail}".rstrip()
            )
        return logs_from_matched_logs_response(resp.json())

    async def verify_block_completeness(
        self, subgrove_id: str, block_number: int
    ) -> bool:
        """Run the full client-side completeness check for one block.

        Fetches the on-chain anchor and the indexer's matched-log preimage, then
        returns whether the served set re-hashes to the anchor.

        Args:
            subgrove_id: the subgrove the block belongs to.
            block_number: the block to check.

        Returns:
            ``True`` if the indexer's matched set is exactly the complete,
            untampered set the chain commits to.

        Raises:
            CompletenessError: if the anchor or the preimage cannot be fetched
                (the check is not verifiable, distinct from a ``False`` result
                which means the served set was tampered with).
        """
        commitment = await self.fetch_anchor(subgrove_id, block_number)
        logs = await self.fetch_matched_logs(subgrove_id, block_number)
        return verify_served_events(commitment, block_number, logs)
