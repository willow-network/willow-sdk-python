"""Canonical ``WillowManifest`` builder for Willow's blockchain-indexing
subgroves.

Mirrors :class:`willow_types::consensus::manifest::WillowManifest` in the
Rust workspace. The consensus validator rejects any ``manifest_content``
that doesn't decode into this exact shape, so SDK callers should build
their on-chain manifest bytes via :func:`serialize_manifest`. Each data
source is either EVM (``address`` + ``abi`` + ``start_block`` + ``events``)
or Solana (``program_id`` + ``start_slot`` + ``instructions``); the family
is dispatched at parse time from the ``network`` field.

Example::

    from willow.manifest import serialize_manifest, WillowManifest, EvmDataSource

    manifest = WillowManifest(
        spec_version="1.0.0",
        data_sources=[
            EvmDataSource(
                name="UniswapV3Pool",
                network="mainnet",
                address="0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
                abi="UniswapV3Pool",
                start_block=12369621,
                events=["Swap(address,address,int256,int256,uint160,uint128,int24)"],
            ),
        ],
    )
    manifest_content = serialize_manifest(manifest)  # bytes ready for on-chain
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import List, Literal, Optional, Union

# Canonical chains. Order mirrors ``SupportedChain::ALL`` in willow-types.
SUPPORTED_CHAINS = (
    # EVM family
    "mainnet",
    "sepolia",
    "holesky",
    "bsc",
    "optimism",
    "arbitrum-one",
    "base",
    "polygon",
    # Solana family
    "solana-mainnet",
)

SupportedChain = Literal[
    "mainnet",
    "sepolia",
    "holesky",
    "bsc",
    "optimism",
    "arbitrum-one",
    "base",
    "polygon",
    "solana-mainnet",
]

ChainFamily = Literal["evm", "solana"]

MANIFEST_SPEC_VERSION = "1.0.0"

# Mirrors ``MAX_*`` constants in willow-types.
MAX_DATA_SOURCES = 64
MAX_EVENTS_PER_SOURCE = 32
MAX_NAME_LEN = 64
MAX_ABI_LEN = 64
MAX_DESCRIPTION_LEN = 1024


_EVM_CHAIN_IDS = {
    "mainnet": 1,
    "sepolia": 11_155_111,
    "holesky": 17_000,
    "bsc": 56,
    "optimism": 10,
    "arbitrum-one": 42_161,
    "base": 8453,
    "polygon": 137,
    "solana-mainnet": None,
}


def chain_family(chain: str) -> ChainFamily:
    """Return the family a chain belongs to. Drives data-source dispatch."""
    return "solana" if chain == "solana-mainnet" else "evm"


def evm_chain_id(chain: str) -> Optional[int]:
    """EIP-155 chain id for EVM-family chains, ``None`` for Solana."""
    return _EVM_CHAIN_IDS.get(chain)


def is_supported_chain(value: str) -> bool:
    """Type guard matching ``SupportedChain::from_canonical_id``."""
    return value in SUPPORTED_CHAINS


def from_evm_chain_id(chain_id: int) -> Optional[str]:
    """Map an EIP-155 chain id back to the canonical chain identifier."""
    for chain, cid in _EVM_CHAIN_IDS.items():
        if cid == chain_id:
            return chain
    return None


class ManifestValidationError(ValueError):
    """Raised when a manifest fails to satisfy the canonical schema.

    The ``field`` attribute holds a dotted path (e.g.
    ``"data_sources[1].address"``) so callers can attribute the failure.
    """

    def __init__(self, message: str, field_path: str = ""):
        super().__init__(message)
        self.field = field_path


@dataclass
class EvmDataSource:
    """One indexed EVM contract within a manifest."""

    name: str
    network: str
    address: str  # 0x + 40 hex chars (lowercased on serialize)
    abi: str
    start_block: int
    events: List[str]


@dataclass
class SolanaDataSource:
    """One indexed Solana program within a manifest."""

    name: str
    network: str
    program_id: str  # base58-encoded 32-byte pubkey
    start_slot: int
    instructions: List[str]  # each `0x` + even hex chars (>= 2)


DataSource = Union[EvmDataSource, SolanaDataSource]


@dataclass
class WillowManifest:
    """Canonical manifest for ``BlockchainIndexing`` subgroves."""

    spec_version: str = MANIFEST_SPEC_VERSION
    data_sources: List[DataSource] = field(default_factory=list)
    description: Optional[str] = None
    deferred_completeness: bool = False


_EVENT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_EVENT_PARAM_RE = re.compile(r"^[A-Za-z0-9_\[\]]+$")
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_NAME_CHARSET_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_DISCRIMINATOR_RE = re.compile(r"^0x([0-9a-fA-F]{2})+$")
_BASE58_ALPHABET = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


def _validate_event_signature(sig: str, path: str) -> None:
    if not sig:
        raise ManifestValidationError(f"{path} must not be empty", path)
    open_paren = sig.find("(")
    if open_paren == -1:
        raise ManifestValidationError(f"{path} {sig!r} missing '('", path)
    if not sig.endswith(")"):
        raise ManifestValidationError(f"{path} {sig!r} missing trailing ')'", path)
    name = sig[:open_paren]
    params = sig[open_paren + 1 : -1]
    if not _EVENT_NAME_RE.match(name):
        raise ManifestValidationError(
            f"{path} event name {name!r} is not a valid identifier", path
        )
    if not params:
        return
    for part in params.split(","):
        if not _EVENT_PARAM_RE.match(part):
            raise ManifestValidationError(
                f"{path} has invalid parameter type {part!r}", path
            )


def _validate_name(name: str, path: str) -> None:
    if not name:
        raise ManifestValidationError(f"{path}.name must not be empty", f"{path}.name")
    if len(name) > MAX_NAME_LEN:
        raise ManifestValidationError(
            f"{path}.name length {len(name)} exceeds maximum {MAX_NAME_LEN}",
            f"{path}.name",
        )
    if not _NAME_CHARSET_RE.match(name):
        raise ManifestValidationError(
            f"{path}.name {name!r} must be alphanumeric, '-', or '_'",
            f"{path}.name",
        )


def _validate_data_source(ds: DataSource, path: str) -> None:
    _validate_name(ds.name, path)
    if not is_supported_chain(ds.network):
        raise ManifestValidationError(
            f"{path}.network {ds.network!r} is not a canonical chain",
            f"{path}.network",
        )
    family = chain_family(ds.network)
    if family == "evm":
        if not isinstance(ds, EvmDataSource):
            raise ManifestValidationError(
                f"{path}.network {ds.network!r} is EVM-family but data source is not EvmDataSource",
                path,
            )
        _validate_evm_data_source(ds, path)
    else:
        if not isinstance(ds, SolanaDataSource):
            raise ManifestValidationError(
                f"{path}.network {ds.network!r} is Solana-family but data source is not SolanaDataSource",
                path,
            )
        _validate_solana_data_source(ds, path)


def _validate_evm_data_source(ds: EvmDataSource, path: str) -> None:
    if not _ADDRESS_RE.match(ds.address):
        raise ManifestValidationError(
            f"{path}.address must be 0x + 40 hex chars (got {ds.address!r})",
            f"{path}.address",
        )
    if not ds.abi:
        raise ManifestValidationError(f"{path}.abi must not be empty", f"{path}.abi")
    if len(ds.abi) > MAX_ABI_LEN:
        raise ManifestValidationError(
            f"{path}.abi length {len(ds.abi)} exceeds maximum {MAX_ABI_LEN}",
            f"{path}.abi",
        )
    if not isinstance(ds.start_block, int) or ds.start_block < 0:
        raise ManifestValidationError(
            f"{path}.start_block must be a non-negative integer",
            f"{path}.start_block",
        )
    if not ds.events:
        raise ManifestValidationError(
            f"{path}.events must declare at least one event", f"{path}.events"
        )
    if len(ds.events) > MAX_EVENTS_PER_SOURCE:
        raise ManifestValidationError(
            f"{path}.events has {len(ds.events)} entries (maximum {MAX_EVENTS_PER_SOURCE})",
            f"{path}.events",
        )
    for idx, sig in enumerate(ds.events):
        _validate_event_signature(sig, f"{path}.events[{idx}]")


def _validate_solana_data_source(ds: SolanaDataSource, path: str) -> None:
    if not ds.program_id or not (32 <= len(ds.program_id) <= 44):
        raise ManifestValidationError(
            f"{path}.program_id must be a base58-encoded 32-byte pubkey (got {ds.program_id!r})",
            f"{path}.program_id",
        )
    for c in ds.program_id:
        if c not in _BASE58_ALPHABET:
            raise ManifestValidationError(
                f"{path}.program_id contains invalid base58 character {c!r}",
                f"{path}.program_id",
            )
    if not isinstance(ds.start_slot, int) or ds.start_slot < 0:
        raise ManifestValidationError(
            f"{path}.start_slot must be a non-negative integer",
            f"{path}.start_slot",
        )
    if not ds.instructions:
        raise ManifestValidationError(
            f"{path}.instructions must declare at least one discriminator",
            f"{path}.instructions",
        )
    if len(ds.instructions) > MAX_EVENTS_PER_SOURCE:
        raise ManifestValidationError(
            f"{path}.instructions has {len(ds.instructions)} entries "
            f"(maximum {MAX_EVENTS_PER_SOURCE})",
            f"{path}.instructions",
        )
    for idx, d in enumerate(ds.instructions):
        if not _DISCRIMINATOR_RE.match(d):
            raise ManifestValidationError(
                f"{path}.instructions[{idx}] must be 0x + an even, non-zero number of hex chars (got {d!r})",
                f"{path}.instructions[{idx}]",
            )


def validate_manifest(manifest: WillowManifest) -> None:
    """Apply every canonical-schema check.

    Same rules as ``WillowManifest::from_bytes`` + ``validate()`` in
    willow-types. Raises :class:`ManifestValidationError` with a
    ``field`` path on the first problem found.
    """
    if manifest.spec_version != MANIFEST_SPEC_VERSION:
        raise ManifestValidationError(
            f"unsupported spec_version {manifest.spec_version!r} "
            f"(expected {MANIFEST_SPEC_VERSION!r})",
            "spec_version",
        )
    if manifest.description is not None and len(manifest.description) > MAX_DESCRIPTION_LEN:
        raise ManifestValidationError(
            f"description length {len(manifest.description)} exceeds maximum "
            f"{MAX_DESCRIPTION_LEN}",
            "description",
        )
    if not manifest.data_sources:
        raise ManifestValidationError(
            "manifest must declare at least one data source", "data_sources"
        )
    if len(manifest.data_sources) > MAX_DATA_SOURCES:
        raise ManifestValidationError(
            f"manifest has {len(manifest.data_sources)} data sources "
            f"(maximum {MAX_DATA_SOURCES})",
            "data_sources",
        )
    for idx, ds in enumerate(manifest.data_sources):
        _validate_data_source(ds, f"data_sources[{idx}]")


def serialize_manifest(manifest: WillowManifest) -> bytes:
    """Validate and serialize to the canonical JSON byte form that goes
    on-chain via ``SubgroveMode.BlockchainIndexing.manifest_content``.

    EVM addresses are normalised to lowercase so the emitted bytes
    round-trip bit-for-bit with what ``WillowManifest::from_bytes``
    produces in Rust.
    """
    validate_manifest(manifest)
    sources_payload = []
    for ds in manifest.data_sources:
        if isinstance(ds, EvmDataSource):
            sources_payload.append({
                "name": ds.name,
                "network": ds.network,
                "address": ds.address.lower(),
                "abi": ds.abi,
                "start_block": ds.start_block,
                "events": list(ds.events),
            })
        else:
            sources_payload.append({
                "name": ds.name,
                "network": ds.network,
                "program_id": ds.program_id,
                "start_slot": ds.start_slot,
                "instructions": [d.lower() for d in ds.instructions],
            })
    payload = {
        "spec_version": manifest.spec_version,
        "data_sources": sources_payload,
    }
    if manifest.description is not None:
        payload["description"] = manifest.description
    if manifest.deferred_completeness:
        payload["deferred_completeness"] = True
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def parse_manifest(data: Union[bytes, str]) -> WillowManifest:
    """Validate and decode canonical manifest bytes (or a JSON string)."""
    text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        raise ManifestValidationError(
            f"manifest is not valid JSON: {e}", ""
        ) from e
    if not isinstance(parsed, dict):
        raise ManifestValidationError("manifest must be a JSON object", "")

    extra_keys = set(parsed.keys()) - {
        "spec_version",
        "description",
        "data_sources",
        "deferred_completeness",
    }
    if extra_keys:
        raise ManifestValidationError(
            f"manifest has unknown top-level fields: {sorted(extra_keys)!r}", ""
        )

    sources_raw = parsed.get("data_sources")
    if not isinstance(sources_raw, list):
        raise ManifestValidationError("data_sources must be a list", "data_sources")

    data_sources: List[DataSource] = []
    evm_keys = {"name", "network", "address", "abi", "start_block", "events"}
    solana_keys = {"name", "network", "program_id", "start_slot", "instructions"}
    for idx, raw in enumerate(sources_raw):
        if not isinstance(raw, dict):
            raise ManifestValidationError(
                f"data_sources[{idx}] must be a JSON object", f"data_sources[{idx}]"
            )
        network = raw.get("network")
        if not isinstance(network, str) or not is_supported_chain(network):
            raise ManifestValidationError(
                f"data_sources[{idx}].network {network!r} is not a canonical chain",
                f"data_sources[{idx}].network",
            )
        family = chain_family(network)
        allowed = evm_keys if family == "evm" else solana_keys
        unknown = set(raw.keys()) - allowed
        if unknown:
            raise ManifestValidationError(
                f"data_sources[{idx}] has unknown fields: {sorted(unknown)!r}",
                f"data_sources[{idx}]",
            )
        try:
            if family == "evm":
                ds = EvmDataSource(
                    name=raw["name"],
                    network=raw["network"],
                    address=raw["address"],
                    abi=raw["abi"],
                    start_block=raw["start_block"],
                    events=list(raw["events"]),
                )
            else:
                ds = SolanaDataSource(
                    name=raw["name"],
                    network=raw["network"],
                    program_id=raw["program_id"],
                    start_slot=raw["start_slot"],
                    instructions=list(raw["instructions"]),
                )
        except KeyError as e:
            raise ManifestValidationError(
                f"data_sources[{idx}] missing required field {e.args[0]!r}",
                f"data_sources[{idx}]",
            ) from None
        data_sources.append(ds)

    manifest = WillowManifest(
        spec_version=parsed["spec_version"],
        data_sources=data_sources,
        description=parsed.get("description"),
        deferred_completeness=bool(parsed.get("deferred_completeness", False)),
    )
    validate_manifest(manifest)
    return manifest


__all__ = [
    "SUPPORTED_CHAINS",
    "SupportedChain",
    "ChainFamily",
    "MANIFEST_SPEC_VERSION",
    "MAX_DATA_SOURCES",
    "MAX_EVENTS_PER_SOURCE",
    "MAX_NAME_LEN",
    "MAX_ABI_LEN",
    "MAX_DESCRIPTION_LEN",
    "WillowManifest",
    "EvmDataSource",
    "SolanaDataSource",
    "DataSource",
    "ManifestValidationError",
    "chain_family",
    "evm_chain_id",
    "from_evm_chain_id",
    "is_supported_chain",
    "validate_manifest",
    "serialize_manifest",
    "parse_manifest",
]
