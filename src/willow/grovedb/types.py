"""
GroveDB Proof Types

Type definitions matching the Rust GroveDB proof structures.
"""

from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum

# Type alias for 32-byte cryptographic hash
CryptoHash = bytes

# Hash length constant
HASH_LENGTH = 32

# Null hash (all zeros)
NULL_HASH: CryptoHash = bytes(32)


class GroveDBVerificationError(Exception):
    """Error raised during GroveDB proof verification."""
    pass


# =============================================================================
# Tree Feature Types
# =============================================================================

@dataclass
class BasicMerkNode:
    """Basic Merk node without additional features."""
    pass


@dataclass
class SummedMerkNode:
    """Merk node with a sum value (i64)."""
    sum: int


@dataclass
class BigSummedMerkNode:
    """Merk node with a big sum value (i128)."""
    sum: int


@dataclass
class CountedMerkNode:
    """Merk node with a count value (u64)."""
    count: int


@dataclass
class CountedSummedMerkNode:
    """Merk node with both count and sum."""
    count: int
    sum: int


TreeFeatureType = Union[
    BasicMerkNode,
    SummedMerkNode,
    BigSummedMerkNode,
    CountedMerkNode,
    CountedSummedMerkNode
]


# =============================================================================
# Merk Node Types
# =============================================================================

@dataclass
class HashNode:
    """Hash-only node."""
    hash: CryptoHash


@dataclass
class KVHashNode:
    """Key-value hash node."""
    kv_hash: CryptoHash


@dataclass
class KVNode:
    """Key-value node with actual data."""
    key: bytes
    value: bytes


@dataclass
class KVValueHashNode:
    """Key-value node with value hash."""
    key: bytes
    value: bytes
    value_hash: CryptoHash


@dataclass
class KVDigestNode:
    """Key-value digest node (no value, just proof of existence)."""
    key: bytes
    value_hash: CryptoHash


@dataclass
class KVRefValueHashNode:
    """Key-value reference node with value hash."""
    key: bytes
    value: bytes
    value_hash: CryptoHash


@dataclass
class KVValueHashFeatureTypeNode:
    """Key-value node with value hash and feature type."""
    key: bytes
    value: bytes
    value_hash: CryptoHash
    feature_type: TreeFeatureType


MerkNode = Union[
    HashNode,
    KVHashNode,
    KVNode,
    KVValueHashNode,
    KVDigestNode,
    KVRefValueHashNode,
    KVValueHashFeatureTypeNode
]


# =============================================================================
# Merk Operations
# =============================================================================

@dataclass
class PushOp:
    """Push a node onto the stack."""
    node: MerkNode


@dataclass
class PushInvertedOp:
    """Push a node onto the stack (inverted order)."""
    node: MerkNode


@dataclass
class ParentOp:
    """Pop parent and child, attach child as LEFT of parent."""
    pass


@dataclass
class ChildOp:
    """Pop child and parent, attach child as RIGHT of parent."""
    pass


@dataclass
class ParentInvertedOp:
    """Pop parent and child, attach child as RIGHT of parent (inverted)."""
    pass


@dataclass
class ChildInvertedOp:
    """Pop child and parent, attach child as LEFT of parent (inverted)."""
    pass


MerkOp = Union[
    PushOp,
    PushInvertedOp,
    ParentOp,
    ChildOp,
    ParentInvertedOp,
    ChildInvertedOp
]


# =============================================================================
# Proof Structures
# =============================================================================

@dataclass
class ProveOptions:
    """Options used when generating the proof."""
    decrease_limit_on_empty_sub_query_result: bool


@dataclass
class LayerProof:
    """Layer proof - contains Merk proof and nested subtree proofs."""
    merk_proof: bytes
    lower_layers: Dict[str, "LayerProof"]  # Key is hex-encoded for dict compatibility


@dataclass
class GroveDBProofV0:
    """GroveDB Proof version 0."""
    root_layer: LayerProof
    prove_options: ProveOptions


@dataclass
class GroveDBProof:
    """GroveDB Proof (versioned)."""
    version: int
    proof: GroveDBProofV0


# =============================================================================
# Verification Results
# =============================================================================

@dataclass
class ProvedKeyValue:
    """Proved key-value pair from verification."""
    key: bytes
    value: Optional[bytes]
    proof: CryptoHash


@dataclass
class MerkExecutionResult:
    """Result of executing a Merk proof."""
    root_hash: CryptoHash
    result_set: List[ProvedKeyValue]
    limit: Optional[int]


@dataclass
class GroveDBVerificationResult:
    """Result of verifying a GroveDB proof."""
    root_hash: CryptoHash
    results: List[Dict]  # [{path, key, value, element}]


# =============================================================================
# Element Types
# =============================================================================

@dataclass
class ItemElement:
    """Item element with raw value."""
    value: bytes
    flags: Optional[bytes]


@dataclass
class ReferenceElement:
    """Reference element pointing to another location."""
    path: List[List[bytes]]
    flags: Optional[bytes]


@dataclass
class TreeElement:
    """Tree element (subtree)."""
    root_key: Optional[bytes]
    flags: Optional[bytes]


@dataclass
class SumTreeElement:
    """Sum tree element."""
    root_key: Optional[bytes]
    sum_value: int
    flags: Optional[bytes]


@dataclass
class SumItemElement:
    """Sum item element."""
    value: int
    flags: Optional[bytes]


@dataclass
class BigSumTreeElement:
    """Big sum tree element."""
    root_key: Optional[bytes]
    sum_value: int
    flags: Optional[bytes]


@dataclass
class CountTreeElement:
    """Count tree element."""
    root_key: Optional[bytes]
    count: int
    flags: Optional[bytes]


@dataclass
class CountSumTreeElement:
    """Count sum tree element."""
    root_key: Optional[bytes]
    count: int
    sum: int
    flags: Optional[bytes]


Element = Union[
    ItemElement,
    ReferenceElement,
    TreeElement,
    SumTreeElement,
    SumItemElement,
    BigSumTreeElement,
    CountTreeElement,
    CountSumTreeElement
]
