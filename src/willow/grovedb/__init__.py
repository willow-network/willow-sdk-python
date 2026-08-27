"""
GroveDB Proof Verification

Pure Python implementation of GroveDB Merkle proof verification.
This enables fully trustless verification without native Rust bindings.

Usage:
    from willow.grovedb import verify_grovedb_proof, verify_proof_against_root

    # Verify a proof and get root hash + results
    result = verify_grovedb_proof(proof_bytes)
    print(f"Root hash: {result.root_hash.hex()}")
    for item in result.results:
        print(f"Key: {item['key']}, Value: {item['value']}")

    # Verify against expected root hash (from light client)
    result = verify_proof_against_root(proof_bytes, expected_root_hash)
"""

# Types
from .types import (
    CryptoHash,
    HASH_LENGTH,
    NULL_HASH,
    GroveDBVerificationError,
    # MerkNode variants
    HashNode,
    KVHashNode,
    KVNode,
    KVValueHashNode,
    KVDigestNode,
    KVRefValueHashNode,
    KVValueHashFeatureTypeNode,
    MerkNode,
    # MerkOp variants
    PushOp,
    PushInvertedOp,
    ParentOp,
    ChildOp,
    ParentInvertedOp,
    ChildInvertedOp,
    MerkOp,
    # TreeFeatureType variants
    BasicMerkNode,
    SummedMerkNode,
    BigSummedMerkNode,
    CountedMerkNode,
    CountedSummedMerkNode,
    TreeFeatureType,
    # Element variants
    ItemElement,
    ReferenceElement,
    TreeElement,
    SumTreeElement,
    SumItemElement,
    BigSumTreeElement,
    CountTreeElement,
    CountSumTreeElement,
    Element,
    # Proof structures
    ProveOptions,
    LayerProof,
    GroveDBProofV0,
    GroveDBProof,
    ProvedKeyValue,
    MerkExecutionResult,
    GroveDBVerificationResult,
)

# Hash functions
from .hash import (
    blake3_hash,
    value_hash,
    kv_hash,
    kv_digest_to_kv_hash,
    node_hash,
    combine_hash,
    hash_equals,
    is_null_hash,
    hash_to_hex,
    hex_to_hash,
    bytes_to_hex,
    hex_to_bytes,
)

# Varint encoding
from .varint import (
    encode_varint,
    decode_varint,
    decode_signed_varint,
    decode_varint64,
    decode_signed_varint64,
    VarintError,
)

# Bincode decoding
from .bincode import (
    BincodeReader,
    decode_grovedb_proof,
    decode_layer_proof,
)

# Merk decoding
from .merk_decoder import (
    MerkDecoder,
    decode_merk_ops,
)

# Tree structure
from .tree import (
    Tree,
    Child,
    compare_bytes,
)

# Element deserialization
from .element import (
    deserialize_element,
    is_tree_element,
    has_root_key,
    get_tree_feature_type,
)

# Executor
from .executor import (
    execute_ops,
    execute_merk_proof,
    execute_merk_proof_with_query,
)

# Main verifier functions
from .verifier import (
    verify_grovedb_proof,
    verify_proof_against_root,
    check_envelope,
    quick_verify,
    VerifyOptions,
)

__all__ = [
    # Types
    "CryptoHash",
    "HASH_LENGTH",
    "NULL_HASH",
    "GroveDBVerificationError",
    # MerkNode variants
    "HashNode",
    "KVHashNode",
    "KVNode",
    "KVValueHashNode",
    "KVDigestNode",
    "KVRefValueHashNode",
    "KVValueHashFeatureTypeNode",
    "MerkNode",
    # MerkOp variants
    "PushOp",
    "PushInvertedOp",
    "ParentOp",
    "ChildOp",
    "ParentInvertedOp",
    "ChildInvertedOp",
    "MerkOp",
    # TreeFeatureType variants
    "BasicMerkNode",
    "SummedMerkNode",
    "BigSummedMerkNode",
    "CountedMerkNode",
    "CountedSummedMerkNode",
    "TreeFeatureType",
    # Element variants
    "ItemElement",
    "ReferenceElement",
    "TreeElement",
    "SumTreeElement",
    "SumItemElement",
    "BigSumTreeElement",
    "CountTreeElement",
    "CountSumTreeElement",
    "Element",
    # Proof structures
    "ProveOptions",
    "LayerProof",
    "GroveDBProofV0",
    "GroveDBProof",
    "ProvedKeyValue",
    "MerkExecutionResult",
    "GroveDBVerificationResult",
    # Hash functions
    "blake3_hash",
    "value_hash",
    "kv_hash",
    "kv_digest_to_kv_hash",
    "node_hash",
    "combine_hash",
    "hash_equals",
    "is_null_hash",
    "hash_to_hex",
    "hex_to_hash",
    "bytes_to_hex",
    "hex_to_bytes",
    # Varint encoding
    "encode_varint",
    "decode_varint",
    "decode_signed_varint",
    "decode_varint64",
    "decode_signed_varint64",
    "VarintError",
    # Bincode decoding
    "BincodeReader",
    "decode_grovedb_proof",
    "decode_layer_proof",
    # Merk decoding
    "MerkDecoder",
    "decode_merk_ops",
    # Tree structure
    "Tree",
    "Child",
    "compare_bytes",
    # Element deserialization
    "deserialize_element",
    "is_tree_element",
    "has_root_key",
    "get_tree_feature_type",
    # Executor
    "execute_ops",
    "execute_merk_proof",
    "execute_merk_proof_with_query",
    # Main verifier functions
    "verify_grovedb_proof",
    "verify_proof_against_root",
    "check_envelope",
    "quick_verify",
    "VerifyOptions",
]
