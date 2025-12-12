"""
GroveDB Proof Verifier

Main entry point for verifying GroveDB proofs.
Handles nested layer verification and returns proven results.
"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from .types import (
    GroveDBProof,
    LayerProof,
    CryptoHash,
    Element,
    GroveDBVerificationResult,
    GroveDBVerificationError
)
from .bincode import decode_grovedb_proof
from .executor import execute_merk_proof_with_query
from .element import deserialize_element, is_tree_element, has_root_key
from .hash import combine_hash, value_hash, hash_equals, hash_to_hex, bytes_to_hex


@dataclass
class VerifyOptions:
    """Options for proof verification."""
    limit: Optional[int] = None
    deserialize_elements: bool = True


def verify_grovedb_proof(
    proof_bytes: bytes,
    options: Optional[VerifyOptions] = None
) -> GroveDBVerificationResult:
    """
    Verify a GroveDB proof and return the root hash and proven values.

    Args:
        proof_bytes: The bincode-encoded GroveDBProof
        options: Verification options

    Returns:
        Verification result with root hash and proven values
    """
    if options is None:
        options = VerifyOptions()

    proof = decode_grovedb_proof(proof_bytes)
    return _verify_proof(proof, options)


def _verify_proof(
    proof: GroveDBProof,
    options: VerifyOptions
) -> GroveDBVerificationResult:
    """Verify a decoded GroveDB proof."""
    if proof.version != 0:
        raise GroveDBVerificationError(f"Unsupported proof version: {proof.version}")

    results: List[Dict[str, Any]] = []
    limit = options.limit
    deserialize_elements = options.deserialize_elements

    root_hash = _verify_layer_proof(
        proof.proof.root_layer,
        proof.proof.prove_options.decrease_limit_on_empty_sub_query_result,
        [],
        results,
        limit,
        deserialize_elements
    )

    return GroveDBVerificationResult(root_hash=root_hash, results=results)


def _verify_layer_proof(
    layer_proof: LayerProof,
    decrease_limit_on_empty: bool,
    current_path: List[bytes],
    results: List[Dict[str, Any]],
    limit: Optional[int],
    deserialize_elements: bool
) -> CryptoHash:
    """
    Verify a layer proof recursively.

    Args:
        layer_proof: The layer proof to verify
        decrease_limit_on_empty: Whether to decrease limit on empty results
        current_path: Current path in the tree
        results: Accumulator for proven values
        limit: Maximum results (None for unlimited)
        deserialize_elements: Whether to parse element bytes

    Returns:
        Root hash of this layer
    """
    # Execute the Merk proof to get root hash and values
    merk_result = execute_merk_proof_with_query(
        layer_proof.merk_proof,
        limit,
        True  # left to right
    )

    # Process each proven value
    for proved in merk_result.result_set:
        # Check if this key has a lower layer proof (subtree)
        key_hex = bytes_to_hex(proved.key)
        lower_layer = layer_proof.lower_layers.get(key_hex)

        if lower_layer and proved.value:
            # This is a subtree - verify the lower layer
            element: Optional[Element] = None
            if deserialize_elements:
                try:
                    element = deserialize_element(proved.value)
                except Exception:
                    # If deserialization fails, treat as opaque bytes
                    element = None

            # Only recurse if element is a tree type with a root key
            if element and is_tree_element(element) and has_root_key(element):
                new_path = current_path + [proved.key]

                # Recursively verify the lower layer
                lower_hash = _verify_layer_proof(
                    lower_layer,
                    decrease_limit_on_empty,
                    new_path,
                    results,
                    limit - len(results) if limit is not None else None,
                    deserialize_elements
                )

                # Verify the combined hash matches
                element_value_hash = value_hash(proved.value)
                combined_hash = combine_hash(element_value_hash, lower_hash)

                if not hash_equals(combined_hash, proved.proof):
                    raise GroveDBVerificationError(
                        f"Lower layer hash mismatch at path {_path_to_string(new_path)}: "
                        f"expected {hash_to_hex(proved.proof)}, got {hash_to_hex(combined_hash)}"
                    )
            else:
                # Element doesn't have subtrees but has a lower layer - error
                raise GroveDBVerificationError(
                    f"Proof has lower layer for non-tree element at "
                    f"{_path_to_string(current_path + [proved.key])}"
                )
        elif proved.value:
            # Leaf value - add to results
            element: Optional[Element] = None
            if deserialize_elements:
                try:
                    element = deserialize_element(proved.value)
                except Exception:
                    # If deserialization fails, treat as opaque bytes
                    element = None

            results.append({
                "path": current_path,
                "key": proved.key,
                "value": proved.value,
                "element": element
            })

    return merk_result.root_hash


def verify_proof_against_root(
    proof_bytes: bytes,
    expected_root_hash: CryptoHash,
    options: Optional[VerifyOptions] = None
) -> GroveDBVerificationResult:
    """
    Verify that a proof matches an expected root hash.

    Args:
        proof_bytes: The bincode-encoded GroveDBProof
        expected_root_hash: The expected root hash (from light client)
        options: Verification options

    Returns:
        Verification result if valid

    Raises:
        GroveDBVerificationError: If root hash doesn't match
    """
    result = verify_grovedb_proof(proof_bytes, options)

    if not hash_equals(result.root_hash, expected_root_hash):
        raise GroveDBVerificationError(
            f"Root hash mismatch: expected {hash_to_hex(expected_root_hash)}, "
            f"got {hash_to_hex(result.root_hash)}"
        )

    return result


def quick_verify(proof_bytes: bytes) -> CryptoHash:
    """
    Quick verification - just check if proof is valid and return root hash.
    Does not parse elements or return results.

    Args:
        proof_bytes: The bincode-encoded GroveDBProof

    Returns:
        Root hash of the proof
    """
    proof = decode_grovedb_proof(proof_bytes)
    return _quick_verify_layer(proof.proof.root_layer)


def _quick_verify_layer(layer_proof: LayerProof) -> CryptoHash:
    """Quick verify a single layer."""
    merk_result = execute_merk_proof_with_query(layer_proof.merk_proof, None, True)

    # Verify any lower layers
    for key_hex, lower_layer in layer_proof.lower_layers.items():
        proved = None
        for r in merk_result.result_set:
            if bytes_to_hex(r.key) == key_hex:
                proved = r
                break

        if proved is None or proved.value is None:
            raise GroveDBVerificationError(
                f"Lower layer key {key_hex} not found in Merk proof"
            )

        lower_hash = _quick_verify_layer(lower_layer)
        element_value_hash = value_hash(proved.value)
        combined_hash = combine_hash(element_value_hash, lower_hash)

        if not hash_equals(combined_hash, proved.proof):
            raise GroveDBVerificationError(
                f"Lower layer hash mismatch for key {key_hex}"
            )

    return merk_result.root_hash


def _path_to_string(path: List[bytes]) -> str:
    """Convert a path to a human-readable string."""
    parts = []
    for p in path:
        # Try to decode as UTF-8, fall back to hex
        try:
            s = p.decode('utf-8')
            # Only use string if it's printable ASCII
            if all(0x20 <= ord(c) <= 0x7e for c in s):
                parts.append(s)
            else:
                parts.append(bytes_to_hex(p))
        except Exception:
            parts.append(bytes_to_hex(p))
    return "/" + "/".join(parts)
