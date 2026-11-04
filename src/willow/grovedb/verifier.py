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
    ItemElement,
    NULL_HASH,
    ProvedKeyValue,
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
    # The GroveDB path the query was made at. When set, the proof envelope
    # must carry a lower layer for every segment (see check_envelope); without
    # it an empty result set at that path cannot be told apart from a proof
    # whose subtree was silently dropped.
    expected_path: Optional[List[bytes]] = None


def check_envelope(proof: GroveDBProof, expected_path: List[bytes]) -> None:
    """
    The check grovedb's own verifier does not make. The verifier finds the
    next layer by the envelope's `lower_layers` map KEY, which is not
    hash-bound: a prover who renames or drops the entry for a subtree on the
    query path gets the same root hash with that subtree's results silently
    gone, so a proof of "K = V" verifies as "K is absent". Requiring a layer
    for every path segment closes it (once a layer is present its root is
    hash-bound to the parent).

    A proof of a query at a path carries, above the path, only the layer of
    the path's next segment, and none below it. A lower layer off the path is
    refused: it would carry entries proven at another path (another
    subgrove's data, say) beside the queried ones. `prove_options` is
    prover-chosen bytes that steer limit accounting, so it is pinned to the
    default the chain's prover uses.
    """
    if proof.version != 0:
        raise GroveDBVerificationError(f"Unsupported proof version: {proof.version}")
    _check_prove_options(proof)
    layer = proof.proof.root_layer
    for i, seg in enumerate(expected_path):
        seg_hex = bytes_to_hex(seg)
        nxt = layer.lower_layers.get(seg_hex)
        if nxt is None:
            raise GroveDBVerificationError(
                f"envelope: no lower layer for path segment {i} ({seg!r}); "
                "the proof does not descend to the query path"
            )
        if len(layer.lower_layers) != 1:
            raise GroveDBVerificationError(
                f"envelope: a lower layer off the query path beside path segment {i} ({seg!r})"
            )
        layer = nxt
    if layer.lower_layers:
        raise GroveDBVerificationError("envelope: unexpected lower layers below the query path")


def _check_prove_options(proof: GroveDBProof) -> None:
    if not proof.proof.prove_options.decrease_limit_on_empty_sub_query_result:
        raise GroveDBVerificationError("envelope: non-default prove_options")


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
    _check_prove_options(proof)
    if options.expected_path is not None:
        check_envelope(proof, options.expected_path)

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
    consumed = set()
    for proved in merk_result.result_set:
        # Check if this key has a lower layer proof (subtree)
        key_hex = bytes_to_hex(proved.key)
        lower_layer = layer_proof.lower_layers.get(key_hex)

        if lower_layer is not None:
            # This is a subtree - verify the lower layer
            element = _try_deserialize(proved.value) if proved.value is not None else None

            # Only recurse if element is a tree type with a root key
            if element is not None and is_tree_element(element) and has_root_key(element):
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
                consumed.add(key_hex)
            else:
                # Element doesn't have subtrees but has a lower layer - error
                raise GroveDBVerificationError(
                    f"Proof has lower layer for non-tree element at "
                    f"{_path_to_string(current_path + [proved.key])}"
                )
        elif proved.value:
            # Leaf value: bind its bytes to the value hash the node commits
            # to, then add it. The element is read whatever
            # `deserialize_elements` says, to tell a subtree from a value.
            element = _try_deserialize(proved.value)
            bound = _bind_leaf_value(proved, element, current_path)
            tree = element is not None and is_tree_element(element)
            results.append({
                "path": current_path,
                "key": proved.key,
                "value": proved.value if bound else None,
                "element": element if bound and deserialize_elements else None,
                "tree": tree,
                "node_type": proved.node_type,
            })

    # A lower layer under a key this layer doesn't prove is bound to nothing.
    unproven = set(layer_proof.lower_layers) - consumed
    if unproven:
        raise GroveDBVerificationError(
            f"Proof has a lower layer under a key its layer at {_path_to_string(current_path)} "
            f"does not prove: {sorted(unproven)[0]}"
        )

    return merk_result.root_hash


def _try_deserialize(value: bytes) -> Optional[Element]:
    try:
        return deserialize_element(value)
    except Exception:
        return None


def _bind_leaf_value(proved: ProvedKeyValue, element: Optional[Element], path: List[bytes]) -> bool:
    """Bind a leaf's bytes to the value hash its merk node commits to;
    whether they are bound.

    A ``KV`` node's hash is computed from its bytes, and a
    ``KVRefValueHash`` node's from the referenced bytes it carries, so both
    are bound. A ``KVValueHash`` node carries its value hash beside its
    bytes, and only the hash enters the root: its bytes are bound only when
    they hash to it, so a value whose hash differs is refused. A tree
    element is the exception: its value hash is
    ``combine_hash(value_hash(bytes), subtree root)``. An empty subtree's
    root is the null hash, so it is checked; a non-empty one's can't be
    without its lower layer, so its bytes are not bound (``False``).
    """
    if proved.node_type not in ("KVValueHash", "KVValueHashFeatureType"):
        return True
    if element is not None and is_tree_element(element):
        if has_root_key(element):
            return False
        expected = combine_hash(value_hash(proved.value), NULL_HASH)
        what = "Empty subtree"
    else:
        expected = value_hash(proved.value)
        what = "Value"
    if not hash_equals(expected, proved.proof):
        raise GroveDBVerificationError(
            f"{what} at {_path_to_string(path + [proved.key])} does not hash to the value hash "
            f"its node commits to: expected {hash_to_hex(proved.proof)}, got {hash_to_hex(expected)}"
        )
    return True


@dataclass
class ProvenItem:
    """An Item element a proof proves at a path and key.

    ``value`` is the Item's payload (for a Willow data key, the stored JSON
    text), ``element`` the element's serialized bytes, and ``flags`` its
    element flags.
    """
    path: List[bytes]
    key: bytes
    value: bytes
    element: bytes
    flags: Optional[bytes] = None


def _path_bytes(path: List[Any]) -> List[bytes]:
    segments = []
    for seg in path:
        if isinstance(seg, str):
            segments.append(seg.encode("utf-8"))
        elif isinstance(seg, (bytes, bytearray)):
            segments.append(bytes(seg))
        else:
            raise GroveDBVerificationError(f"a path segment must be str or bytes, not {type(seg).__name__}")
    return segments


def verify_items_at_path(
    proof_bytes: bytes,
    path: List[Any],
    expected_root_hash: Optional[CryptoHash] = None,
) -> "tuple[CryptoHash, List[ProvenItem]]":
    """
    Verify a GroveDB proof of a query at ``path`` and return its root hash
    and the Item elements it proves at exactly ``path``, in key order.

    The proof must descend to ``path`` with no lower layer off it (see
    ``check_envelope``), and each Item's bytes must be bound to the root
    (see ``_bind_leaf_value``). Entries proven at another path, subtrees,
    references, and sum items are not returned. This proves each returned
    Item is stored at ``path`` under the returned root; it does not prove
    that no other Item is.

    Args:
        proof_bytes: The bincode-encoded GroveDBProof
        path: The query's path, as str (UTF-8) or bytes segments; not empty
        expected_root_hash: When given, the root the proof must reproduce

    Raises:
        GroveDBVerificationError: The proof is invalid, does not descend to
            ``path``, or (with ``expected_root_hash``) has another root.
    """
    segments = _path_bytes(path)
    if not segments:
        raise GroveDBVerificationError("a path is required: a proof binds values only at a path")
    result = verify_grovedb_proof(proof_bytes, VerifyOptions(expected_path=segments))
    if expected_root_hash is not None and not hash_equals(result.root_hash, expected_root_hash):
        raise GroveDBVerificationError(
            f"Root hash mismatch: expected {hash_to_hex(expected_root_hash)}, "
            f"got {hash_to_hex(result.root_hash)}"
        )
    items = []
    for entry in result.results:
        if entry["path"] != segments or entry["value"] is None:
            continue
        if entry["node_type"] not in ("KV", "KVValueHash", "KVValueHashFeatureType"):
            continue
        element = _try_deserialize(entry["value"])
        if isinstance(element, ItemElement):
            items.append(ProvenItem(
                path=segments, key=entry["key"], value=element.value,
                element=entry["value"], flags=element.flags,
            ))
    return result.root_hash, items


def verify_item_at_path(
    proof_bytes: bytes,
    path: List[Any],
    key: Any,
    expected_root_hash: Optional[CryptoHash] = None,
) -> "tuple[CryptoHash, ProvenItem]":
    """
    Verify a GroveDB proof that ``key`` holds an Item element at ``path``,
    and return its root hash and that Item.

    See ``verify_items_at_path``. A proof that proves no Item at exactly
    ``path`` and ``key`` (another key, another path, a subtree, a lone
    root hash) is refused.

    Raises:
        GroveDBVerificationError: The proof is invalid, or does not prove an
            Item at ``path`` and ``key``.
    """
    key_bytes = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    root_hash, items = verify_items_at_path(proof_bytes, path, expected_root_hash)
    for item in items:
        if item.key == key_bytes:
            return root_hash, item
    raise GroveDBVerificationError(
        f"The proof does not prove an Item at {_path_to_string(_path_bytes(path) + [key_bytes])}"
    )


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
