"""
Proof verification for Willow data.

A GroveDB proof proves values at a path under a root hash. This module
checks, locally, that a proof proves a given value at a given path and key
(``verify_item_proof``), or that each of a set of documents is a value
proven at a path (``verify_query_proof``), and returns the root it computes.
That root proves nothing until it is compared with a root you trust: pass
``ProofVerificationOptions(expected_root_hash=...)``, or compare the
returned ``root_hash`` yourself. A proof the node returns is of the state
after a block ``height``; that state's root is the ``app_hash`` of the
CometBFT header at ``height + 1``.

A subgrove's keys are stored and proven at ``subgrove_data_path(id)``.
"""

import json
from typing import List, Dict, Any, Optional, Tuple, Union
import logging
from dataclasses import dataclass

from .types import QueryResponse
from .errors import ProofVerificationError

from .grovedb import (
    verify_proof_against_root,
    verify_items_at_path,
    quick_verify,
    GroveDBVerificationError,
    ProvenItem,
    hash_to_hex,
    hex_to_hash,
)

logger = logging.getLogger(__name__)

PathSegment = Union[str, bytes]


def subgrove_data_path(subgrove_id: str) -> List[bytes]:
    """The GroveDB path a subgrove's keys are stored and proven at:
    ``[b"subgroves", subgrove_id, b"data"]``."""
    return [b"subgroves", subgrove_id.encode("utf-8"), b"data"]


@dataclass
class ProofVerificationOptions:
    """Options for proof verification.

    ``expected_root_hash``: the root a proof must reproduce (hex), for
    example a trusted header's ``app_hash``; without it the computed root is
    returned for you to compare. ``deserialize_elements`` and ``limit`` apply
    to ``grovedb.verify_grovedb_proof`` only: the binding checks here read
    every element and every value a proof carries.
    """
    expected_root_hash: Optional[str] = None
    deserialize_elements: bool = True
    limit: Optional[int] = None


@dataclass
class ProofVerificationResult:
    """Result of proof verification.

    ``valid`` is true only when the proof proves what was asked (see the
    method that returned it). ``root_hash`` is the root the proof computes,
    and ``results`` the Items it proves at the path, as
    ``{path, key, value, element}`` dicts (``value`` the Item's payload
    bytes, ``element`` its serialized element).
    """
    valid: bool
    root_hash: Optional[str] = None
    error: Optional[str] = None
    results: Optional[List[Dict]] = None

    def __bool__(self):
        """Allow result to be used in boolean context."""
        return self.valid


class PathQueryData:
    """Path query data for proof verification: the path the query was made
    at (``str`` or ``bytes`` segments)."""
    def __init__(self, path: List[PathSegment], query: Optional[Dict[str, Any]] = None):
        self.path = path
        self.query = query or {}


def json_values_equal(a: Any, b: Any) -> bool:
    """Whether two decoded JSON values are the same value: the same types
    (a boolean is not a number, an integer not a float), keys, and items."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) or isinstance(b, (int, float)):
        return type(a) is type(b) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_values_equal(a[k], b[k]) for k in a)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(json_values_equal(x, y) for x, y in zip(a, b))
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return False


def stored_value(payload: bytes) -> Any:
    """The JSON value an Item's payload holds, as the node's data route
    serves it: the parsed JSON, or ``{"hex": <payload hex>}`` for a payload
    that isn't JSON."""
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"hex": payload.hex()}


def _value_matches(expected: Any, payload: bytes) -> bool:
    """Whether ``expected`` is an Item's payload: the same bytes, or (for
    anything but bytes) the same JSON value the payload holds."""
    if isinstance(expected, (bytes, bytearray)):
        return bytes(expected) == payload
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    return json_values_equal(expected, decoded)


def _path_of(path: Union[None, PathQueryData, List[PathSegment]]) -> Optional[List[PathSegment]]:
    if isinstance(path, PathQueryData):
        return path.path
    return path


def _entry(item: ProvenItem) -> Dict[str, Any]:
    return {"path": item.path, "key": item.key, "value": item.value, "element": item.element}


class GroveDBProofVerifier:
    """
    GroveDB proof verifier using a pure Python implementation.

    Every check is local and synchronous; the ``async`` methods are kept for
    callers that await them.
    """

    def __init__(self, options: Optional[ProofVerificationOptions] = None):
        """
        Initialize proof verifier with options.

        Args:
            options: Verification options
        """
        self.options = options or ProofVerificationOptions()

    def _items(
        self, proof_hex: str, path: Optional[List[PathSegment]]
    ) -> Tuple[Optional[str], List[ProvenItem], Optional[str]]:
        """The root and the Items a proof proves at ``path``, or an error."""
        if not path:
            return None, [], "A path is required: a proof binds values only at the path it was made at"
        if not proof_hex:
            return None, [], "Empty proof provided"
        try:
            proof_bytes = bytes.fromhex(proof_hex[2:] if proof_hex.startswith("0x") else proof_hex)
        except ValueError as e:
            return None, [], f"Failed to decode hex: {e}"
        if not proof_bytes:
            return None, [], "Empty proof provided"
        try:
            expected = (
                hex_to_hash(self.options.expected_root_hash)
                if self.options.expected_root_hash else None
            )
            root_hash, items = verify_items_at_path(proof_bytes, path, expected)
        except GroveDBVerificationError as e:
            return None, [], str(e)
        except Exception as e:
            return None, [], f"Verification failed: {e}"
        return hash_to_hex(root_hash), items, None

    def verify_item(
        self, proof_hex: str, key: Union[str, bytes], value: Any, path: List[PathSegment]
    ) -> ProofVerificationResult:
        """
        Verify that a proof proves ``value`` as the Item at ``path`` and
        ``key``.

        Valid only when the proof descends to ``path``, proves an Item at
        exactly ``key`` there whose bytes are bound to the root, and that
        Item's payload is ``value``: the same bytes when ``value`` is
        ``bytes``, otherwise the same JSON value (see ``json_values_equal``).
        A proof of another key or path, or a lone root hash, is invalid.

        Args:
            proof_hex: Hex-encoded proof bytes
            key: The item's key
            value: The item's payload (bytes) or the JSON value it holds
            path: The path the key is at (``str`` or ``bytes`` segments;
                ``subgrove_data_path(id)`` for a subgrove's data)
        """
        if key is None or (isinstance(key, (str, bytes)) and not key):
            return ProofVerificationResult(valid=False, error="A key is required")
        root_hash, items, error = self._items(proof_hex, path)
        if error:
            return ProofVerificationResult(valid=False, error=error)
        key_bytes = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        item = next((i for i in items if i.key == key_bytes), None)
        if item is None:
            return ProofVerificationResult(
                valid=False, root_hash=root_hash,
                error=f"The proof does not prove an Item at key {key!r} under the path",
            )
        if not _value_matches(value, item.value):
            return ProofVerificationResult(
                valid=False, root_hash=root_hash, results=[_entry(item)],
                error=f"The value given is not the Item the proof proves at key {key!r}",
            )
        return ProofVerificationResult(valid=True, root_hash=root_hash, results=[_entry(item)])

    def verify_documents(
        self, proof_hex: str, documents: List[Any], path: List[PathSegment]
    ) -> ProofVerificationResult:
        """
        Verify that each document is the payload of an Item the proof proves
        at ``path``, each Item matched once.

        This proves that each document is stored at ``path`` under the
        returned root. It does not prove that a query's filter, order,
        offset, or limit were applied, or that no document was left out.

        Args:
            proof_hex: Hex-encoded proof bytes
            documents: The documents, each the JSON value (or payload bytes)
                of an Item
            path: The path the query was made at
        """
        root_hash, items, error = self._items(proof_hex, path)
        if error:
            return ProofVerificationResult(valid=False, error=error)
        unmatched = list(items)
        for index, document in enumerate(documents):
            match = next((i for i in unmatched if _value_matches(document, i.value)), None)
            if match is None:
                return ProofVerificationResult(
                    valid=False, root_hash=root_hash,
                    error=f"Document {index} is not an Item the proof proves under the path",
                )
            unmatched.remove(match)
        return ProofVerificationResult(
            valid=True, root_hash=root_hash, results=[_entry(i) for i in items]
        )

    async def verify_query_proof(
        self,
        proof_hex: str,
        documents: List[Any],
        path_query: Union[None, PathQueryData, List[PathSegment]] = None,
    ) -> ProofVerificationResult:
        """
        Verify that each document is an Item the proof proves at the query's
        path (see ``verify_documents``). Without a path the result is invalid.

        Args:
            proof_hex: Hex-encoded proof bytes
            documents: The documents the query returned
            path_query: The query's path (a ``PathQueryData`` or a list of
                segments)
        """
        return self.verify_documents(proof_hex, documents, _path_of(path_query))

    async def verify_item_proof(
        self,
        proof_hex: str,
        key: Union[str, bytes],
        value: Any,
        path: List[PathSegment],
    ) -> ProofVerificationResult:
        """
        Verify that a proof proves ``value`` as the Item at ``path`` and
        ``key`` (see ``verify_item``).
        """
        return self.verify_item(proof_hex, key, value, path)

    def extract_root_hash(self, proof_hex: str) -> str:
        """
        Compute the root hash a proof reproduces. It binds no key or value.

        Args:
            proof_hex: Hex-encoded proof bytes

        Returns:
            The root hash (hex-encoded)

        Raises:
            ValueError: If verification fails
        """
        try:
            proof_bytes = bytes.fromhex(proof_hex.replace('0x', ''))
            root_hash = quick_verify(proof_bytes)
            return hash_to_hex(root_hash)
        except GroveDBVerificationError as e:
            raise ValueError(f"Failed to extract root hash: {str(e)}")
        except Exception as e:
            raise ValueError(f"Failed to extract root hash: {str(e)}")


# Global verifier instance
_global_verifier: Optional[GroveDBProofVerifier] = None


def configure_proof_verification(options: ProofVerificationOptions) -> None:
    """
    Configure the global proof verifier.

    Args:
        options: Proof verification options
    """
    global _global_verifier
    _global_verifier = GroveDBProofVerifier(options)


def get_verifier() -> GroveDBProofVerifier:
    """Get the current proof verifier instance."""
    global _global_verifier
    if not _global_verifier:
        _global_verifier = GroveDBProofVerifier()
    return _global_verifier


class ProofVerifier:
    """Synchronous proof verification with the global verifier (callable
    inside or outside a running event loop)."""

    @staticmethod
    def verify_query_proof(
        proof_hex: str,
        documents: List[Any],
        path: List[PathSegment],
    ) -> ProofVerificationResult:
        """Verify that each document is an Item the proof proves at ``path``
        (see ``GroveDBProofVerifier.verify_documents``)."""
        return get_verifier().verify_documents(proof_hex, documents, path)

    @staticmethod
    def verify_item_proof(
        proof_hex: str,
        key: Union[str, bytes],
        value: Any,
        path: List[PathSegment],
    ) -> ProofVerificationResult:
        """Verify that a proof proves ``value`` as the Item at ``path`` and
        ``key`` (see ``GroveDBProofVerifier.verify_item``)."""
        return get_verifier().verify_item(proof_hex, key, value, path)

    @staticmethod
    def verify_query_response(
        response: QueryResponse, path: List[PathSegment]
    ) -> ProofVerificationResult:
        """Verify that each document of a query response is an Item its proof
        proves at ``path`` (see ``GroveDBProofVerifier.verify_documents``)."""
        if not response.proof:
            return ProofVerificationResult(
                valid=False,
                error="Query response does not contain proof data"
            )

        return ProofVerifier.verify_query_proof(response.proof, response.documents, path)


async def verify_query_proof(
    proof_hex: str,
    documents: List[Any],
    path: List[PathSegment],
) -> str:
    """
    Verify that each document is an Item the proof proves at ``path``, and
    return the root hash (see ``GroveDBProofVerifier.verify_documents``).

    Raises:
        ProofVerificationError: If verification fails
    """
    result = get_verifier().verify_documents(proof_hex, documents, path)
    if not result.valid or result.error:
        raise ProofVerificationError(result.error or "Proof verification failed")
    return result.root_hash


async def verify_item_proof(
    proof_hex: str,
    key: Union[str, bytes],
    value: Any,
    path: List[PathSegment],
) -> str:
    """
    Verify that a proof proves ``value`` as the Item at ``path`` and
    ``key``, and return the root hash (see ``GroveDBProofVerifier.verify_item``).

    Raises:
        ProofVerificationError: If verification fails
    """
    result = get_verifier().verify_item(proof_hex, key, value, path)
    if not result.valid or result.error:
        raise ProofVerificationError(result.error or "Proof verification failed")
    return result.root_hash


def verify_query_response(response: QueryResponse, path: List[PathSegment]) -> str:
    """
    Verify that each document of a query response is an Item its proof
    proves at ``path``, and return the root hash.

    Raises:
        ProofVerificationError: If verification fails
    """
    result = ProofVerifier.verify_query_response(response, path)
    if not result.valid or result.error:
        raise ProofVerificationError(result.error or "Proof verification failed")
    return result.root_hash


async def extract_root_hash_from_proof(proof_hex: str) -> str:
    """
    Extract root hash from proof. It binds no key or value.

    Args:
        proof_hex: Hex-encoded proof

    Returns:
        The extracted root hash

    Raises:
        ProofVerificationError: If extraction fails
    """
    verifier = get_verifier()
    try:
        return verifier.extract_root_hash(proof_hex)
    except ValueError as e:
        raise ProofVerificationError(str(e))


def verify_proof_quick(proof_hex: str) -> str:
    """
    Quick verification - compute root hash from proof. It binds no key or
    value.

    Args:
        proof_hex: Hex-encoded proof bytes

    Returns:
        Root hash as hex string

    Raises:
        ProofVerificationError: If verification fails
    """
    try:
        proof_bytes = bytes.fromhex(proof_hex.replace('0x', ''))
        root_hash = quick_verify(proof_bytes)
        return hash_to_hex(root_hash)
    except GroveDBVerificationError as e:
        raise ProofVerificationError(str(e))
    except Exception as e:
        raise ProofVerificationError(f"Proof verification failed: {str(e)}")


def verify_proof_with_expected_root(proof_hex: str, expected_root_hash: str) -> bool:
    """
    Verify a proof matches an expected root hash. It binds no key or value:
    use ``verify_item_proof`` to check a value.

    Args:
        proof_hex: Hex-encoded proof bytes
        expected_root_hash: Expected root hash (hex)

    Returns:
        True if proof is valid and matches expected root hash

    Raises:
        ProofVerificationError: If verification fails
    """
    try:
        proof_bytes = bytes.fromhex(proof_hex.replace('0x', ''))
        expected_hash = hex_to_hash(expected_root_hash)
        verify_proof_against_root(proof_bytes, expected_hash)
        return True
    except GroveDBVerificationError as e:
        raise ProofVerificationError(str(e))
    except Exception as e:
        raise ProofVerificationError(f"Proof verification failed: {str(e)}")
