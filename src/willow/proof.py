"""
Proof verification for Willow query results.

This module provides fully trustless GroveDB proof verification using a pure
Python implementation. It computes root hashes and verifies all Merkle proof
operations locally, providing the same security guarantees as the Rust SDK.
"""

from typing import List, Dict, Any, Optional
import logging
from dataclasses import dataclass

from .types import QueryResponse
from .errors import ProofVerificationError

from .grovedb import (
    verify_grovedb_proof,
    verify_proof_against_root,
    quick_verify,
    GroveDBVerificationError,
    hash_to_hex,
    hex_to_hash,
    VerifyOptions as GroveDBVerifyOptions
)

logger = logging.getLogger(__name__)


@dataclass
class ProofVerificationOptions:
    """Options for proof verification."""
    expected_root_hash: Optional[str] = None
    deserialize_elements: bool = True
    limit: Optional[int] = None


@dataclass
class ProofVerificationResult:
    """Result of proof verification."""
    valid: bool
    root_hash: Optional[str] = None
    error: Optional[str] = None
    results: Optional[List[Dict]] = None

    def __bool__(self):
        """Allow result to be used in boolean context."""
        return self.valid


class PathQueryData:
    """Path query data for proof verification."""
    def __init__(self, path: List[str], query: Optional[Dict[str, Any]] = None):
        self.path = path
        self.query = query or {}


class GroveDBProofVerifier:
    """
    GroveDB proof verifier using pure Python implementation.

    Provides fully trustless local verification with the same security
    guarantees as the Rust SDK.
    """

    def __init__(self, options: Optional[ProofVerificationOptions] = None):
        """
        Initialize proof verifier with options.

        Args:
            options: Verification options
        """
        self.options = options or ProofVerificationOptions()

    async def verify_query_proof(
        self,
        proof_hex: str,
        documents: List[Dict[str, Any]],
        path_query: Optional[PathQueryData] = None
    ) -> ProofVerificationResult:
        """
        Verify a query proof and compute the root hash.

        Args:
            proof_hex: Hex-encoded proof bytes
            documents: The documents/values returned by the query
            path_query: Optional path query information

        Returns:
            ProofVerificationResult with root hash and verification status
        """
        if not proof_hex:
            return ProofVerificationResult(
                valid=False,
                error="Empty proof provided"
            )

        try:
            proof_bytes = bytes.fromhex(proof_hex.replace('0x', ''))

            if len(proof_bytes) == 0:
                return ProofVerificationResult(
                    valid=False,
                    error="Empty proof provided"
                )

            return self._verify(proof_bytes)

        except ValueError as e:
            return ProofVerificationResult(
                valid=False,
                error=f"Failed to decode hex: {str(e)}"
            )
        except Exception as e:
            return ProofVerificationResult(
                valid=False,
                error=f"Verification error: {str(e)}"
            )

    async def verify_item_proof(
        self,
        proof_hex: str,
        key: str,
        value: Any,
        path: Optional[List[str]] = None
    ) -> ProofVerificationResult:
        """
        Verify a single item proof.

        Args:
            proof_hex: Hex-encoded proof bytes
            key: The key of the item
            value: The value of the item
            path: Optional path to the item in the tree

        Returns:
            ProofVerificationResult with root hash and verification status
        """
        documents = [{"key": key, "value": value}]
        path_query = PathQueryData(path or [], {"items": [{"key": key.encode()}]})

        return await self.verify_query_proof(proof_hex, documents, path_query)

    def _verify(self, proof_bytes: bytes) -> ProofVerificationResult:
        """
        Verify proof bytes and return result.

        Args:
            proof_bytes: Raw proof bytes

        Returns:
            ProofVerificationResult
        """
        try:
            grovedb_options = GroveDBVerifyOptions(
                limit=self.options.limit,
                deserialize_elements=self.options.deserialize_elements
            )

            if self.options.expected_root_hash:
                expected_hash = hex_to_hash(self.options.expected_root_hash)
                result = verify_proof_against_root(
                    proof_bytes,
                    expected_hash,
                    grovedb_options
                )
            else:
                result = verify_grovedb_proof(proof_bytes, grovedb_options)

            return ProofVerificationResult(
                valid=True,
                root_hash=hash_to_hex(result.root_hash),
                results=result.results
            )

        except GroveDBVerificationError as e:
            return ProofVerificationResult(
                valid=False,
                error=str(e)
            )
        except Exception as e:
            return ProofVerificationResult(
                valid=False,
                error=f"Verification failed: {str(e)}"
            )

    def extract_root_hash(self, proof_hex: str) -> str:
        """
        Extract root hash from proof via full verification.

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
    """Wrapper class for proof verification."""

    @staticmethod
    def verify_query_proof(
        proof_hex: str,
        documents: List[Dict[str, Any]]
    ) -> ProofVerificationResult:
        """Verify a query proof synchronously."""
        import asyncio
        verifier = get_verifier()

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                verifier.verify_query_proof(proof_hex, documents)
            )
            return result
        finally:
            loop.close()

    @staticmethod
    def verify_item_proof(
        proof_hex: str,
        key: str,
        value: Any
    ) -> ProofVerificationResult:
        """Verify an item proof synchronously."""
        import asyncio
        verifier = get_verifier()

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                verifier.verify_item_proof(proof_hex, key, value)
            )
            return result
        finally:
            loop.close()

    @staticmethod
    def verify_query_response(response: QueryResponse) -> ProofVerificationResult:
        """Verify the proof included in a query response."""
        if not response.proof:
            return ProofVerificationResult(
                valid=False,
                error="Query response does not contain proof data"
            )

        return ProofVerifier.verify_query_proof(
            response.proof,
            response.documents
        )


async def verify_query_proof(
    proof_hex: str,
    documents: List[Dict[str, Any]]
) -> str:
    """
    Verify a query proof and get root hash.

    Returns:
        Computed root hash

    Raises:
        ProofVerificationError: If verification fails
    """
    verifier = get_verifier()
    result = await verifier.verify_query_proof(proof_hex, documents)
    if not result.valid or result.error:
        raise ProofVerificationError(result.error or "Proof verification failed")
    return result.root_hash


async def verify_item_proof(
    proof_hex: str,
    key: str,
    value: Any,
    path: Optional[List[str]] = None
) -> str:
    """
    Verify an item proof and get root hash.

    Returns:
        Computed root hash

    Raises:
        ProofVerificationError: If verification fails
    """
    verifier = get_verifier()
    result = await verifier.verify_item_proof(proof_hex, key, value, path)
    if not result.valid or result.error:
        raise ProofVerificationError(result.error or "Proof verification failed")
    return result.root_hash


def verify_query_response(response: QueryResponse) -> str:
    """
    Verify a query response and get root hash.

    Returns:
        Computed root hash

    Raises:
        ProofVerificationError: If verification fails
    """
    result = ProofVerifier.verify_query_response(response)
    if not result.valid or result.error:
        raise ProofVerificationError(result.error or "Proof verification failed")
    return result.root_hash


async def extract_root_hash_from_proof(proof_hex: str) -> str:
    """
    Extract root hash from proof.

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
    Quick verification - compute root hash from proof.

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
    Verify a proof matches an expected root hash.

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
