"""
Light Client Verification

Basic header checks (no commit signature verification: see
``HeaderVerifier``) and GroveDB proof verification against a root.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from .types import (
    LightBlock, Header, ValidatorSet,
    TrustThreshold, VerificationResult, LightClientError, QueryProof
)
from ..errors import UnsupportedError
from ..grovedb import (
    quick_verify, verify_items_at_path, verify_item_at_path, hash_equals, GroveDBVerificationError,
)


#: Why ``HeaderVerifier.verify_header`` reports no header verified.
HEADER_NOT_VERIFIED = (
    "Header not verified: this SDK does not verify CometBFT commit signatures, the "
    "validator set against validators_hash, or the header against the commit's block ID"
)


class HeaderVerifier:
    """Checks a header's basic fields. It does not verify headers.

    Verifying a CometBFT header takes the header's hash checked against the
    commit's block ID, the validator set checked against ``validators_hash``
    (and against the trusted one), and each commit signature checked over
    CometBFT's canonical vote encoding. The SDK does none of these, so
    ``verify_header`` never reports a header verified.
    """

    def __init__(self, chain_id: str, trust_threshold: TrustThreshold):
        """Initialize header verifier with chain parameters."""
        self.chain_id = chain_id
        self.trust_threshold = trust_threshold

    def verify_header(
        self,
        untrusted_header: LightBlock,
        trusted_header: Optional[LightBlock] = None,
        trusted_validators: Optional[ValidatorSet] = None,
        max_clock_drift_secs: int = 10
    ) -> VerificationResult:
        """
        Check an untrusted header's basic fields (chain ID, height, time, and
        its height, time, and validator set hash after ``trusted_header``).

        It never succeeds: the SDK does not verify commit signatures, so
        nothing here shows that the chain's validators signed the header. A
        header that passes these checks fails with ``HEADER_NOT_VERIFIED``.

        Args:
            untrusted_header: Header to check
            trusted_header: A trusted header it follows
            trusted_validators: Unused
            max_clock_drift_secs: Maximum allowed clock drift

        Returns:
            A failed VerificationResult, whose ``error`` says why
        """
        try:
            self._validate_basic_header(untrusted_header.header, max_clock_drift_secs)
            if trusted_header is not None:
                self._verify_sequential(untrusted_header, trusted_header)
                self._verify_validator_set_transition(untrusted_header, trusted_header)
        except Exception as e:
            return VerificationResult(
                success=False,
                error=str(e),
                height=getattr(untrusted_header.header, 'height', None)
            )
        return VerificationResult(
            success=False,
            error=HEADER_NOT_VERIFIED,
            height=untrusted_header.header.height,
        )

    def _validate_basic_header(self, header: Header, max_clock_drift_secs: int):
        """Validate basic header properties."""
        # Chain ID must match
        if header.chain_id != self.chain_id:
            raise LightClientError(f"Chain ID mismatch: {header.chain_id} != {self.chain_id}")
        
        # Height must be positive
        if header.height <= 0:
            raise LightClientError(f"Invalid height: {header.height}")
        
        # Time must be reasonable (not too far in future/past)
        now = datetime.now(timezone.utc)
        time_diff = abs((header.time - now).total_seconds())
        if time_diff > max_clock_drift_secs:
            raise LightClientError(f"Clock drift too large: {time_diff}s > {max_clock_drift_secs}s")
    
    def _verify_sequential(self, untrusted: LightBlock, trusted: LightBlock):
        """Verify sequential header progression."""
        # Height must increase by exactly 1
        if untrusted.header.height != trusted.header.height + 1:
            raise LightClientError(
                f"Non-sequential height: {untrusted.header.height} != {trusted.header.height + 1}"
            )

        # Time must progress forward
        if untrusted.header.time <= trusted.header.time:
            raise LightClientError("Time did not progress forward")

    def _verify_validator_set_transition(self, untrusted: LightBlock, trusted: LightBlock):
        """Verify validator set hash transition."""
        # The untrusted header's validators_hash should match the trusted next_validators_hash
        if untrusted.header.validators_hash != trusted.header.next_validators_hash:
            raise LightClientError("Validator set transition hash mismatch")


class ProofVerifier:
    """Verifies GroveDB proofs against trusted headers."""
    
    def __init__(self):
        """Initialize proof verifier."""
        pass
    
    def verify_query_proof(
        self,
        proof: QueryProof,
        trusted_app_hash: bytes,
        query_result: Optional[List[bytes]] = None
    ) -> VerificationResult:
        """
        Verify a GroveDB query proof against a trusted app hash.

        Succeeds when the proof reproduces ``trusted_app_hash`` and, for each
        entry of ``query_result`` (``proof.query_result`` when not given),
        the proof proves an Item with that payload at the query's path
        (``proof.path_query["path"]``), each Item matched once. With no
        ``query_result`` it binds no value: it shows only that the proof's
        root is the trusted one.

        Args:
            proof: Query proof containing proof bytes and metadata
            trusted_app_hash: Trusted app hash from verified header
            query_result: Item payloads the proof must prove at the path

        Returns:
            VerificationResult indicating success/failure
        """
        try:
            # Extract query result from proof if not provided
            if query_result is None:
                query_result = proof.query_result

            if query_result:
                path = _query_path(proof.path_query)
                if not path:
                    return VerificationResult(
                        success=False,
                        error="The query result can't be bound to the proof without the query's path "
                              "(path_query['path'])",
                        height=proof.height
                    )
                _, items = verify_items_at_path(proof.proof, path, trusted_app_hash)
                unmatched = [item.value for item in items]
                for index, payload in enumerate(query_result):
                    if bytes(payload) not in unmatched:
                        return VerificationResult(
                            success=False,
                            error=f"Query result {index} is not an Item the proof proves at the path",
                            height=proof.height
                        )
                    unmatched.remove(bytes(payload))
                return VerificationResult(success=True, height=proof.height)

            # Verify the proof reconstructs to the trusted app hash
            computed_root = self._verify_grovedb_proof(proof.proof, query_result)

            if computed_root != trusted_app_hash:
                return VerificationResult(
                    success=False,
                    error=f"Root hash mismatch: computed {computed_root.hex()} != trusted {trusted_app_hash.hex()}",
                    height=proof.height
                )

            return VerificationResult(
                success=True,
                height=proof.height
            )

        except Exception as e:
            return VerificationResult(
                success=False,
                error=f"Proof verification failed: {str(e)}",
                height=proof.height
            )

    def _verify_grovedb_proof(self, proof_bytes: bytes, query_result: List[bytes]) -> bytes:
        """
        Compute the root hash a GroveDB proof reproduces. It binds no value.

        Args:
            proof_bytes: Raw proof bytes
            query_result: Unused

        Returns:
            Computed root hash (32 bytes)

        Raises:
            LightClientError: If proof verification fails
        """
        try:
            return quick_verify(proof_bytes)
        except GroveDBVerificationError as e:
            raise LightClientError(f"GroveDB proof verification failed: {e}")

    def verify_inclusion_proof(
        self,
        key: bytes,
        value: bytes,
        proof_bytes: bytes,
        trusted_root: bytes,
        path: List[Any],
    ) -> bool:
        """
        Verify that ``key`` holds the Item ``value`` at ``path``.

        True only when the proof reproduces ``trusted_root`` and proves an
        Item at exactly ``path`` and ``key`` whose payload is ``value``.

        Args:
            key: Key to verify
            value: The Item's expected payload
            proof_bytes: GroveDB proof bytes
            trusted_root: Trusted root hash from light client
            path: The key's path (``str`` or ``bytes`` segments)

        Returns:
            True if the proof proves ``value`` at ``path`` and ``key`` under
            ``trusted_root``
        """
        try:
            _, item = verify_item_at_path(proof_bytes, path, key, trusted_root)
            return item.value == bytes(value)
        except Exception:
            return False

    def verify_absence_proof(
        self,
        key: bytes,
        proof_bytes: bytes,
        trusted_root: bytes
    ) -> bool:
        """
        Not supported: raises ``UnsupportedError``.

        A proof's root matching proves nothing about one key; the SDK does
        not check that a proof shows where a key would be with nothing there.
        """
        raise UnsupportedError("Checking that a key is absent is not supported")


def _query_path(path_query: Any) -> Optional[List[bytes]]:
    """A query's path from ``path_query["path"]``: segments as ``str``
    (UTF-8), ``bytes``, or lists of byte values."""
    if not isinstance(path_query, dict) or not isinstance(path_query.get("path"), list):
        return None
    segments = []
    for seg in path_query["path"]:
        if isinstance(seg, str):
            segments.append(seg.encode("utf-8"))
        elif isinstance(seg, (bytes, bytearray)):
            segments.append(bytes(seg))
        elif isinstance(seg, list) and all(isinstance(b, int) and 0 <= b <= 255 for b in seg):
            segments.append(bytes(seg))
        else:
            return None
    return segments
