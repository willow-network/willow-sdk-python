"""Tests for GroveDB proof verification in Python SDK."""

import pytest
from willow.proof import (
    GroveDBProofVerifier,
    ProofVerificationOptions,
    ProofVerificationResult,
    ProofVerifier,
    verify_proof_quick,
    verify_proof_with_expected_root,
    configure_proof_verification,
)
from willow.errors import ProofVerificationError
from willow.grovedb import (
    verify_grovedb_proof,
    verify_proof_against_root,
    quick_verify,
    GroveDBVerificationError,
)


class TestGroveDBProofVerifier:
    """Test the GroveDBProofVerifier class."""

    def test_create_verifier_default_options(self):
        """Test creating a verifier with default options."""
        verifier = GroveDBProofVerifier()
        assert verifier.options.expected_root_hash is None
        assert verifier.options.deserialize_elements is True
        assert verifier.options.limit is None

    def test_create_verifier_with_options(self):
        """Test creating a verifier with custom options."""
        options = ProofVerificationOptions(
            expected_root_hash="abc123",
            deserialize_elements=False,
            limit=100
        )
        verifier = GroveDBProofVerifier(options)
        assert verifier.options.expected_root_hash == "abc123"
        assert verifier.options.deserialize_elements is False
        assert verifier.options.limit == 100

    @pytest.mark.asyncio
    async def test_reject_empty_proof(self):
        """Test that empty proofs are rejected."""
        verifier = GroveDBProofVerifier()
        result = await verifier.verify_query_proof("", [])

        assert result.valid is False
        assert "Empty proof" in result.error

    @pytest.mark.asyncio
    async def test_reject_invalid_hex(self):
        """Test that invalid hex strings are rejected."""
        verifier = GroveDBProofVerifier()
        result = await verifier.verify_query_proof("invalid-hex", [])

        assert result.valid is False
        assert "Failed to decode hex" in result.error

    @pytest.mark.asyncio
    async def test_reject_malformed_proof(self):
        """Test that malformed proofs are rejected."""
        verifier = GroveDBProofVerifier()
        # Random bytes that don't form a valid GroveDB proof
        result = await verifier.verify_query_proof("deadbeef" * 10, [])

        assert result.valid is False
        assert result.error is not None


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_verify_proof_quick_invalid(self):
        """Test quick verification with invalid proof."""
        with pytest.raises(ProofVerificationError):
            verify_proof_quick("deadbeef")

    def test_verify_proof_quick_empty(self):
        """Test quick verification with empty proof."""
        with pytest.raises(ProofVerificationError):
            verify_proof_quick("")

    def test_verify_proof_with_expected_root_invalid(self):
        """Test verification against expected root with invalid proof."""
        with pytest.raises(ProofVerificationError):
            verify_proof_with_expected_root("deadbeef", "a" * 64)


class TestConfiguration:
    """Test global configuration."""

    def test_configure_proof_verification(self):
        """Test configuring global proof verification."""
        options = ProofVerificationOptions(
            expected_root_hash="test_hash",
            limit=50
        )

        configure_proof_verification(options)
        # Configuration should not raise errors
        assert True


class TestProofVerificationResult:
    """Test ProofVerificationResult dataclass."""

    def test_result_bool_valid(self):
        """Test that valid result is truthy."""
        result = ProofVerificationResult(valid=True, root_hash="abc")
        assert bool(result) is True

    def test_result_bool_invalid(self):
        """Test that invalid result is falsy."""
        result = ProofVerificationResult(valid=False, error="test error")
        assert bool(result) is False

    def test_result_with_results(self):
        """Test result with proved key-value pairs."""
        result = ProofVerificationResult(
            valid=True,
            root_hash="abc",
            results=[{"path": [], "key": b"test", "value": b"data"}]
        )
        assert result.results is not None
        assert len(result.results) == 1
