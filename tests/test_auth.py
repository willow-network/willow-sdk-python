"""Tests for authentication module."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from willow.auth import (
    derive_did,
    detect_algorithm_from_did,
    generate_did,
    sign_challenge,
    verify_signature,
)


class TestGenerateDid:
    """Test DID generation."""
    
    def test_generate_ed25519_did(self):
        """Test Ed25519 DID generation."""
        result = generate_did("Ed25519")

        assert result["did"].startswith("did:willow:z")
        assert len(result["private_key"]) == 64  # 32 bytes hex
        assert len(result["public_key"]) == 64   # 32 bytes hex
        assert result["public_key_id"] == f"{result['did']}#key-1"
        assert result["algorithm"] == "Ed25519"
        
        # Verify DID document
        did_doc = result["did_document"]
        assert did_doc.id == result["did"]
        assert len(did_doc.public_keys) == 1
        assert did_doc.public_keys[0].key_type == "Ed25519VerificationKey2020"
    
    def test_generate_secp256k1_did(self):
        """Test secp256k1 DID generation."""
        result = generate_did("secp256k1")

        assert result["did"].startswith("did:willow:z")
        assert len(result["private_key"]) == 64  # 32 bytes hex
        assert len(result["public_key"]) == 128  # 64 bytes hex (uncompressed)
        assert result["algorithm"] == "secp256k1"
        
        # Verify DID document
        did_doc = result["did_document"]
        assert did_doc.public_keys[0].key_type == "secp256k1VerificationKey2020"
    
    def test_generate_unique_dids(self):
        """Test that generated DIDs are unique."""
        did1 = generate_did()
        did2 = generate_did()

        assert did1["did"] != did2["did"]
        assert did1["private_key"] != did2["private_key"]
        assert did1["public_key"] != did2["public_key"]


class TestSelfCertifyingDid:
    """Test the self-certifying DID derivation.

    did = "did:willow:z" + base58btc( SHA3-256( multicodec_prefix || pubkey ) )
    """

    def test_ed25519_acceptance_vector(self):
        """MANDATORY: this exact vector is what the chain's RegisterDid enforces.

        If this fails, the derivation is wrong (e.g. Keccak-256 instead of
        FIPS-202 SHA3-256, wrong multicodec prefix, or bad base58btc).
        """
        public_key_hex = (
            "a003201e65e47d578ad9bb17cb1d3590e9f504f55eac6ee40002e3ab9517c49c"
        )
        expected = "did:willow:zDZ1Qqspppayjd9LF3Pkebq64Fa2PuK8zFQDDc11citB2"

        derived = derive_did(public_key_hex, "Ed25519")

        assert derived["did"] == expected
        assert derived["public_key_id"] == f"{expected}#key-1"

    def test_derive_accepts_bytes_and_hex(self):
        """derive_did accepts both raw bytes and a hex string."""
        public_key_hex = (
            "a003201e65e47d578ad9bb17cb1d3590e9f504f55eac6ee40002e3ab9517c49c"
        )
        from_hex = derive_did(public_key_hex, "Ed25519")
        from_bytes = derive_did(bytes.fromhex(public_key_hex), "Ed25519")
        assert from_hex == from_bytes

    def test_did_is_derived_from_key(self):
        """The generated DID must equal the derivation of its own public key."""
        result = generate_did("Ed25519")
        assert result["did"] == derive_did(result["public_key"], "Ed25519")["did"]

    def test_secp256k1_did_is_derived_from_compressed_key(self):
        """secp256k1 DID is derived from the 33-byte compressed public key."""
        result = generate_did("secp256k1")
        # generate_did stores the 64-byte uncompressed key; derive_did must
        # normalise it to compressed and reproduce the same id.
        assert result["did"] == derive_did(result["public_key"], "secp256k1")["did"]
        assert result["did"].startswith("did:willow:z")

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            derive_did("aa" * 32, "RSA")


class TestSignChallenge:
    """Test challenge signing."""
    
    def test_sign_with_ed25519(self):
        """Test Ed25519 signature."""
        message = "test message"
        private_key = "a" * 64  # 32 bytes hex
        
        signature = sign_challenge(message, private_key, "Ed25519")
        
        assert isinstance(signature, str)
        assert len(signature) == 128  # 64 bytes hex
    
    def test_sign_with_secp256k1(self):
        """Test secp256k1 signature."""
        message = "test message"
        private_key = "b" * 64  # 32 bytes hex
        
        signature = sign_challenge(message, private_key, "secp256k1")
        
        assert isinstance(signature, str)
        assert len(signature) >= 128  # At least 64 bytes hex
    
    def test_invalid_algorithm(self):
        """Test invalid algorithm."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            sign_challenge("message", "a" * 64, "RSA")
    
    def test_deterministic_ed25519(self):
        """Test that Ed25519 signatures are deterministic."""
        message = "test"
        key = "c" * 64
        
        sig1 = sign_challenge(message, key, "Ed25519")
        sig2 = sign_challenge(message, key, "Ed25519")
        
        assert sig1 == sig2


class TestVerifySignature:
    """Test signature verification."""
    
    def test_verify_ed25519_valid(self):
        """Test valid Ed25519 signature verification."""
        # Generate real keypair via cryptography (same library the SDK uses).
        signing_key = Ed25519PrivateKey.from_private_bytes(b"a" * 32)
        from cryptography.hazmat.primitives import serialization
        verifying_key_bytes = signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        message = "test message"
        signature = signing_key.sign(message.encode())

        is_valid = verify_signature(
            message,
            signature.hex(),
            verifying_key_bytes.hex(),
            "Ed25519",
        )

        assert is_valid is True

    def test_verify_ed25519_invalid(self):
        """Test invalid Ed25519 signature verification."""
        signing_key = Ed25519PrivateKey.from_private_bytes(b"a" * 32)
        from cryptography.hazmat.primitives import serialization
        verifying_key_bytes = signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        message = "test message"
        invalid_signature = "0" * 128  # Invalid signature

        is_valid = verify_signature(
            message,
            invalid_signature,
            verifying_key_bytes.hex(),
            "Ed25519",
        )

        assert is_valid is False
    
    def test_verify_secp256k1_valid(self):
        """Test valid secp256k1 signature verification."""
        # Use the actual sign_challenge function
        did_info = generate_did("secp256k1")
        message = "test message"
        
        signature = sign_challenge(message, did_info["private_key"], "secp256k1")
        
        is_valid = verify_signature(
            message,
            signature,
            did_info["public_key"],
            "secp256k1"
        )
        
        assert is_valid is True
    
    def test_verify_wrong_message(self):
        """Test verification with wrong message."""
        did_info = generate_did("Ed25519")
        
        signature = sign_challenge("message1", did_info["private_key"], "Ed25519")
        
        is_valid = verify_signature(
            "message2",  # Different message
            signature,
            did_info["public_key"],
            "Ed25519"
        )
        
        assert is_valid is False
    
    def test_verify_malformed_inputs(self):
        """Test verification with malformed inputs."""
        # Invalid hex
        assert verify_signature("msg", "xyz", "abc", "Ed25519") is False
        
        # Wrong length
        assert verify_signature("msg", "aa", "bb", "Ed25519") is False


class TestDetectAlgorithm:
    """Test algorithm detection from DID."""
    
    def test_detect_ed25519(self):
        """Test Ed25519 detection."""
        assert detect_algorithm_from_did("did:willow:ed25519:abc123") == "Ed25519"
        assert detect_algorithm_from_did("did:willow:Ed25519:abc123") == "Ed25519"
    
    def test_detect_secp256k1(self):
        """Test secp256k1 detection."""
        assert detect_algorithm_from_did("did:willow:secp256k1:abc123") == "secp256k1"
        assert detect_algorithm_from_did("did:willow:Secp256k1:abc123") == "secp256k1"
    
    def test_detect_default(self):
        """Test default algorithm detection."""
        assert detect_algorithm_from_did("did:willow:unknown:abc123") == "Ed25519"
        assert detect_algorithm_from_did("did:willow:test:abc123") == "Ed25519"


class TestIntegration:
    """Integration tests for auth flow."""
    
    def test_full_auth_flow_ed25519(self):
        """Test complete authentication flow with Ed25519."""
        # Generate DID
        did_info = generate_did("Ed25519")
        
        # Create challenge
        challenge = f"challenge_{int(1234567890)}"
        timestamp = 1234567890
        message = f"{did_info['did']}:{challenge}:{timestamp}"
        
        # Sign challenge
        signature = sign_challenge(message, did_info["private_key"], "Ed25519")
        
        # Verify signature
        is_valid = verify_signature(
            message,
            signature,
            did_info["public_key"],
            "Ed25519"
        )
        
        assert is_valid is True
    
    def test_full_auth_flow_secp256k1(self):
        """Test complete authentication flow with secp256k1."""
        # Generate DID
        did_info = generate_did("secp256k1")
        
        # Create challenge
        challenge = f"challenge_{int(1234567890)}"
        timestamp = 1234567890
        message = f"{did_info['did']}:{challenge}:{timestamp}"
        
        # Sign challenge
        signature = sign_challenge(message, did_info["private_key"], "secp256k1")
        
        # Verify signature
        is_valid = verify_signature(
            message,
            signature,
            did_info["public_key"],
            "secp256k1"
        )
        
        assert is_valid is True