"""Authentication utilities for Willow SDK."""

import os
import time
import hashlib
from typing import Dict, Literal, Optional, Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import coincurve
from eth_utils import keccak
from .types import DidDocument, PublicKey
from .utils import generate_id


SignatureAlgorithm = Literal["Ed25519", "secp256k1"]


def generate_did(algorithm: SignatureAlgorithm = "Ed25519") -> Dict[str, Union[str, DidDocument]]:
    """
    Generate a new DID with keypair.

    Args:
        algorithm: Signature algorithm to use ("Ed25519" or "secp256k1")

    Returns:
        Dictionary containing:
        - did: The generated DID string
        - private_key: Hex-encoded private key
        - public_key: Hex-encoded public key
        - public_key_id: Public key identifier
        - did_document: The DID document
    """
    if algorithm == "Ed25519":
        # Generate Ed25519 keypair using cryptography library
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
    elif algorithm == "secp256k1":
        # Generate secp256k1 keypair (Ethereum compatible)
        private_key_bytes = os.urandom(32)
        private_key = coincurve.PrivateKey(private_key_bytes)
        public_key_bytes = private_key.public_key.format(compressed=False)[1:]  # Remove 0x04 prefix
        
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    # Create DID
    did_suffix = public_key_bytes[:8].hex()
    did = f"did:willow:{algorithm.lower()}:{did_suffix}"
    public_key_id = f"{did}#key-1"
    
    # Create DID document
    did_document = DidDocument(
        id=did,
        public_keys=[
            PublicKey(
                id=public_key_id,
                key_type=f"{algorithm}VerificationKey2020",
                public_key_hex=public_key_bytes.hex()
            )
        ],
        created=int(time.time()),
        updated=int(time.time())
    )
    
    return {
        "did": did,
        "private_key": private_key_bytes.hex(),
        "public_key": public_key_bytes.hex(),
        "public_key_id": public_key_id,
        "did_document": did_document,
        "algorithm": algorithm
    }


def sign_challenge(
    message: str,
    private_key_hex: str,
    algorithm: SignatureAlgorithm = "Ed25519"
) -> str:
    """
    Sign a challenge message.

    Args:
        message: The message to sign
        private_key_hex: Hex-encoded private key
        algorithm: Signature algorithm

    Returns:
        Hex-encoded signature
    """
    message_bytes = message.encode('utf-8')
    private_key_bytes = bytes.fromhex(private_key_hex)

    if algorithm == "Ed25519":
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        signature = private_key.sign(message_bytes)
        
    elif algorithm == "secp256k1":
        # Hash message with Keccak256 (Ethereum style)
        message_hash = keccak(message_bytes)
        private_key = coincurve.PrivateKey(private_key_bytes)
        signature_obj = private_key.sign(message_hash, hasher=None)
        signature = signature_obj.serialize_compact()
        
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    return signature.hex()


def verify_signature(
    message: str,
    signature_hex: str,
    public_key_hex: str,
    algorithm: SignatureAlgorithm = "Ed25519"
) -> bool:
    """
    Verify a signature.

    Args:
        message: The original message
        signature_hex: Hex-encoded signature
        public_key_hex: Hex-encoded public key
        algorithm: Signature algorithm

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        message_bytes = message.encode('utf-8')
        signature_bytes = bytes.fromhex(signature_hex)
        public_key_bytes = bytes.fromhex(public_key_hex)

        if algorithm == "Ed25519":
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature_bytes, message_bytes)
            return True
            
        elif algorithm == "secp256k1":
            # Hash message with Keccak256
            message_hash = keccak(message_bytes)
            # Add 0x04 prefix for uncompressed public key
            full_public_key = b'\x04' + public_key_bytes
            public_key = coincurve.PublicKey(full_public_key)
            return public_key.verify(signature_bytes, message_hash, hasher=None)
            
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
    except Exception:
        return False


def detect_algorithm_from_did(did: str) -> SignatureAlgorithm:
    """
    Detect signature algorithm from DID.

    Args:
        did: The DID string

    Returns:
        The detected algorithm
    """
    if "ed25519" in did.lower():
        return "Ed25519"
    elif "secp256k1" in did.lower():
        return "secp256k1"
    else:
        # Default to Ed25519
        return "Ed25519"


# Alias for sign_challenge - used by consensus client
sign_message = sign_challenge