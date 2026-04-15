"""Authentication utilities for Willow SDK."""

import os
import time
import hashlib
from typing import Dict, Literal, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)
from eth_utils import keccak

from .types import DidDocument, PublicKey
from .utils import generate_id


SignatureAlgorithm = Literal["Ed25519", "secp256k1"]


# ---------------------------------------------------------------------------
# secp256k1 helpers backed by `cryptography` (pure-Python wheel coverage,
# no libsecp256k1 C build required). Formats match the Willow wire protocol:
#
#   - public keys:  64-byte uncompressed (X || Y), no 0x04 prefix
#   - signatures:   64-byte compact (r || s)
#   - message input: the caller pre-hashes (we sign/verify the raw digest)
#
# Previously this module used `coincurve`, which wraps libsecp256k1 and
# has spotty prebuilt-wheel coverage on newer Pythons (e.g. 3.14 on macOS)
# — building from source requires pkg-config and a C toolchain. Switching
# to `cryptography` keeps us aligned with the rest of the SDK (which
# already uses `cryptography` for Ed25519) and avoids the native-build
# failure mode entirely.
# ---------------------------------------------------------------------------


def _secp256k1_public_key_bytes_from_private(private_key_bytes: bytes) -> bytes:
    """Derive a 64-byte uncompressed public key (X || Y) from a 32-byte private key."""
    private_int = int.from_bytes(private_key_bytes, "big")
    private_key = ec.derive_private_key(private_int, ec.SECP256K1())
    pub = private_key.public_key().public_numbers()
    return pub.x.to_bytes(32, "big") + pub.y.to_bytes(32, "big")


def _secp256k1_sign_prehashed(private_key_bytes: bytes, digest: bytes) -> bytes:
    """Sign a 32-byte digest with secp256k1, returning a 64-byte compact (r || s) signature.

    The caller is responsible for hashing (we use Prehashed to tell
    `cryptography` the input is already a digest). SHA256 is passed as the
    declared pre-hash algorithm purely because both SHA256 and Keccak-256
    produce 32-byte outputs and `cryptography` only uses the algorithm to
    validate the input length.
    """
    private_int = int.from_bytes(private_key_bytes, "big")
    private_key = ec.derive_private_key(private_int, ec.SECP256K1())
    signature_der = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(signature_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _secp256k1_verify_prehashed(
    public_key_bytes: bytes, digest: bytes, signature_compact: bytes
) -> bool:
    """Verify a 64-byte compact signature against a 64-byte uncompressed public key.

    `public_key_bytes` must be 64 bytes (X || Y, no 0x04 prefix).
    `signature_compact` must be 64 bytes (r || s).
    """
    if len(public_key_bytes) != 64 or len(signature_compact) != 64:
        return False
    try:
        x = int.from_bytes(public_key_bytes[:32], "big")
        y = int.from_bytes(public_key_bytes[32:], "big")
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1())
        public_key = public_numbers.public_key()
        r = int.from_bytes(signature_compact[:32], "big")
        s = int.from_bytes(signature_compact[32:], "big")
        signature_der = encode_dss_signature(r, s)
        public_key.verify(signature_der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False


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
        public_key_bytes = _secp256k1_public_key_bytes_from_private(private_key_bytes)

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
        # Hash message with Keccak256 (Ethereum style), then sign the digest.
        message_hash = keccak(message_bytes)
        signature = _secp256k1_sign_prehashed(private_key_bytes, message_hash)

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
            # Hash message with Keccak256 to match sign_challenge, then verify.
            message_hash = keccak(message_bytes)
            return _secp256k1_verify_prehashed(
                public_key_bytes, message_hash, signature_bytes
            )

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


def sign_request(
    did: str,
    private_key_hex: str,
    public_key_id: str,
    method: str,
    path: str
) -> Dict[str, str]:
    """
    Sign an HTTP request for per-request authentication.

    Creates a timestamp-based signature over the request method and path,
    returning headers that should be included in the HTTP request.

    Args:
        did: The DID to authenticate as
        private_key_hex: Hex-encoded private key
        public_key_id: Public key ID from DID document
        method: HTTP method (e.g., "GET", "POST")
        path: API path (e.g., "/data/my-subgrove/my-key")

    Returns:
        Dictionary of authentication headers to include in the request
    """
    timestamp = int(time.time())
    message = f"{method}:{path}:{timestamp}"
    algorithm = detect_algorithm_from_did(did)
    signature = sign_challenge(message, private_key_hex, algorithm)
    return {
        "X-DID": did,
        "X-Public-Key-ID": public_key_id,
        "X-Signature": signature,
        "X-Timestamp": str(timestamp),
    }


# Alias for sign_challenge - used by consensus client
sign_message = sign_challenge