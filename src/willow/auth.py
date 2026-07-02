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
# Self-certifying DID derivation.
#
# Willow DIDs are bound to the public key, not chosen. The chain's RegisterDid
# check recomputes this exact derivation and rejects any id that does not match:
#
#     did = "did:willow:z" + base58btc( SHA3-256( multicodec_prefix || pubkey ) )
#
#   - SHA3-256 is FIPS-202 SHA3-256 (hashlib.sha3_256), NOT Keccak-256.
#   - multicodec_prefix: Ed25519 => 0xED 0x01 ; secp256k1 => 0xE7 0x01.
#   - secp256k1 hashes the 33-byte COMPRESSED public key.
#   - base58btc uses the Bitcoin alphabet; each leading 0x00 byte -> '1'.
#   - the literal leading 'z' is the multibase base58btc marker.
# ---------------------------------------------------------------------------

_BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

_MULTICODEC_PREFIX: Dict[SignatureAlgorithm, bytes] = {
    "Ed25519": bytes([0xED, 0x01]),
    "secp256k1": bytes([0xE7, 0x01]),
}


def _base58btc_encode(data: bytes) -> str:
    """Encode bytes with the Bitcoin/base58btc alphabet.

    Each leading 0x00 byte is preserved as a leading '1', matching the
    canonical base58check/base58btc convention.
    """
    num = int.from_bytes(data, "big")
    encoded = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = _BASE58BTC_ALPHABET[remainder] + encoded
    # Preserve leading zero bytes as leading '1's.
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    return "1" * leading_zeros + encoded


def _secp256k1_compress(public_key_bytes: bytes) -> bytes:
    """Normalise a secp256k1 public key to its 33-byte compressed form.

    Accepts the SDK's 64-byte uncompressed form (X || Y, no prefix), the
    65-byte SEC1 uncompressed form (0x04 || X || Y), or an already-compressed
    33-byte key (0x02/0x03 || X).
    """
    if len(public_key_bytes) == 33 and public_key_bytes[0] in (0x02, 0x03):
        return public_key_bytes
    if len(public_key_bytes) == 65 and public_key_bytes[0] == 0x04:
        body = public_key_bytes[1:]
    elif len(public_key_bytes) == 64:
        body = public_key_bytes
    else:
        raise ValueError(
            "secp256k1 public key must be 64-byte uncompressed (X||Y), "
            "65-byte SEC1 (0x04||X||Y), or 33-byte compressed"
        )
    x = body[:32]
    y = body[32:]
    prefix = 0x02 if (y[-1] & 1) == 0 else 0x03
    return bytes([prefix]) + x


def _did_key_material(public_key_bytes: bytes, algorithm: SignatureAlgorithm) -> bytes:
    """Return the key bytes that are hashed (after the multicodec prefix)."""
    if algorithm == "Ed25519":
        if len(public_key_bytes) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        return public_key_bytes
    if algorithm == "secp256k1":
        return _secp256k1_compress(public_key_bytes)
    raise ValueError(f"Unsupported algorithm: {algorithm}")


def derive_did(
    public_key: Union[bytes, str],
    algorithm: SignatureAlgorithm = "Ed25519",
) -> Dict[str, str]:
    """Derive the self-certifying Willow DID for a public key.

    The id is bound to the key, so anyone holding the public key can compute
    it (this is what enables the pre-fund step of onboarding: fund the derived
    id *before* it is registered). The chain recomputes this exact value.

    Args:
        public_key: The public key as raw ``bytes`` or a hex string. Ed25519
            is the 32-byte key; secp256k1 may be 64-byte uncompressed (the
            SDK's wire form), 65-byte SEC1, or 33-byte compressed (it is
            normalised to compressed before hashing).
        algorithm: "Ed25519" or "secp256k1".

    Returns:
        ``{"did": ..., "public_key_id": "{did}#key-1"}``
    """
    if isinstance(public_key, str):
        public_key = bytes.fromhex(public_key)

    try:
        prefix = _MULTICODEC_PREFIX[algorithm]
    except KeyError:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    material = _did_key_material(public_key, algorithm)
    digest = hashlib.sha3_256(prefix + material).digest()
    did = "did:willow:z" + _base58btc_encode(digest)
    return {"did": did, "public_key_id": f"{did}#key-1"}


# ---------------------------------------------------------------------------
# secp256k1 helpers backed by `cryptography`. Formats match the Willow
# wire protocol:
#
#   - public keys:  64-byte uncompressed (X || Y), no 0x04 prefix
#   - signatures:   64-byte compact (r || s)
#   - message input: the caller pre-hashes (we sign/verify the raw digest)
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
    Generate a new keypair and derive its self-certifying Willow DID.

    The DID is *derived* from the public key (see ``derive_did``); it is not
    chosen. Because the id is bound to the key, onboarding is a two-step
    bootstrap: a funded account must transfer >= the registration fee to the
    derived ``did`` *first*, then the holder registers the DID document (the
    fee is paid from that pre-funded balance).

    Args:
        algorithm: Signature algorithm to use ("Ed25519" or "secp256k1")

    Returns:
        Dictionary containing:
        - did: The derived, self-certifying DID string
        - private_key: Hex-encoded private key
        - public_key: Hex-encoded public key
        - public_key_id: Public key identifier ("{did}#key-1")
        - did_document: The DID document
        - algorithm: The signature algorithm
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
    
    # Derive the self-certifying DID from the public key. The id is bound to
    # the key (not chosen): the chain's RegisterDid check recomputes this exact
    # value and rejects anything else. See ``derive_did`` for the derivation.
    derived = derive_did(public_key_bytes, algorithm)
    did = derived["did"]
    public_key_id = derived["public_key_id"]
    
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