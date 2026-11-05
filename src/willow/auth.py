"""Authentication utilities for Willow SDK."""

import os
import time
import hashlib
import secrets
from typing import Any, Dict, Literal, Optional, Union

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
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

    Accepts the 64-byte uncompressed form older versions of this SDK
    generated (X || Y, no prefix), the 65-byte SEC1 uncompressed form
    (0x04 || X || Y), or an already-compressed 33-byte key (0x02/0x03 || X).
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
            is the 32-byte key; secp256k1 may be 33-byte compressed (what
            ``generate_did`` publishes), 65-byte SEC1, or 64-byte X || Y (it
            is normalised to compressed before hashing).
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
#   - public keys:  33-byte compressed (0x02/0x03 || X), a form the server
#                   reads from a DID document. Verification also accepts the
#                   65-byte SEC1 form and the 64-byte X || Y form older
#                   versions of this SDK published.
#   - signatures:   64-byte compact (r || s), lower-S, over the Keccak-256
#                   (Ethereum's hash, not FIPS-202 SHA3-256) of the message
#   - message input: the caller pre-hashes (we sign/verify the raw digest)
# ---------------------------------------------------------------------------

# The order of the secp256k1 group.
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_HALF_N = _SECP256K1_N // 2

# Key types the server verifies, by algorithm.
_KEY_TYPES: Dict[SignatureAlgorithm, str] = {
    "Ed25519": "Ed25519VerificationKey2018",
    "secp256k1": "EcdsaSecp256k1VerificationKey2019",
}


def _key_algorithm(body: Dict[str, Any], public_key_id: str) -> Optional[SignatureAlgorithm]:
    """The algorithm of the key ``public_key_id`` in a DID document body
    (``did_document_body``), from its key type; ``None`` if the document has
    no such key or names another type."""
    for key in body["public_keys"]:
        if key["id"] == public_key_id:
            for algorithm, key_type in _KEY_TYPES.items():
                if key["type"] == key_type:
                    return algorithm
            return None
    return None


def _secp256k1_public_key_bytes_from_private(private_key_bytes: bytes) -> bytes:
    """Derive the 33-byte compressed public key from a 32-byte private key."""
    private_int = int.from_bytes(private_key_bytes, "big")
    private_key = ec.derive_private_key(private_int, ec.SECP256K1())
    return private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )


def _secp256k1_public_key(public_key_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Parse a secp256k1 public key: 33-byte compressed, 65-byte SEC1
    uncompressed, or the 64-byte X || Y form. Raises ValueError otherwise."""
    if len(public_key_bytes) == 64:
        public_key_bytes = b"\x04" + public_key_bytes
    if len(public_key_bytes) not in (33, 65):
        raise ValueError("secp256k1 public key must be 33, 64, or 65 bytes")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)


def _secp256k1_sign_prehashed(private_key_bytes: bytes, digest: bytes) -> bytes:
    """Sign a 32-byte digest with secp256k1, returning a 64-byte compact (r || s) signature.

    The nonce is RFC 6979 deterministic where the installed `cryptography`
    supports it, and s is normalised to the lower half of the order: the
    server, like libsecp256k1, refuses a signature with a high s.

    The caller is responsible for hashing (we use Prehashed to tell
    `cryptography` the input is already a digest). SHA256 is the declared
    pre-hash algorithm because `cryptography` uses it to check the digest's
    length and, for RFC 6979, as the HMAC hash, as libsecp256k1 does.
    """
    private_int = int.from_bytes(private_key_bytes, "big")
    private_key = ec.derive_private_key(private_int, ec.SECP256K1())
    try:
        signature_der = private_key.sign(
            digest, ec.ECDSA(Prehashed(hashes.SHA256()), deterministic_signing=True)
        )
    except (TypeError, UnsupportedAlgorithm):
        # An older `cryptography`, or an OpenSSL without RFC 6979: a random nonce.
        signature_der = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(signature_der)
    if s > _SECP256K1_HALF_N:
        s = _SECP256K1_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _secp256k1_verify_prehashed(
    public_key_bytes: bytes, digest: bytes, signature: bytes
) -> bool:
    """Verify a secp256k1 signature over a 32-byte digest as the server does.

    `signature` is a 64-byte compact r || s, or else DER; a signature with a
    high s is refused. `public_key_bytes` is any form `_secp256k1_public_key`
    reads.
    """
    try:
        public_key = _secp256k1_public_key(public_key_bytes)
        if len(signature) == 64:
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
        else:
            r, s = decode_dss_signature(signature)
            if encode_dss_signature(r, s) != signature:
                return False
        if not (0 < r < _SECP256K1_N and 0 < s <= _SECP256K1_HALF_N):
            return False
        public_key.verify(
            encode_dss_signature(r, s), digest, ec.ECDSA(Prehashed(hashes.SHA256()))
        )
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
        - public_key: Hex-encoded public key (secp256k1: 33-byte compressed)
        - public_key_id: Public key identifier ("{did}#key-1")
        - did_document: The DID document, with the key listed for
          authentication so it can sign requests
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
        # Generate secp256k1 keypair (Ethereum compatible). The public key is
        # the 33-byte compressed form: the server can't parse 64-byte X || Y.
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
    
    # Create DID document. The server verifies a request only by a key of a
    # type it knows that the document lists for authentication.
    now = int(time.time())
    did_document = DidDocument(
        id=did,
        public_keys=[
            PublicKey(
                id=public_key_id,
                key_type=_KEY_TYPES[algorithm],
                controller=did,
                public_key_hex=public_key_bytes.hex()
            )
        ],
        authentication=[public_key_id],
        created=now,
        updated=now
    )
    
    return {
        "did": did,
        "private_key": private_key_bytes.hex(),
        "public_key": public_key_bytes.hex(),
        "public_key_id": public_key_id,
        "did_document": did_document,
        "algorithm": algorithm
    }


def _strip_0x(value: str) -> str:
    return value[2:] if value.startswith(("0x", "0X")) else value


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

    Ed25519 signs the message's UTF-8 bytes. secp256k1 signs their
    Keccak-256 (Ethereum's hash, not FIPS-202 SHA3-256), as the server
    verifies every secp256k1 signature, and returns a 64-byte compact r || s
    with a low s.

    Returns:
        Hex-encoded signature, with no ``0x`` prefix. (A request signature
        sent in ``X-Signature`` is encoded by ``sign_request`` and
        ``sign_request_with_nonce``, which prefix secp256k1 with ``0x``.)
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
        signature_hex: Hex-encoded signature, with or without a ``0x``
            prefix. secp256k1 takes a 64-byte compact r || s or DER, with a
            low s, over the Keccak-256 of the message, as the server does.
        public_key_hex: Hex-encoded public key. secp256k1 takes the 33-byte
            compressed form, the 65-byte SEC1 form, or the 64-byte X || Y
            form older versions of this SDK generated.
        algorithm: Signature algorithm

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        message_bytes = message.encode('utf-8')
        signature_bytes = bytes.fromhex(_strip_0x(signature_hex))
        public_key_bytes = bytes.fromhex(_strip_0x(public_key_hex))

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
    Detect signature algorithm from a *legacy* DID string.

    .. deprecated::
        Willow DIDs are now self-certifying and no longer embed the key
        algorithm in the string::

            did:willow:z<base58btc(SHA3-256(multicodec || pubkey))>

        The algorithm is therefore **not recoverable** from the DID and this
        helper returns ``"Ed25519"`` for every self-certifying id. Do not use
        it to pick a signing algorithm: pass the algorithm explicitly instead
        (see ``sign_request`` and ``Client.set_identity``). It is retained only
        to parse the retired ``did:willow:<alg>:<pubkey>`` format.

    Args:
        did: The DID string

    Returns:
        The detected algorithm (``"Ed25519"`` for any self-certifying id)
    """
    if "ed25519" in did.lower():
        return "Ed25519"
    elif "secp256k1" in did.lower():
        return "secp256k1"
    else:
        # Default to Ed25519
        return "Ed25519"


# ---------------------------------------------------------------------------
# Request signing.
#
# The API server reads X-DID, X-Public-Key-ID, X-Signature, X-Timestamp,
# and, optionally, X-Nonce. With X-Nonce, the signature is over the eight
# lines of ``signed_request_message``: the whole request, accepted once. That
# is the only form that carries the DID's read rights. Without it, the
# signature is over ``{METHOD}:{PATH}:{TIMESTAMP}``
# (``legacy_request_message``), which proves the DID but carries no read
# rights and can be replayed with any body until the timestamp expires.
# ---------------------------------------------------------------------------

REQUEST_SIGNATURE_VERSION = "willow-request-v2"


def signed_request_message(
    did: str,
    public_key_id: str,
    method: str,
    path_and_query: str,
    timestamp: Union[int, str],
    nonce: str,
    body: Optional[bytes] = None,
) -> str:
    """The message a nonce-signed request signs.

    A version line, then one per line: the DID, its key's id, the method, the
    path and query exactly as the server receives them, the Unix timestamp,
    the nonce, and the lowercase hex SHA-256 of the exact body bytes (of no
    bytes, for a request without a body). Lines are joined with ``\\n``, with
    no trailing newline.
    """
    return "\n".join(
        [
            REQUEST_SIGNATURE_VERSION,
            did,
            public_key_id,
            method,
            path_and_query,
            str(timestamp),
            nonce,
            hashlib.sha256(_body_bytes(body)).hexdigest(),
        ]
    )


def legacy_request_message(method: str, path: str, timestamp: Union[int, str]) -> str:
    """The message ``sign_request`` signs: ``{METHOD}:{PATH}:{TIMESTAMP}``.

    The server verifies this form over the request's path alone, so anything
    from the first ``?`` in ``path`` is left out.
    """
    return f"{method}:{path.split('?', 1)[0]}:{timestamp}"


def new_request_nonce() -> str:
    """A fresh nonce for a nonce-signed request: 32 hex characters from 16
    random bytes. The server accepts 16 to 128 characters of
    ``A-Z a-z 0-9 - _``, and each (DID, nonce) once."""
    return secrets.token_hex(16)


def sign_request_with_nonce(
    did: str,
    private_key_hex: str,
    public_key_id: str,
    method: str,
    path_and_query: str,
    body: Optional[bytes] = None,
    algorithm: SignatureAlgorithm = "Ed25519",
) -> Dict[str, str]:
    """Sign a request with a one-time nonce over the whole request.

    Only this form carries the DID's read rights: a Reader permission on a
    subgrove, or a place on a priced subgrove's free-reader list.

    Args:
        did: The DID to authenticate as
        private_key_hex: Hex-encoded private key
        public_key_id: Public key ID from the DID document (it must be listed
            in the document's ``authentication``)
        method: HTTP method, as sent (e.g. "POST")
        path_and_query: The request target exactly as the server receives it,
            query string included and URL-encoded as on the wire
            (e.g. "/query/my-subgrove?x=1")
        body: The exact body bytes sent (``None`` or ``b""`` for none)
        algorithm: Signature algorithm of the identity

    Returns:
        Headers to send: X-DID, X-Public-Key-ID, X-Signature, X-Timestamp,
        and X-Nonce. The server accepts the timestamp for 300 seconds and the
        nonce once, so sign each attempt of a retried request anew.
    """
    return _sign_request_with_nonce_at(
        did,
        private_key_hex,
        public_key_id,
        method,
        path_and_query,
        body,
        algorithm,
        timestamp=int(time.time()),
        nonce=new_request_nonce(),
    )


def _sign_request_with_nonce_at(
    did: str,
    private_key_hex: str,
    public_key_id: str,
    method: str,
    path_and_query: str,
    body: Optional[bytes],
    algorithm: SignatureAlgorithm,
    timestamp: Union[int, str],
    nonce: str,
) -> Dict[str, str]:
    message = signed_request_message(
        did, public_key_id, method, path_and_query, timestamp, nonce, body
    )
    return {
        "X-DID": did,
        "X-Public-Key-ID": public_key_id,
        "X-Signature": _sign_request_message(message, private_key_hex, algorithm),
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
    }


def sign_request(
    did: str,
    private_key_hex: str,
    public_key_id: str,
    method: str,
    path: str,
    algorithm: SignatureAlgorithm = "Ed25519",
) -> Dict[str, str]:
    """
    Sign a request in the server's older ``{METHOD}:{PATH}:{TIMESTAMP}`` form.

    PATH is the path alone: the server verifies this form over the request's
    path without its query, so any query string in ``path`` is left out of
    the message (see ``legacy_request_message``).

    This form proves the DID but carries none of its read rights, and anyone
    who sees it can replay it with any body until the timestamp expires (300
    seconds). ``WillowClient`` signs its ``GET /data``, ``GET /proof``, and
    ``POST /query``, ``/sql``, and ``/graphql`` reads sent to the API with
    ``sign_request_with_nonce``, and its other authenticated requests,
    indexer reads included, with this form.

    Args:
        did: The DID to authenticate as
        private_key_hex: Hex-encoded private key
        public_key_id: Public key ID from DID document
        method: HTTP method (e.g., "GET", "POST")
        path: API path (e.g., "/data/my-subgrove/my-key")
        algorithm: Signature algorithm of the identity ("Ed25519" or
            "secp256k1"). Must be supplied by the caller because the
            self-certifying DID no longer encodes it; the algorithm cannot be
            recovered from the DID string. Defaults to "Ed25519" for backward
            compatibility with the SDK's Ed25519-first identities.

    Returns:
        Dictionary of authentication headers to include in the request
    """
    timestamp = int(time.time())
    message = legacy_request_message(method, path, timestamp)
    return {
        "X-DID": did,
        "X-Public-Key-ID": public_key_id,
        "X-Signature": _sign_request_message(message, private_key_hex, algorithm),
        "X-Timestamp": str(timestamp),
    }


def _sign_request_message(
    message: str, private_key_hex: str, algorithm: SignatureAlgorithm
) -> str:
    """Sign a request message, encoded as the server decodes X-Signature:
    Ed25519 as hex, secp256k1 as ``0x``-prefixed hex. The server reads an
    unprefixed secp256k1 signature as base64 first, and most hex strings are
    valid base64."""
    signature = sign_challenge(message, private_key_hex, algorithm)
    if algorithm == "secp256k1":
        return "0x" + signature
    return signature


def _body_bytes(body: Optional[Union[bytes, bytearray, str]]) -> bytes:
    if body is None:
        return b""
    if isinstance(body, str):
        return body.encode("utf-8")
    return bytes(body)


# Alias for sign_challenge - used by consensus client
sign_message = sign_challenge