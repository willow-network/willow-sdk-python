"""RegisterDid known answers.

The node signs a RegisterDid over ``serde_json::to_vec`` of the transaction's
``DidDocument``: its fields in declaration order (``id``, ``public_keys``,
``authentication``, ``service``, ``created``, ``updated``, ``proof``; a key's
``id``, ``type``, ``controller``, ``public_key_base58``, ``public_key_hex``; a
service's ``id``, ``type``, ``service_endpoint``; a proof's ``type``,
``created``, ``verification_method``, ``proof_purpose``, ``jws``), ``None`` as
``null``, no whitespace. serde_json escapes ``"`` and ``\\``, writes
backspace, form feed, line feed, carriage return, and tab as ``\\b \\f \\n
\\r \\t``, every other byte below 0x20 as ``\\u00xx`` with lowercase hex, and
nothing else: DEL, ``/``, non-ASCII text, and U+2028 go in as their UTF-8.

The messages below are written out by hand from those rules; the signatures
were made over them with an independent Ed25519 and secp256k1 (RFC 6979,
lower-S) implementation, seed ``03`` x 32.
"""

import hashlib

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from eth_utils import keccak

from willow import register_did_message, sign_challenge, verify_signature
from willow.consensus.types import RegisterDidTx, create_sign_message

SEED = "03" * 32
ED_DID = "did:willow:zF5GZ1jk3Sqbqh6Q6hG4HrQa3ZMhs794Hbhv7yytr1Y9d"
ED_PUBLIC_KEY = "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1"
K1_DID = "did:willow:z5AzUUsCPyDPxpAWq23RAgvXpvqqx2C4Y824gEss4HyvL"
K1_PUBLIC_KEY = "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"

ED_DOCUMENT = {
    "id": ED_DID,
    "public_keys": [{
        "id": f"{ED_DID}#key-1",
        "type": "Ed25519VerificationKey2018",
        "controller": ED_DID,
        "public_key_base58": None,
        "public_key_hex": ED_PUBLIC_KEY,
    }],
    "authentication": [f"{ED_DID}#key-1"],
    "service": [{
        "id": f"{ED_DID}#profile",
        "type": 'Profile "main"',
        "service_endpoint": "https://example.com/a\\b\tc\x01\x1f\x7f é\U0001F33F ",
    }],
    "created": 1700000000,
    "updated": 4294967297,
    "proof": {
        "type": "Ed25519Signature2018",
        "created": 1700000001,
        "verification_method": f"{ED_DID}#key-1",
        "proof_purpose": "assertionMethod",
        "jws": "a.b.c",
    },
}

ED_MESSAGE = (
    '{"id":"' + ED_DID + '",'
    '"public_keys":[{"id":"' + ED_DID + '#key-1","type":"Ed25519VerificationKey2018",'
    '"controller":"' + ED_DID + '","public_key_base58":null,"public_key_hex":"' + ED_PUBLIC_KEY + '"}],'
    '"authentication":["' + ED_DID + '#key-1"],'
    '"service":[{"id":"' + ED_DID + '#profile","type":"Profile \\"main\\"",'
    '"service_endpoint":"https://example.com/a\\\\b\\tc\\u0001\\u001f\x7f é\U0001F33F "}],'
    '"created":1700000000,"updated":4294967297,'
    '"proof":{"type":"Ed25519Signature2018","created":1700000001,'
    '"verification_method":"' + ED_DID + '#key-1","proof_purpose":"assertionMethod","jws":"a.b.c"}}'
)
ED_MESSAGE_SHA256 = "d5e8588d155adb6dc693d86657212c2ec9b9dfab82ebff11d5421692f0bcda0e"
ED_SIGNATURE = (
    "887e46d4b9afd7e954fa4e630834df2a586b49c565a4054c4a91428f3376acc4"
    "f8b7279c34913ac360106eb02dba3503766a13262a87069bf6b89f70bf25ac0f"
)

K1_DOCUMENT = {
    "id": K1_DID,
    "public_keys": [{
        "id": f"{K1_DID}#key-1",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": K1_DID,
        "public_key_hex": K1_PUBLIC_KEY,
    }],
    "authentication": [f"{K1_DID}#key-1"],
    "created": 0,
    "updated": 0,
}

# ``service`` and ``proof`` left out: the SDK sends ``[]`` and ``null``, as
# the node serializes them.
K1_MESSAGE = (
    '{"id":"' + K1_DID + '",'
    '"public_keys":[{"id":"' + K1_DID + '#key-1","type":"EcdsaSecp256k1VerificationKey2019",'
    '"controller":"' + K1_DID + '","public_key_base58":null,"public_key_hex":"' + K1_PUBLIC_KEY + '"}],'
    '"authentication":["' + K1_DID + '#key-1"],'
    '"service":[],"created":0,"updated":0,"proof":null}'
)
K1_KECCAK256 = "37ba9e634af66aa88838b106b0b9fa744dda06effb9b6253d0763d2571dc2453"
K1_SIGNATURE = (
    "1cb18d5113042faa3f35edd89452b1eb573c7cfc381a09b71060cda460283723"
    "510a4e400b5ea62a6287ae6566e65dd2202c5491d3603f0de7a559c6f163aed8"
)


def _rfc6979_available() -> bool:
    key = ec.derive_private_key(3, ec.SECP256K1())
    try:
        key.sign(b"\x00" * 32, ec.ECDSA(Prehashed(hashes.SHA256()), deterministic_signing=True))
        return True
    except (TypeError, UnsupportedAlgorithm):
        return False


def test_the_ed25519_document_is_the_known_message():
    message = register_did_message(ED_DOCUMENT)
    assert message == ED_MESSAGE
    assert hashlib.sha256(message.encode("utf-8")).hexdigest() == ED_MESSAGE_SHA256
    tx = RegisterDidTx(did_document=ED_DOCUMENT, signature="", public_key_id=f"{ED_DID}#key-1", nonce=1)
    assert create_sign_message("RegisterDid", tx) == ED_MESSAGE


def test_the_ed25519_signature_is_the_known_answer():
    assert sign_challenge(ED_MESSAGE, SEED, "Ed25519") == ED_SIGNATURE
    assert verify_signature(ED_MESSAGE, ED_SIGNATURE, ED_PUBLIC_KEY, "Ed25519")


def test_the_secp256k1_document_is_the_known_message():
    message = register_did_message(K1_DOCUMENT)
    assert message == K1_MESSAGE
    assert keccak(message.encode("utf-8")).hex() == K1_KECCAK256


def test_the_secp256k1_signature_is_the_known_answer():
    assert verify_signature(K1_MESSAGE, K1_SIGNATURE, K1_PUBLIC_KEY, "secp256k1")
    signature = sign_challenge(K1_MESSAGE, SEED, "secp256k1")
    assert verify_signature(K1_MESSAGE, signature, K1_PUBLIC_KEY, "secp256k1")
    if not _rfc6979_available():
        pytest.skip("this cryptography build signs secp256k1 without RFC 6979")
    assert signature == K1_SIGNATURE
