"""Request signing: the API server's test vector, known-answer signatures, and
the client's signing as a server would verify it."""

import json
import re

import hashlib

import httpx
import pytest
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
from eth_utils import keccak

from willow import QuerySource, WillowClient, WillowError
from willow.errors import AuthenticationError, ProofVerificationError, UnsupportedError
from willow.auth import (
    _SECP256K1_N,
    _sign_request_with_nonce_at,
    legacy_request_message,
    new_request_nonce,
    sign_challenge,
    sign_request,
    sign_request_with_nonce,
    signed_request_message,
    verify_signature,
)

# The API server's own test vector for the eight-line message, byte for byte.
VECTOR_MESSAGE = (
    "willow-request-v2\ndid:willow:a\ndid:willow:a#key-1\nPOST\n/query/sg?x=1\n1700000000\n"
    "abcdefghijklmnop\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
)
VECTOR = dict(
    did="did:willow:a",
    public_key_id="did:willow:a#key-1",
    method="POST",
    path_and_query="/query/sg?x=1",
    timestamp=1700000000,
    nonce="abcdefghijklmnop",
    body=b"{}",
)

# Signatures over VECTOR_MESSAGE by the key whose seed is 32 bytes of 0x03,
# computed with an independent implementation of the server's verification.
SEED = "03" * 32
ED25519_PUBLIC_KEY = "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1"
ED25519_SIGNATURE = (
    "c117313c0d01641340e398d9a7a9ff024a1c6672bca16bbcb99e6fe2738f82e7"
    "7870bd2c30dc62d6c50cea32a3b21086730d9c25297831dd83bc797c5b394d0d"
)
SECP256K1_PUBLIC_KEY = "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"
SECP256K1_KECCAK = "d88e0d6795532372abf6cc33c33a8903b5b0fb108c1dc0b0ccc63fe061bd9e93"
SECP256K1_COMPACT = (
    "bfbad8ec000c66ed30349070db245db0c45249293c545e35dc997d6427d32238"
    "30787244d5b3bb7e8a1b39bdba0c62261e02344a515f5e8e89f678e17d4b976d"
)
SECP256K1_DER = (
    "3045022100bfbad8ec000c66ed30349070db245db0c45249293c545e35dc997d6427d32238"
    "022030787244d5b3bb7e8a1b39bdba0c62261e02344a515f5e8e89f678e17d4b976d"
)

NONCE_FORMAT = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


def _rfc6979_available() -> bool:
    """Whether the installed `cryptography` signs ECDSA deterministically.

    Without it the SDK signs with a random nonce: still valid, but not equal
    to the known answer."""
    key = ec.derive_private_key(3, ec.SECP256K1())
    try:
        key.sign(b"\x00" * 32, ec.ECDSA(Prehashed(hashes.SHA256()), deterministic_signing=True))
        return True
    except (TypeError, UnsupportedAlgorithm):
        return False


def _vector_headers(algorithm):
    return _sign_request_with_nonce_at(
        VECTOR["did"],
        SEED,
        VECTOR["public_key_id"],
        VECTOR["method"],
        VECTOR["path_and_query"],
        VECTOR["body"],
        algorithm,
        timestamp=VECTOR["timestamp"],
        nonce=VECTOR["nonce"],
    )


class TestMessages:
    def test_signed_request_message_matches_server_vector(self):
        assert signed_request_message(**VECTOR) == VECTOR_MESSAGE

    def test_signed_request_message_without_body_hashes_no_bytes(self):
        message = signed_request_message("d", "d#k", "GET", "/data/sg/k", 1, "n" * 16)
        empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert message.endswith("\n" + empty_sha256)
        assert message == signed_request_message("d", "d#k", "GET", "/data/sg/k", 1, "n" * 16, b"")

    def test_legacy_request_message_signs_the_path_alone(self):
        assert (
            legacy_request_message("GET", "/data/sg/k?include_proof=true", 1700000000)
            == "GET:/data/sg/k:1700000000"
        )
        assert legacy_request_message("GET", "/data/sg/k", "1700000000") == "GET:/data/sg/k:1700000000"
        assert legacy_request_message("GET", "/a?b?c", 1) == "GET:/a:1"


class TestNonce:
    def test_nonce_format_and_uniqueness(self):
        nonces = [new_request_nonce() for _ in range(200)]
        for nonce in nonces:
            assert NONCE_FORMAT.match(nonce)
            assert re.fullmatch(r"[0-9a-f]{32}", nonce)
        assert len(set(nonces)) == len(nonces)

    def test_each_signature_draws_a_fresh_nonce(self):
        first = sign_request_with_nonce("d", SEED, "d#k", "GET", "/data/sg/k")
        second = sign_request_with_nonce("d", SEED, "d#k", "GET", "/data/sg/k")
        assert first["X-Nonce"] != second["X-Nonce"]


class TestKnownAnswers:
    def test_ed25519_public_key_from_seed(self):
        public_key = (
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED))
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        assert public_key.hex() == ED25519_PUBLIC_KEY

    def test_ed25519_nonce_signature_known_answer(self):
        headers = _vector_headers("Ed25519")
        assert headers == {
            "X-DID": "did:willow:a",
            "X-Public-Key-ID": "did:willow:a#key-1",
            "X-Signature": ED25519_SIGNATURE,
            "X-Timestamp": "1700000000",
            "X-Nonce": "abcdefghijklmnop",
        }
        assert verify_signature(VECTOR_MESSAGE, ED25519_SIGNATURE, ED25519_PUBLIC_KEY, "Ed25519")

    def test_secp256k1_signs_the_keccak256_of_the_message(self):
        assert keccak(VECTOR_MESSAGE.encode()).hex() == SECP256K1_KECCAK
        signature = bytes.fromhex(sign_challenge(VECTOR_MESSAGE, SEED, "secp256k1"))
        der = encode_dss_signature(
            int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        )
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), bytes.fromhex(SECP256K1_PUBLIC_KEY)
        )
        prehashed = ec.ECDSA(Prehashed(hashes.SHA256()))
        public_key.verify(der, bytes.fromhex(SECP256K1_KECCAK), prehashed)
        with pytest.raises(InvalidSignature):
            # Not over SHA-256.
            public_key.verify(der, hashlib.sha256(VECTOR_MESSAGE.encode()).digest(), prehashed)

    @pytest.mark.skipif(not _rfc6979_available(), reason="cryptography without RFC 6979 signing")
    def test_secp256k1_nonce_signature_known_answer(self):
        headers = _vector_headers("secp256k1")
        # 0x-prefixed: the server reads an unprefixed secp256k1 signature as
        # base64 first. Compact r || s, RFC 6979 nonce, low s.
        assert headers["X-Signature"] == "0x" + SECP256K1_COMPACT
        assert set(headers) == {"X-DID", "X-Public-Key-ID", "X-Signature", "X-Timestamp", "X-Nonce"}

    def test_secp256k1_verify_accepts_the_known_answer(self):
        for signature in (
            "0x" + SECP256K1_COMPACT,
            SECP256K1_COMPACT,
            SECP256K1_DER,
            "0x" + SECP256K1_DER,
        ):
            assert verify_signature(VECTOR_MESSAGE, signature, SECP256K1_PUBLIC_KEY, "secp256k1")
        assert not verify_signature(VECTOR_MESSAGE + "x", SECP256K1_COMPACT, SECP256K1_PUBLIC_KEY, "secp256k1")

    def test_secp256k1_verify_reads_every_public_key_form(self):
        point = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), bytes.fromhex(SECP256K1_PUBLIC_KEY)
        )
        sec1 = point.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        # The 33-byte form, the 65-byte SEC1 form, and the 64-byte X || Y form
        # older versions of this SDK published.
        for public_key in (bytes.fromhex(SECP256K1_PUBLIC_KEY), sec1, sec1[1:]):
            assert verify_signature(
                VECTOR_MESSAGE, SECP256K1_COMPACT, public_key.hex(), "secp256k1"
            )

    def test_secp256k1_verify_refuses_high_s(self):
        r = SECP256K1_COMPACT[:64]
        s = int(SECP256K1_COMPACT[64:], 16)
        high_s = r + (_SECP256K1_N - s).to_bytes(32, "big").hex()
        assert not verify_signature(VECTOR_MESSAGE, high_s, SECP256K1_PUBLIC_KEY, "secp256k1")

    def test_secp256k1_signatures_are_low_s(self):
        for i in range(32):
            signature = bytes.fromhex(sign_challenge(f"message {i}", SEED, "secp256k1"))
            assert len(signature) == 64
            assert int.from_bytes(signature[32:], "big") <= _SECP256K1_N // 2


class TestLegacySigner:
    def test_old_form_drops_the_query(self):
        headers = sign_request("did:willow:a", SEED, "did:willow:a#key-1", "GET", "/data/sg/k?include_proof=true")
        assert "X-Nonce" not in headers
        message = f"GET:/data/sg/k:{headers['X-Timestamp']}"
        assert verify_signature(message, headers["X-Signature"], ED25519_PUBLIC_KEY, "Ed25519")

    def test_old_form_secp256k1_is_0x_prefixed(self):
        headers = sign_request(
            "did:willow:a", SEED, "did:willow:a#key-1", "POST", "/data/sg", "secp256k1"
        )
        assert headers["X-Signature"].startswith("0x")
        message = f"POST:/data/sg:{headers['X-Timestamp']}"
        assert verify_signature(message, headers["X-Signature"], SECP256K1_PUBLIC_KEY, "secp256k1")


# ---------------------------------------------------------------------------
# The client, through a mocked transport: each request verified as the server
# would, from the method, path and query, headers, and body it received.
# ---------------------------------------------------------------------------


def _server_verifies(request: httpx.Request, public_key_hex: str, algorithm: str, prefix: str = "") -> str:
    """Verify a request as the API would, returning the form it was signed in."""
    headers = request.headers
    target = request.url.raw_path.decode("ascii")
    if prefix:
        # A proxy mounted under ``prefix`` strips it before the API sees it.
        assert target.startswith(prefix + "/")
        target = target[len(prefix):]
    if "X-Nonce" in headers:
        assert NONCE_FORMAT.match(headers["X-Nonce"])
        message = signed_request_message(
            headers["X-DID"],
            headers["X-Public-Key-ID"],
            request.method,
            target,
            headers["X-Timestamp"],
            headers["X-Nonce"],
            request.content,
        )
        form = "nonce"
    else:
        # The server's request.uri().path(): the encoded path, no query.
        message = f"{request.method}:{target.split('?', 1)[0]}:{headers['X-Timestamp']}"
        form = "legacy"
    assert verify_signature(message, headers["X-Signature"], public_key_hex, algorithm), (
        form,
        message,
    )
    return form


def _ok(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.startswith("/willow/"):  # behind a proxy mounted under /willow
        path = path[len("/willow"):]
    if path.startswith("/data/"):
        data = {"value": 1}
    elif path.startswith("/proof/"):
        data = {"proof": "00", "value": {"value": 1}}
    elif path.startswith("/query/"):
        data = {"documents": [], "total": 0}
    elif path.startswith("/sql/"):
        data = {"columns": ["n"], "rows": [[1]]}
    elif path.startswith("/key-grants/"):
        data = {
            "grantee_did": "did:willow:a",
            "key_epoch": 1,
            "grantee_public_key_id": "did:willow:a#key-1",
            "ephemeral_public_key": "00",
            "encrypted_key": "00",
            "granted_by": "did:willow:owner",
            "granted_at": 1,
        }
    else:
        data = None
    return httpx.Response(200, json={"success": True, "data": data, "error": None})


def _client(handler, api_url="http://api.test", algorithm="Ed25519", identity=True, **kwargs):
    client = WillowClient(api_url, **kwargs)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    if identity:
        client.set_identity("did:willow:a", SEED, "did:willow:a#key-1", algorithm)
    return client


@pytest.mark.asyncio
async def test_client_nonce_signs_reads_and_key_grant_reads():
    seen = []

    def handler(request):
        seen.append((request, _server_verifies(request, ED25519_PUBLIC_KEY, "Ed25519")))
        return _ok(request)

    client = _client(handler)
    await client.data.get_unverified("sg", "k")
    await client.data.query_unverified("sg", {"limit": 5})
    await client.proof.get("sg", "k")
    await client.indexing.sql_query("sg", "SELECT 1", source=QuerySource.VALIDATOR)
    await client.privacy.get_my_key_grant("sg")
    await client.privacy.list_key_grantees("sg")
    await client.privacy.get_key_grant_proof("sg", "did:willow:b")
    await client._http.aclose()

    forms = [(r.method, r.url.path, form) for r, form in seen]
    assert forms == [
        ("GET", "/data/sg/k", "nonce"),
        ("POST", "/query/sg", "nonce"),
        ("GET", "/proof/sg/k", "nonce"),
        ("POST", "/sql/sg", "nonce"),
        ("GET", "/key-grants/sg/did:willow:a", "nonce"),
        ("GET", "/key-grants/sg", "nonce"),
        ("GET", "/proof/key-grant/sg/did:willow:b", "nonce"),
    ]
    # The signed body is the body sent.
    query = seen[1][0]
    assert json.loads(query.content) == {"limit": 5, "include_proof": False}
    # The API's JSON routes refuse a body without this header.
    for request, _ in seen:
        if request.method == "POST":
            assert request.headers["Content-Type"] == "application/json"
    nonces = [r.headers["X-Nonce"] for r, form in seen if form == "nonce"]
    assert len(set(nonces)) == len(nonces)


# The node's key-grant routes name a caller only for the nonce-signed form
# (its handlers' ``proven_caller``): any other request is refused 401.
_KEY_GRANT_AUTH_REQUIRED = "Authentication required: sign the request with a one-time nonce (X-Nonce)"


def _key_grant_node(request):
    if "X-Nonce" not in request.headers:
        return httpx.Response(401, json={"success": False, "data": None, "error": _KEY_GRANT_AUTH_REQUIRED})
    assert _server_verifies(request, ED25519_PUBLIC_KEY, "Ed25519") == "nonce"
    path = request.url.path
    if path == "/key-grants/sg/did:willow:a":
        # EncryptedKeyGrant as serde writes it: byte vectors as arrays.
        data = {
            "grantee_did": "did:willow:a", "key_epoch": 2, "grantee_public_key_id": "did:willow:a#key-1",
            "ephemeral_public_key": list(range(32)), "encrypted_key": list(range(48)),
            "granted_by": "did:willow:owner", "granted_at": 1700000000,
        }
    elif path == "/key-grants/sg":
        data = ["did:willow:a", "did:willow:b"]
    elif path == "/proof/key-grant/sg/did:willow:a":
        data = {"proof": "0011", "subgrove_id": "sg", "grantee_did": "did:willow:a"}
    else:
        return httpx.Response(404, json={"success": False, "data": None, "error": "not found"})
    return httpx.Response(200, json={"success": True, "data": data, "error": None})


@pytest.mark.asyncio
async def test_key_grant_reads_are_answered_by_a_node_that_takes_only_nonce_signed_reads():
    client = _client(_key_grant_node)
    grant = await client.privacy.get_my_key_grant("sg")
    assert (grant.grantee_did, grant.key_epoch, bytes(grant.ephemeral_public_key)) == (
        "did:willow:a", 2, bytes(range(32))
    )
    assert bytes(grant.encrypted_key) == bytes(range(48))
    assert await client.privacy.list_key_grantees("sg") == ["did:willow:a", "did:willow:b"]
    assert await client.privacy.get_key_grant_proof("sg", "did:willow:a") == {
        "proof": "0011", "subgrove_id": "sg", "grantee_did": "did:willow:a"
    }
    await client._http.aclose()


@pytest.mark.asyncio
async def test_client_nonce_signs_graphql_and_both_reads_of_a_verified_get():
    seen = []

    def handler(request):
        assert _server_verifies(request, ED25519_PUBLIC_KEY, "Ed25519") == "nonce"
        seen.append(request)
        if request.url.path.startswith("/proof/"):
            # No proof: data.get raises rather than return the value unverified.
            return httpx.Response(200, json={"success": True, "data": {"proof": None}, "error": None})
        if request.url.path.startswith("/graphql/"):
            return httpx.Response(200, json={"success": True, "data": {"data": {"items": []}}, "error": None})
        return _ok(request)

    client = _client(handler)
    client.consensus_rpc_url = "http://rpc.test:26657"
    with pytest.raises(ProofVerificationError, match="no proof"):
        await client.data.get("sg", "k")
    await client.indexing.graphql_query("sg", "{ items { id } }", source=QuerySource.VALIDATOR)
    await client._http.aclose()
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/data/sg/k"),
        ("GET", "/proof/sg/k"),
        ("POST", "/graphql/sg"),
    ]
    assert seen[2].headers["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_client_nonce_signs_an_unverified_query():
    seen = []

    def handler(request):
        assert _server_verifies(request, ED25519_PUBLIC_KEY, "Ed25519") == "nonce"
        seen.append(request)
        return _ok(request)

    client = _client(handler)
    with pytest.raises(UnsupportedError):
        await client.data.query("sg", {})  # nothing is sent
    await client.data.query_unverified("sg", {})
    await client._http.aclose()
    assert [(r.method, r.url.path) for r in seen] == [("POST", "/query/sg")]
    assert json.loads(seen[0].content) == {"include_proof": False}


@pytest.mark.asyncio
async def test_client_signs_the_path_the_api_receives():
    seen = []

    def handler(request):
        assert _server_verifies(request, ED25519_PUBLIC_KEY, "Ed25519", prefix="/willow") == "nonce"
        seen.append(request)
        return _ok(request)

    # URL-encoded, and less the base URL's path, as the API receives it.
    client = _client(handler, api_url="https://proxy.test/willow")
    await client.privacy.get_my_key_grant("a sg")
    await client._http.aclose()
    assert seen[0].url.raw_path == b"/willow/key-grants/a%20sg/did:willow:a"


@pytest.mark.asyncio
async def test_client_reports_a_bare_auth_refusal():
    # The auth middleware refuses with a status and no body.
    client = _client(lambda request: httpx.Response(401))
    with pytest.raises(AuthenticationError) as exc_info:
        await client.data.get_unverified("sg", "k")
    await client._http.aclose()
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_client_sends_a_new_nonce_for_each_attempt():
    # WillowClient makes one attempt per call; a caller's retry is a new
    # call, signed anew.
    seen = []

    def handler(request):
        _server_verifies(request, ED25519_PUBLIC_KEY, "Ed25519")
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(502, json={"success": False, "data": None, "error": "bad gateway"})
        return _ok(request)

    client = _client(handler)
    with pytest.raises(WillowError):
        await client.data.query_unverified("sg", {})
    await client.data.query_unverified("sg", {})
    await client._http.aclose()

    assert len(seen) == 2
    assert seen[0].content == seen[1].content
    assert seen[0].headers["X-Nonce"] != seen[1].headers["X-Nonce"]


@pytest.mark.asyncio
async def test_client_signs_the_target_as_sent():
    seen = []

    def handler(request):
        _server_verifies(request, ED25519_PUBLIC_KEY, "Ed25519")
        seen.append(request)
        return _ok(request)

    client = _client(handler)
    await client.data.get_unverified("sg", "a key")
    await client._http.aclose()
    # Signed over the URL-encoded target on the wire.
    assert seen[0].url.raw_path == b"/data/sg/a%20key"


@pytest.mark.asyncio
async def test_client_drops_the_base_url_path_from_the_signed_target():
    def handler(request):
        assert _server_verifies(request, ED25519_PUBLIC_KEY, "Ed25519", prefix="/willow") == "nonce"
        return _ok(request)

    client = _client(handler, api_url="https://proxy.test/willow")
    assert client._api_target("https://proxy.test/willow/data/sg/k?x=1") == "/data/sg/k?x=1"
    await client.data.get_unverified("sg", "k")
    await client._http.aclose()


@pytest.mark.asyncio
async def test_client_secp256k1_requests_verify():
    def handler(request):
        assert request.headers["X-Signature"].startswith("0x")
        _server_verifies(request, SECP256K1_PUBLIC_KEY, "secp256k1")
        return _ok(request)

    client = _client(handler, algorithm="secp256k1")
    await client.data.query_unverified("sg", {})
    await client.privacy.get_my_key_grant("sg")
    await client._http.aclose()


@pytest.mark.asyncio
async def test_client_without_identity_sends_reads_unsigned():
    seen = []

    def handler(request):
        seen.append(request)
        return _ok(request)

    client = _client(handler, identity=False)
    await client.proof.get("sg", "k")
    await client.indexing.sql_query("sg", "SELECT 1", source=QuerySource.VALIDATOR)
    await client._http.aclose()
    for request in seen:
        assert "X-Signature" not in request.headers
        assert "X-Nonce" not in request.headers


@pytest.mark.asyncio
async def test_client_does_not_nonce_sign_indexer_requests():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"columns": ["n"], "rows": [[1]]})

    client = _client(handler, indexer_url="http://indexer.test")
    await client.indexing.sql_query("sg", "SELECT 1", source=QuerySource.INDEXER)
    await client._http.aclose()
    assert seen[0].url.host == "indexer.test"
    assert "X-Nonce" not in seen[0].headers
