"""Tests for Willow client."""

import json

import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock
from willow import (
    WillowClient,
    generate_did,
    register_did_message,
    register_subgrove_message,
    store_data_message,
    verify_signature,
)
from willow.types import (
    RegisterDatasetRequest,
    SchemaDefinition,
    FieldType
)
from willow.errors import (
    WillowError, AuthenticationError, NetworkError, NotAuthenticatedError, ProofVerificationError,
)


def _tx_client(account_nonce=0, did_info=None):
    """A client on a mocked API that answers the account nonce and accepts
    every transaction, recording each request."""
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path.endswith("/nonce"):
            data = {"did": "x", "nonce": account_nonce}
        elif request.url.path == "/tx/submit":
            data = {"tx_hash": "AB", "code": 0, "log": ""}
        else:
            return httpx.Response(404, json={"success": False, "data": None, "error": "no route"})
        return httpx.Response(200, json={"success": True, "data": data, "error": None})

    client = WillowClient("http://api.test")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    if did_info is not None:
        client.set_identity(
            did_info["did"], did_info["private_key"], did_info["public_key_id"], did_info["algorithm"]
        )
    return client, seen


def _submitted(seen):
    return [json.loads(r.content) for r in seen if r.url.path == "/tx/submit"]


@pytest.fixture
def client():
    """Create test client."""
    return WillowClient("http://localhost:3031")


@pytest.fixture
def mock_http_client():
    """Create mock HTTP client."""
    mock = AsyncMock()
    return mock


@pytest.fixture
def did_info():
    """Generate test DID info."""
    return generate_did("Ed25519")


class TestWillowClient:
    """Test WillowClient class."""

    @pytest.mark.asyncio
    async def test_client_initialization(self):
        """Test client initialization."""
        client = WillowClient("http://example.com", timeout=60.0)

        assert client.api_url == "http://example.com"
        assert client.timeout == 60.0
        assert not client.is_authenticated()
        assert hasattr(client, "data")
        assert hasattr(client, "registration")
        assert hasattr(client, "proof")

        await client.close()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager."""
        async with WillowClient() as client:
            assert isinstance(client, WillowClient)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("algorithm", ["Ed25519", "secp256k1"])
    async def test_register_did(self, algorithm):
        """register_did sends a RegisterDid transaction to /tx/submit, signed
        with the document's key over the node's JSON of the document, nonce 1."""
        info = generate_did(algorithm)
        client, seen = _tx_client(did_info=info)

        result = await client.register_did(info["did_document"])

        assert result == {"tx_hash": "AB", "code": 0, "log": "", "did": info["did"], "nonce": 1}
        assert [(r.method, r.url.path) for r in seen] == [("POST", "/tx/submit")]
        ((kind, body),) = _submitted(seen)[0].items()
        assert kind == "RegisterDid"
        assert (body["nonce"], body["public_key_id"]) == (1, info["public_key_id"])
        document = body["did_document"]
        assert list(document) == [
            "id", "public_keys", "authentication", "service", "created", "updated", "proof",
        ]
        assert list(document["public_keys"][0]) == [
            "id", "type", "controller", "public_key_base58", "public_key_hex",
        ]
        # Signed over the node's serialization of the document it decodes.
        message = json.dumps(document, separators=(",", ":"), ensure_ascii=False)
        assert message == register_did_message(info["did_document"])
        assert verify_signature(
            message, bytes(body["signature"]).hex(), info["public_key"], algorithm
        )
        await client.close()

    @pytest.mark.asyncio
    async def test_register_did_takes_an_explicit_key(self):
        info = generate_did()
        client, seen = _tx_client()
        await client.register_did(info["did_document"], private_key_hex=info["private_key"])
        body = _submitted(seen)[0]["RegisterDid"]
        assert body["public_key_id"] == info["public_key_id"]
        assert verify_signature(
            register_did_message(info["did_document"]),
            bytes(body["signature"]).hex(),
            info["public_key"],
            "Ed25519",
        )
        await client.close()

    @pytest.mark.asyncio
    async def test_register_did_signs_in_the_algorithm_the_documents_key_names(self):
        # No algorithm passed: a secp256k1 key signs secp256k1, both with an
        # explicit key and with an identity set without its algorithm.
        info = generate_did("secp256k1")
        client, seen = _tx_client()
        await client.register_did(info["did_document"], private_key_hex=info["private_key"])
        client.set_identity(info["did"], info["private_key"], info["public_key_id"])  # Ed25519 default
        await client.register_did(info["did_document"])
        for body in (tx["RegisterDid"] for tx in _submitted(seen)):
            assert verify_signature(
                register_did_message(info["did_document"]),
                bytes(body["signature"]).hex(),
                info["public_key"],
                "secp256k1",
            )
        await client.close()

    @pytest.mark.asyncio
    async def test_register_did_needs_the_documents_key(self):
        info, other = generate_did(), generate_did()
        client, seen = _tx_client(did_info=other)
        with pytest.raises(NotAuthenticatedError):
            await client.register_did(info["did_document"])
        assert seen == []
        await client.close()

    @pytest.mark.asyncio
    async def test_set_identity(self, client, did_info):
        """Test setting identity for per-request auth."""
        assert not client.is_authenticated()

        # Set identity
        client.set_identity(
            did_info["did"],
            did_info["private_key"],
            did_info["public_key_id"]
        )

        assert client.is_authenticated()
        assert client._did == did_info["did"]
        assert client._private_key == did_info["private_key"]
        assert client._public_key_id == did_info["public_key_id"]
        # Algorithm defaults to Ed25519 when not supplied.
        assert client._algorithm == "Ed25519"

    @pytest.mark.asyncio
    async def test_set_identity_secp256k1_algorithm(self, client):
        """set_identity stores an explicit secp256k1 algorithm."""
        info = generate_did("secp256k1")
        client.set_identity(
            info["did"], info["private_key"], info["public_key_id"], "secp256k1"
        )
        assert client._algorithm == "secp256k1"
        # clear_identity resets the algorithm back to the default.
        client.clear_identity()
        assert client._algorithm == "Ed25519"

    @pytest.mark.asyncio
    async def test_secp256k1_identity_signs_requests_with_secp256k1(self):
        """A secp256k1 identity must sign per-request auth with secp256k1.

        Regression guard for the self-certifying DID migration: the algorithm
        can no longer be parsed from the ``did:willow:z...`` string, so it is
        threaded through ``set_identity`` into ``sign_request``. Before the fix
        the client defaulted to Ed25519 and secp256k1 auth silently failed.
        """
        from willow.auth import verify_signature

        info = generate_did("secp256k1")
        client = WillowClient("http://localhost:3031")
        client.set_identity(
            info["did"], info["private_key"], info["public_key_id"], "secp256k1"
        )

        captured = {}
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True, "data": []}

        async def fake_request(method, url, content=None, headers=None):
            captured["headers"] = headers
            return mock_response

        client._http.request = AsyncMock(side_effect=fake_request)

        await client.privacy.list_key_grantees("my-subgrove")

        headers = captured["headers"]
        assert headers["X-DID"] == info["did"]
        # A key-grant read: signed in the older form, secp256k1 sent 0x-prefixed.
        assert "X-Nonce" not in headers
        assert headers["X-Signature"].startswith("0x")
        message = f"GET:/key-grants/my-subgrove:{headers['X-Timestamp']}"
        # The captured signature verifies under secp256k1 (the true algorithm)...
        assert verify_signature(
            message, headers["X-Signature"], info["public_key"], "secp256k1"
        )
        # ...and would NOT verify had the client defaulted to Ed25519.
        assert not verify_signature(
            message, headers["X-Signature"], info["public_key"], "Ed25519"
        )
        await client.close()

    def test_computed_field_registration(self, client):
        """The client's computed-field methods reach the registry."""
        from willow.computed_fields import UNISWAP_V2_PAIR_FIELDS

        assert not client.has_computed_fields("pairs")
        client.register_computed_fields("pairs", UNISWAP_V2_PAIR_FIELDS)
        assert client.has_computed_fields("pairs")
        assert client.unregister_computed_fields("pairs")
        assert not client.has_computed_fields("pairs")

    @pytest.mark.asyncio
    async def test_is_authenticated(self, client):
        """Test authentication status check."""
        assert not client.is_authenticated()

        # Set identity
        client.set_identity(
            "did:test",
            "private-key-hex",
            "#key1"
        )
        assert client.is_authenticated()

        # Clear identity
        client.clear_identity()
        assert not client.is_authenticated()

    @pytest.mark.asyncio
    async def test_clear_identity(self, client):
        """Test identity clearing."""
        client.set_identity(
            "did:test",
            "private-key-hex",
            "#key1"
        )

        client.clear_identity()
        assert client._did is None
        assert client._private_key is None
        assert client._public_key_id is None
        assert not client.is_authenticated()

    @pytest.mark.asyncio
    async def test_error_handling(self, client, mock_http_client):
        """Test error response handling."""
        # Mock error response
        error_response = MagicMock()
        error_response.status_code = 400
        error_response.json.return_value = {
            "success": False,
            "error": "Bad request"
        }

        mock_http_client.request = AsyncMock(return_value=error_response)
        client._http = mock_http_client

        with pytest.raises(WillowError) as exc_info:
            await client._request("GET", "/test")

        assert exc_info.value.status_code == 400
        assert "Bad request" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_network_error_handling(self, client, mock_http_client):
        """Test network error handling."""
        mock_http_client.request = AsyncMock(
            side_effect=httpx.NetworkError("Connection failed")
        )
        client._http = mock_http_client

        with pytest.raises(NetworkError) as exc_info:
            await client._request("GET", "/test")

        assert "Network error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_timeout_handling(self, client, mock_http_client):
        """Test timeout handling."""
        mock_http_client.request = AsyncMock(
            side_effect=httpx.TimeoutException("Request timed out")
        )
        client._http = mock_http_client

        with pytest.raises(NetworkError) as exc_info:
            await client._request("GET", "/test")

        assert "timed out" in str(exc_info.value)


def _set_test_identity(client):
    """Helper to set a test identity on a client."""
    # RFC 8032 §7.1 Test 2 Ed25519 vector.
    client.set_identity(
        "did:test",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "#key1"
    )


class TestDataOperations:
    """Test data operations."""

    @pytest.mark.asyncio
    async def test_store_data(self):
        """Each key is a StoreData transaction sent to /tx/submit, under
        consecutive nonces, signed over the message built from its own fields."""
        info = generate_did()
        client, seen = _tx_client(account_nonce=6, did_info=info)

        results = await client.data.store(
            "dataset1", {"key1": {"value": "test"}, "key2": {"b": 2, "a": 1}}
        )

        assert len(results) == 2
        assert [(r.method, r.url.path) for r in seen] == [
            ("GET", f"/account/{info['did']}/nonce"),
            ("POST", "/tx/submit"),
            ("POST", "/tx/submit"),
        ]
        bodies = [tx["StoreData"] for tx in _submitted(seen)]
        assert [(b["key"], b["nonce"]) for b in bodies] == [("key1", 7), ("key2", 8)]
        assert bytes(bodies[1]["data"]) == b'{"a":1,"b":2}'
        for body in bodies:
            assert body["owner_did"] == info["did"]
            message = store_data_message(
                body["subgrove_id"], body["key"], body["owner_did"], bytes(body["data"]), body["nonce"]
            )
            assert verify_signature(message, bytes(body["signature"]).hex(), info["public_key"], "Ed25519")
        await client.close()

    @pytest.mark.asyncio
    async def test_store_data_refuses_a_value_that_is_not_an_object(self):
        client, seen = _tx_client(did_info=generate_did())
        with pytest.raises(TypeError, match="JSON object"):
            await client.data.store_item("dataset1", "key1", "not an object")
        with pytest.raises(ValueError, match="line break"):
            await client.data.store("dataset1", {"ok": {}, "bad\nkey": {}})
        # NaN and the infinities are not JSON: the node would refuse the data.
        for value in (float("nan"), float("inf"), float("-inf")):
            with pytest.raises(ValueError):
                await client.data.store("dataset1", {"ok": {}, "bad": {"x": value}})
        assert seen == []
        await client.close()

    @pytest.mark.asyncio
    async def test_get_data_without_a_proof_raises(self, client, mock_http_client):
        """``get`` reads the value and its proof; a value with no proof is not
        returned (``get_unverified`` reads it without one)."""
        _set_test_identity(client)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {"value": "test"}
        }

        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client
        client.consensus_rpc_url = "http://localhost:26657"

        with pytest.raises(ProofVerificationError, match="no proof"):
            await client.data.get("dataset1", "key1")
        called_urls = [c.args[1] for c in mock_http_client.request.call_args_list]
        assert any("data/dataset1/key1" in url for url in called_urls), called_urls
        assert any("proof/dataset1/key1" in url for url in called_urls), called_urls

        assert await client.data.get_unverified("dataset1", "key1") == {"value": "test"}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation,args,kind", [
        ("update", ("dataset1", "key1", {"value": "updated"}), "UpdateData"),
        ("delete", ("dataset1", "key1"), "DeleteData"),
    ])
    async def test_unsupported_data_writes_name_the_supported_path(
        self, client, mock_http_client, operation, args, kind
    ):
        """The API serves no REST data writes; the SDK builds no UpdateData or
        DeleteData, so these raise without a request."""
        _set_test_identity(client)
        mock_http_client.request = AsyncMock()
        client._http = mock_http_client

        with pytest.raises(WillowError) as exc_info:
            await getattr(client.data, operation)(*args)

        assert kind in str(exc_info.value)
        assert "POST /tx/submit" in str(exc_info.value)
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_require_auth_decorator(self, client):
        """Test authentication requirement."""
        # No identity set
        with pytest.raises(WillowError, match="Not authenticated"):
            await client.data.get("dataset1", "key1")


class TestRegistrationOperations:
    """Test registration operations."""

    @pytest.mark.asyncio
    async def test_register_dataset(self):
        """A registration request is a RegisterSubgrove transaction with every
        field explicit, signed over its Config, sent to /tx/submit."""
        info = generate_did()
        client, seen = _tx_client(account_nonce=2, did_info=info)

        dataset_request = {
            "dataset_id": "test-dataset",
            "name": "Test Dataset",
            "dataset_path": ["collections"],
            "schema": {
                "version": 1,
                "fields": {"name": {"type": "string", "required": True}},
                "required_fields": [],
            },
            "owner_did": info["did"],
            "writers": [info["did"]],
            "readers": ["did:willow:reader"],
        }

        result = await client.registration.register_dataset(dataset_request)

        assert result == {"tx_hash": "AB", "code": 0, "log": "", "did": info["did"], "nonce": 3}
        assert [(r.method, r.url.path) for r in seen] == [
            ("GET", f"/account/{info['did']}/nonce"),
            ("POST", "/tx/submit"),
        ]
        body = _submitted(seen)[0]["RegisterSubgrove"]
        assert (body["subgrove_id"], body["name"], body["nonce"]) == ("test-dataset", "Test Dataset", 3)
        assert body["mode"] == {"DataStorage": {
            "name": "Test Dataset",
            "writers": [info["did"]],
            "free_readers": ["did:willow:reader"],
            "read_pricing": None,
        }}
        # The node's schema form: field -> type, required fields listed.
        assert json.loads(body["schema"]) == {
            "version": 1,
            "fields": {"name": "string"},
            "indexes": [],
            "required_fields": ["name"],
        }
        assert verify_signature(
            register_subgrove_message(body), bytes(body["signature"]).hex(), info["public_key"], "Ed25519"
        )
        await client.close()

    @pytest.mark.asyncio
    async def test_register_subgrove_is_signed_by_its_owner(self):
        info = generate_did()
        client, seen = _tx_client(did_info=info)
        with pytest.raises(ValueError, match="owner_did"):
            await client.registration.register_subgrove({
                "subgrove_id": "sg", "name": "n", "owner_did": "did:willow:someone-else",
                "schema": {"version": 1, "fields": {}},
            })
        assert seen == []
        await client.close()


class TestProofOperations:
    """Test proof operations."""

    @pytest.mark.asyncio
    async def test_get_proof(self, client, mock_http_client):
        """Test proof retrieval."""
        # Note: Proof operations don't require authentication
        proof_data = {
            "proof": "0xabcdef123456",
            "value": {"test": "data"}
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": proof_data
        }

        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.proof.get("dataset1", "key1")

        assert result["proof"] == proof_data["proof"]
        assert result["value"] == proof_data["value"]
        assert "proof/dataset1/key1" in mock_http_client.request.call_args[0][1]
