"""Tests for Willow client."""

import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock
from willow import WillowClient, generate_did
from willow.types import (
    DidDocument,

    RegisterDatasetRequest,
    SchemaDefinition,
    FieldType
)
from willow.errors import WillowError, AuthenticationError, NetworkError


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
    async def test_register_did(self, client, mock_http_client, did_info):
        """Test DID registration."""
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "success": True,
            "data": did_info["did_document"].model_dump(by_alias=True)
        }

        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        # Register DID
        result = await client.register_did(did_info["did_document"])

        assert isinstance(result, DidDocument)
        assert result.id == did_info["did"]
        mock_http_client.request.assert_called_once()

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
    client.set_identity(
        "did:test",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "#key1"
    )


class TestDataOperations:
    """Test data operations."""

    @pytest.mark.asyncio
    async def test_store_data(self, client, mock_http_client):
        """Test data storage."""
        # Set up identity for per-request auth
        _set_test_identity(client)

        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}

        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        # Store data
        await client.data.store("dataset1", {"key1": {"value": "test"}})

        mock_http_client.request.assert_called_once()
        call_args = mock_http_client.request.call_args
        assert call_args[0][0] == "POST"
        assert "data/dataset1" in call_args[0][1]

    @pytest.mark.asyncio
    async def test_get_data(self, client, mock_http_client):
        """Test data retrieval."""
        _set_test_identity(client)

        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {"value": "test"}
        }

        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        # Get data
        result = await client.data.get("dataset1", "key1")

        assert result == {"value": "test"}
        assert "data/dataset1/key1" in mock_http_client.request.call_args[0][1]

    @pytest.mark.asyncio
    async def test_update_data(self, client, mock_http_client):
        """Test data update."""
        _set_test_identity(client)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}

        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        # Update data
        await client.data.update("dataset1", "key1", {"value": "updated"})

        call_args = mock_http_client.request.call_args
        assert call_args[0][0] == "PUT"
        assert "data/dataset1/key1" in call_args[0][1]

    @pytest.mark.asyncio
    async def test_delete_data(self, client, mock_http_client):
        """Test data deletion."""
        _set_test_identity(client)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}

        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        # Delete data
        await client.data.delete("dataset1", "key1")

        call_args = mock_http_client.request.call_args
        assert call_args[0][0] == "DELETE"
        assert "data/dataset1/key1" in call_args[0][1]

    @pytest.mark.asyncio
    async def test_require_auth_decorator(self, client):
        """Test authentication requirement."""
        # No identity set
        with pytest.raises(WillowError, match="Not authenticated"):
            await client.data.get("dataset1", "key1")


class TestRegistrationOperations:
    """Test registration operations."""

    @pytest.mark.asyncio
    async def test_register_subgrove(self, client, mock_http_client):
        """Test subgrove registration."""
        _set_test_identity(client)


    @pytest.mark.asyncio
    async def test_register_dataset(self, client, mock_http_client):
        """Test dataset registration."""
        _set_test_identity(client)

        dataset_request = {
            "dataset_id": "test-dataset",
            
            "name": "Test Dataset",
            "dataset_path": ["collections"],
            "schema": {
                "version": 1,
                "fields": {"name": {"type": "string"}},
                "indexes": [],
                "required_fields": ["name"]
            },
            "owner_did": "did:test",
            "writers": ["did:test"],
            "readers": ["did:test"]
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": dataset_request
        }

        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.registration.register_dataset(dataset_request)

        assert result == dataset_request
        assert "register/subgrove" in mock_http_client.request.call_args[0][1]


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
