"""Tests for Willow client."""

import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock
from willow import WillowClient, generate_did
from willow.types import (
    DidDocument, 
    AuthenticationChallenge, 
    Session,
    RegisterAppRequest,
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
        assert client.session is None
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
    async def test_authenticate(self, client, mock_http_client, did_info):
        """Test authentication flow."""
        # Mock challenge response
        challenge_response = MagicMock()
        challenge_response.status_code = 200
        challenge_response.json.return_value = {
            "success": True,
            "data": {
                "challenge": "test-challenge",
                "timestamp": 1234567890
            }
        }
        
        # Mock verify response
        verify_response = MagicMock()
        verify_response.status_code = 200
        verify_response.json.return_value = {
            "success": True,
            "data": {
                "did": did_info["did"],
                "token": "test-token",
                "expires_at": 9999999999
            }
        }
        
        mock_http_client.request = AsyncMock(
            side_effect=[challenge_response, verify_response]
        )
        client._http = mock_http_client
        
        # Authenticate
        session = await client.authenticate(
            did_info["did"],
            did_info["private_key"],
            did_info["public_key_id"]
        )
        
        assert isinstance(session, Session)
        assert session.did == did_info["did"]
        assert session.token == "test-token"
        assert client.is_authenticated()
        assert mock_http_client.request.call_count == 2
    
    @pytest.mark.asyncio
    async def test_is_authenticated(self, client):
        """Test authentication status check."""
        assert not client.is_authenticated()
        
        # Set valid session
        client.session = Session(
            did="did:test",
            token="token",
            expires_at=9999999999999
        )
        assert client.is_authenticated()
        
        # Set expired session
        client.session = Session(
            did="did:test",
            token="token",
            expires_at=1000
        )
        assert not client.is_authenticated()
    
    @pytest.mark.asyncio
    async def test_clear_session(self, client):
        """Test session clearing."""
        client.session = Session(
            did="did:test",
            token="token",
            expires_at=9999999999
        )
        
        client.clear_session()
        assert client.session is None
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


class TestDataOperations:
    """Test data operations."""
    
    @pytest.mark.asyncio
    async def test_store_data(self, client, mock_http_client):
        """Test data storage."""
        # Set up authenticated session
        client.session = Session(
            did="did:test",
            token="test-token",
            expires_at=9999999999
        )
        
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client
        
        # Store data
        await client.data.store("app1", "dataset1", {"key1": {"value": "test"}})
        
        mock_http_client.request.assert_called_once()
        call_args = mock_http_client.request.call_args
        assert call_args[0][0] == "POST"
        assert "data/app1/dataset1" in call_args[0][1]
    
    @pytest.mark.asyncio
    async def test_get_data(self, client, mock_http_client):
        """Test data retrieval."""
        client.session = Session(
            did="did:test",
            token="test-token",
            expires_at=9999999999
        )
        
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
        result = await client.data.get("app1", "dataset1", "key1")
        
        assert result == {"value": "test"}
        assert "data/app1/dataset1/key1" in mock_http_client.request.call_args[0][1]
    
    @pytest.mark.asyncio
    async def test_update_data(self, client, mock_http_client):
        """Test data update."""
        client.session = Session(
            did="did:test",
            token="test-token",
            expires_at=9999999999
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client
        
        # Update data
        await client.data.update("app1", "dataset1", "key1", {"value": "updated"})
        
        call_args = mock_http_client.request.call_args
        assert call_args[0][0] == "PUT"
        assert "data/app1/dataset1/key1" in call_args[0][1]
    
    @pytest.mark.asyncio
    async def test_delete_data(self, client, mock_http_client):
        """Test data deletion."""
        client.session = Session(
            did="did:test",
            token="test-token",
            expires_at=9999999999
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client
        
        # Delete data
        await client.data.delete("app1", "dataset1", "key1")
        
        call_args = mock_http_client.request.call_args
        assert call_args[0][0] == "DELETE"
        assert "data/app1/dataset1/key1" in call_args[0][1]
    
    @pytest.mark.asyncio
    async def test_require_auth_decorator(self, client):
        """Test authentication requirement."""
        # No session
        with pytest.raises(WillowError, match="Not authenticated"):
            await client.data.get("app1", "dataset1", "key1")


class TestRegistrationOperations:
    """Test registration operations."""
    
    @pytest.mark.asyncio
    async def test_register_app(self, client, mock_http_client):
        """Test app registration."""
        client.session = Session(
            did="did:test",
            token="test-token",
            expires_at=9999999999
        )
        
        app_request = {
            "app_id": "test-app",
            "name": "Test App",
            "description": "Test",
            "app_type": "test",
            "owner_did": "did:test",
            "admins": []
        }
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": app_request
        }
        
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client
        
        result = await client.registration.register_app(app_request)
        
        assert result == app_request
        assert "register/app" in mock_http_client.request.call_args[0][1]
    
    @pytest.mark.asyncio
    async def test_register_dataset(self, client, mock_http_client):
        """Test dataset registration."""
        client.session = Session(
            did="did:test",
            token="test-token",
            expires_at=9999999999
        )
        
        dataset_request = {
            "dataset_id": "test-dataset",
            "app_id": "test-app",
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
        
        result = await client.proof.get("app1", "dataset1", "key1")
        
        assert result["proof"] == proof_data["proof"]
        assert result["value"] == proof_data["value"]
        assert "proof/app1/dataset1/key1" in mock_http_client.request.call_args[0][1]