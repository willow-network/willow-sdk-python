"""Tests for new operations: Token, Validator, Indexing."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from willow import WillowClient
from willow.types import (
    TokenInfo,
    BalanceInfo,
    FeeSchedule,
    ValidatorInfo,
    ValidatorStatus,
    GraphQLResponse,
    SubgroveInfo,
    SubgroveStatus,
    SubgroveIndexingStatus,
    IndexerInfo,
    IndexerStatus,
    VerificationStats,
    HealthStatus,
    AppRegistration,
    SubgroveRegistration,
    DidPermissions,
)


@pytest.fixture
def client():
    """Create test client."""
    return WillowClient("http://localhost:3031")


@pytest.fixture
def mock_http_client():
    """Create mock HTTP client."""
    return AsyncMock()


@pytest.fixture
def authenticated_client(client, mock_http_client):
    """Create authenticated client."""
    client.set_identity(
        "did:willow:test",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "#key1"
    )
    client._http = mock_http_client
    return client


class TestTokenOperations:
    """Test token operations."""

    @pytest.mark.asyncio
    async def test_get_info(self, client, mock_http_client):
        """Test get token info."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "name": "Willow",
                "symbol": "WILL",
                "decimals": 18,
                "total_supply": 1000000000,
                "minted_supply": 500000000
            }
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.token.get_info()

        assert isinstance(result, TokenInfo)
        assert result.name == "Willow"
        assert result.symbol == "WILL"
        assert result.decimals == 18
        assert result.total_supply == 1000000000

    @pytest.mark.asyncio
    async def test_get_balance(self, client, mock_http_client):
        """Test get balance for DID."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "account": "did:willow:test",
                "balance": 1000,
                "staked": 500,
                "unbonding": 100
            }
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.token.get_balance("did:willow:test")

        assert isinstance(result, BalanceInfo)
        assert result.account == "did:willow:test"
        assert result.balance == 1000
        assert result.staked == 500

    @pytest.mark.asyncio
    async def test_get_app_balance(self, client, mock_http_client):
        """Test get balance for app."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "account": "my-app",
                "balance": 5000,
                "staked": 0,
                "unbonding": 0
            }
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.token.get_app_balance("my-app")

        assert isinstance(result, BalanceInfo)
        assert result.account == "my-app"
        assert result.balance == 5000

    @pytest.mark.asyncio
    async def test_get_fee_schedule(self, client, mock_http_client):
        """Test get fee schedule."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "storage_fee_per_byte_per_day": 100,
                "query_fee": 10,
                "indexing_fee_per_block": 1000,
                "minimum_app_balance": 10000
            }
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.token.get_fee_schedule()

        assert isinstance(result, FeeSchedule)
        assert result.storage_fee_per_byte_per_day == 100
        assert result.query_fee == 10


class TestValidatorOperations:
    """Test validator operations."""

    @pytest.mark.asyncio
    async def test_list_validators(self, client, mock_http_client):
        """Test list validators."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": [
                {
                    "validator_did": "did:willow:validator1",
                    "name": "Validator 1",
                    "stake_amount": 100000,
                    "commission_rate": 500,
                    "status": "active",
                    "voting_power": 1000,
                    "delegator_count": 10
                },
                {
                    "validator_did": "did:willow:validator2",
                    "name": "Validator 2",
                    "stake_amount": 50000,
                    "commission_rate": 300,
                    "status": "active",
                    "voting_power": 500,
                    "delegator_count": 5
                }
            ]
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.validators.list()

        assert len(result) == 2
        assert isinstance(result[0], ValidatorInfo)
        assert result[0].validator_did == "did:willow:validator1"
        assert result[0].status == ValidatorStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_get_validator(self, client, mock_http_client):
        """Test get single validator."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "validator_did": "did:willow:validator1",
                "name": "Validator 1",
                "stake_amount": 100000,
                "commission_rate": 500,
                "status": "active",
                "voting_power": 1000,
                "delegator_count": 10
            }
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.validators.get("did:willow:validator1")

        assert isinstance(result, ValidatorInfo)
        assert result.validator_did == "did:willow:validator1"
        assert result.stake_amount == 100000

    @pytest.mark.asyncio
    async def test_get_total_staked(self, client, mock_http_client):
        """Test get total staked."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {"total_staked": 1000000}
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.validators.get_total_staked()

        assert result == 1000000

    @pytest.mark.asyncio
    async def test_get_active_count(self, client, mock_http_client):
        """Test get active validator count."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {"count": 10}
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.validators.get_active_count()

        assert result == 10


class TestIndexingOperations:
    """Test indexing operations."""

    @pytest.mark.asyncio
    async def test_graphql_query(self, client, mock_http_client):
        """Test GraphQL query."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "data": {"users": [{"id": "1", "name": "Alice"}]},
                "errors": None
            }
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.indexing.graphql_query(
            "my-subgrove",
            "query { users { id name } }",
            variables={"first": 10}
        )

        assert isinstance(result, GraphQLResponse)
        assert result.data["users"][0]["name"] == "Alice"

    @pytest.mark.asyncio
    async def test_list_subgroves(self, client, mock_http_client):
        """Test list subgroves."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": [
                {
                    "subgrove_id": "subgrove-1",
                    "name": "My Subgrove",
                    "owner_did": "did:willow:test",
                    "status": "synced",
                    "latest_block": 1000,
                    "indexers": ["indexer-1"],
                    "manifest_ipfs": "QmTest"
                }
            ]
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.indexing.list_subgroves()

        assert len(result) == 1
        assert isinstance(result[0], SubgroveInfo)
        assert result[0].status == SubgroveStatus.SYNCED

    @pytest.mark.asyncio
    async def test_get_indexing_status(self, client, mock_http_client):
        """Test get indexing status."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "subgrove_id": "subgrove-1",
                "synced_block": 900,
                "target_block": 1000,
                "progress_percentage": 90.0,
                "status": "syncing",
                "last_error": None
            }
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.indexing.get_indexing_status("subgrove-1")

        assert isinstance(result, SubgroveIndexingStatus)
        assert result.progress_percentage == 90.0

    @pytest.mark.asyncio
    async def test_list_indexers(self, client, mock_http_client):
        """Test list indexers."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": [
                {
                    "indexer_did": "did:willow:indexer1",
                    "subgroves": ["subgrove-1"],
                    "stake_amount": 50000,
                    "endpoint": "http://indexer1.example.com",
                    "status": "active",
                    "performance_score": 95.5,
                    "last_update": 1234567890
                }
            ]
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.indexing.list_indexers()

        assert len(result) == 1
        assert isinstance(result[0], IndexerInfo)
        assert result[0].status == IndexerStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_get_verification_stats(self, client, mock_http_client):
        """Test get verification stats."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "total_blocks": 1000,
                "verified_blocks": 950,
                "unverified_blocks": 40,
                "finalized_blocks": 900,
                "failed_blocks": 10,
                "verification_rate": 0.95
            }
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.indexing.get_verification_stats()

        assert isinstance(result, VerificationStats)
        assert result.verification_rate == 0.95


class TestHealthAndRootHash:
    """Test health and root hash operations."""

    @pytest.mark.asyncio
    async def test_health(self, client, mock_http_client):
        """Test health check."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "status": "healthy",
                "timestamp": 1234567890,
                "version": "0.2.0",
                "components": {}
            }
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.health()

        assert isinstance(result, HealthStatus)
        assert result.status == "healthy"
        assert result.version == "0.2.0"

    @pytest.mark.asyncio
    async def test_get_root_hash(self, client, mock_http_client):
        """Test get verified root hash."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {"root_hash": "abc123"}
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.get_root_hash()

        assert result == "abc123"

    @pytest.mark.asyncio
    async def test_get_root_hash_local(self, client, mock_http_client):
        """Test get local root hash."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {"root_hash": "def456"}
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.get_root_hash_local()

        assert result == "def456"


class TestRegistrationOperationsExtended:
    """Test extended registration operations."""

    @pytest.mark.asyncio
    async def test_list_apps(self, client, mock_http_client):
        """Test list apps."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": [
                {
                    "app_id": "app-1",
                    "name": "App 1",
                    "description": "Test app",
                    "app_type": "application",
                    "owner_did": "did:willow:test",
                    "admins": [],
                    "created_at": 1234567890,
                    "updated_at": 1234567890
                }
            ]
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.registration.list_apps()

        assert len(result) == 1
        assert isinstance(result[0], AppRegistration)
        assert result[0].app_id == "app-1"

    @pytest.mark.asyncio
    async def test_get_app(self, client, mock_http_client):
        """Test get app."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "app_id": "app-1",
                "name": "App 1",
                "description": "Test app",
                "app_type": "application",
                "owner_did": "did:willow:test",
                "admins": [],
                "created_at": 1234567890,
                "updated_at": 1234567890
            }
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.registration.get_app("app-1")

        assert isinstance(result, AppRegistration)
        assert result.name == "App 1"

    @pytest.mark.asyncio
    async def test_list_subgroves(self, client, mock_http_client):
        """Test list subgroves."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": [
                {
                    "subgrove_id": "subgrove-1",
                    "app_id": "app-1",
                    "name": "Subgrove 1",
                    "subgrove_path": ["data"],
                    "owner_did": "did:willow:test",
                    "writers": [],
                    "readers": [],
                    "created_at": 1234567890,
                    "updated_at": 1234567890
                }
            ]
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.registration.list_subgroves("app-1")

        assert len(result) == 1
        assert isinstance(result[0], SubgroveRegistration)

    @pytest.mark.asyncio
    async def test_get_permissions(self, client, mock_http_client):
        """Test get permissions."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "did": "did:willow:test",
                "owned_apps": ["app-1"],
                "admin_apps": ["app-2"],
                "write_access": ["app-1/subgrove-1"],
                "read_access": ["app-3/subgrove-1"]
            }
        }
        mock_http_client.request = AsyncMock(return_value=mock_response)
        client._http = mock_http_client

        result = await client.registration.get_permissions("did:willow:test")

        assert isinstance(result, DidPermissions)
        assert "app-1" in result.owned_apps
        assert "app-2" in result.admin_apps


class TestClientBuilder:
    """Test client builder."""

    def test_builder_basic(self):
        """Test basic builder."""
        client = WillowClient.builder("http://example.com").build()

        assert client.api_url == "http://example.com"

    def test_builder_with_timeout(self):
        """Test builder with timeout."""
        client = (
            WillowClient.builder("http://example.com")
            .timeout(120.0)
            .build()
        )

        assert client.timeout == 120.0

    def test_builder_chaining(self):
        """Test builder method chaining."""
        from willow.types import RetryConfig

        client = (
            WillowClient.builder("http://example.com")
            .timeout(60.0)
            .retry_config(RetryConfig(max_attempts=5))
            .build()
        )

        assert client.api_url == "http://example.com"
        assert client.timeout == 60.0
        assert client.retry_config.max_attempts == 5
