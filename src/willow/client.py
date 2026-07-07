"""Main client for Willow SDK.

This module provides the main WillowClient class for interacting with
the Willow decentralized data indexing protocol.
"""

import asyncio
import httpx
import logging
from typing import Optional, Dict, Any, List, TYPE_CHECKING

from .types import (
    DidDocument,
    
    RegisterDatasetRequest,
    ApiResponse,
    ProofData,
    QueryRequest,
    QueryResponse,
    
    SubgroveRegistration,
    DidPermissions,
    TokenInfo,
    BalanceInfo,
    FeeSchedule,
    ValidatorInfo,
    GraphQLResponse,
    SqlRequest,
    SqlResponse,
    SubgroveInfo,
    SubgroveIndexingStatus,
    IndexerInfo,
    VerificationStats,
    HealthStatus,
    RetryConfig,
)
from .auth import sign_request, SignatureAlgorithm
from .errors import (
    WillowError,
    AuthenticationError,
    NetworkError,
    NotAuthenticatedError,
    ProofVerificationError,
    parse_api_error,
)
from .indexers import (
    WillowIndexers,
    QuerySource,
    RoutedQueryResult,
    ServedBy,
    ValidatorHasNoDataError,
    NoIndexersReachableError,
)
from .utils import require_auth
from .proof import ProofVerifier, ProofVerificationOptions, configure_proof_verification
from .computed_fields import (
    ComputedFieldRegistry,
    ComputedFieldSet,
    apply_computed_fields_to_response,
)
from .privacy import PrivacyOperations
from .files import FileOperations
from .completeness import CompletenessOperations

if TYPE_CHECKING:
    from .light_client import LightClient

logger = logging.getLogger(__name__)


class DataOperations:
    """Data operations for Willow client.

    Provides methods for storing, retrieving, updating, and querying data
    with automatic proof verification for secure operations.
    """

    def __init__(self, client: "WillowClient"):
        self.client = client

    @require_auth
    async def store(self, subgrove_id: str, data: Dict[str, Any]) -> None:
        """Store data in a subgrove.

        Args:

            subgrove_id: Subgrove/dataset identifier
            data: Data to store (key-value pairs)
        """
        await self.client._request(
            "POST",
            f"/data/{subgrove_id}",
            json=data,
            authenticated=True
        )

    @require_auth
    async def store_item(
        self,
        subgrove_id: str,
        key: str,
        value: Any
    ) -> None:
        """Store a single item in a subgrove.

        Args:

            subgrove_id: Subgrove/dataset identifier
            key: Item key
            value: Item value
        """
        await self.store(subgrove_id, {key: value})

    @require_auth
    async def get(self, subgrove_id: str, key: str) -> Dict[str, Any]:
        """Get a single item from a subgrove with automatic proof verification.

        This method fetches data and automatically verifies the cryptographic
        proof against the consensus root hash for security.

        Args:

            subgrove_id: Subgrove/dataset identifier
            key: Item key

        Returns:
            The data item

        Raises:
            ProofVerificationError: If proof verification fails
        """
        # First get the data
        data_response = await self.client._request(
            "GET",
            f"/data/{subgrove_id}/{key}",
            authenticated=True
        )
        data = data_response["data"]

        # Then get the proof
        try:
            proof_response = await self.client._request(
                "GET",
                f"/proof/{subgrove_id}/{key}",
                authenticated=True
            )

            if proof_response.get("data") and proof_response["data"].get("proof"):
                proof_hex = proof_response["data"]["proof"]

                # Verify the proof
                result = ProofVerifier.verify_item_proof(proof_hex, key, data)
                if result.error:
                    raise ProofVerificationError(f"Proof verification failed: {result.error}")

                # Compare with consensus root hash
                try:
                    consensus_root = await self.client.get_root_hash()
                    if result.root_hash != consensus_root:
                        raise ProofVerificationError(
                            f"Root hash mismatch: computed {result.root_hash} vs consensus {consensus_root}"
                        )
                except ProofVerificationError:
                    raise
                except Exception as e:
                    logger.warning(f"Could not fetch consensus root hash for verification: {e}")
            else:
                logger.warning(f"No proof available for key: {key}")

        except ProofVerificationError:
            raise
        except Exception as e:
            logger.warning(f"Could not fetch proof for key {key}: {e}")

        return data

    @require_auth
    async def get_unverified(self, subgrove_id: str, key: str) -> Dict[str, Any]:
        """Get a single item from a subgrove without proof verification.

        Use this method when performance is more important than cryptographic
        verification, such as in trusted environments.

        Args:

            subgrove_id: Subgrove/dataset identifier
            key: Item key

        Returns:
            The data item
        """
        response = await self.client._request(
            "GET",
            f"/data/{subgrove_id}/{key}",
            authenticated=True
        )
        return response["data"]

    @require_auth
    async def update(self, subgrove_id: str, key: str, data: Dict[str, Any]) -> None:
        """Update an item in a subgrove.

        Args:

            subgrove_id: Subgrove/dataset identifier
            key: Item key
            data: New data
        """
        await self.client._request(
            "PUT",
            f"/data/{subgrove_id}/{key}",
            json=data,
            authenticated=True
        )

    @require_auth
    async def delete(self, subgrove_id: str, key: str) -> None:
        """Delete an item from a subgrove.

        Args:

            subgrove_id: Subgrove/dataset identifier
            key: Item key
        """
        await self.client._request(
            "DELETE",
            f"/data/{subgrove_id}/{key}",
            authenticated=True
        )

    @require_auth
    async def query(self, subgrove_id: str, query: Dict[str, Any]) -> QueryResponse:
        """Query indexed data with automatic proof verification.

        Args:

            subgrove_id: Subgrove/dataset identifier
            query: Query parameters (filters, search, sort, limit, offset)

        Returns:
            Query response with documents and optional proof

        Raises:
            ProofVerificationError: If proof verification fails
        """
        # Convert dict to QueryRequest for validation
        query_request = QueryRequest(**query)

        # Always request proof by default for security
        query_dict = query_request.model_dump(exclude_none=True)
        query_dict["include_proof"] = True

        response = await self.client._request(
            "POST",
            f"/query/{subgrove_id}",
            json=query_dict,
            authenticated=True
        )

        query_response = QueryResponse(**response["data"])

        # Verify proof if present
        if query_response.proof:
            result = ProofVerifier.verify_query_proof(query_response.proof, query_response.documents)
            if result.error:
                raise ProofVerificationError(f"Query proof verification failed: {result.error}")

            # Compare with consensus root hash
            try:
                consensus_root = await self.client.get_root_hash()
                if result.root_hash != consensus_root:
                    raise ProofVerificationError(
                        f"Root hash mismatch: computed {result.root_hash} vs consensus {consensus_root}"
                    )
            except ProofVerificationError:
                raise
            except Exception as e:
                logger.warning(f"Could not fetch consensus root hash for verification: {e}")

        # Apply computed fields if registered for this app/dataset
        computed_fields = self.client._computed_fields.get(subgrove_id, subgrove_id)
        if computed_fields:
            query_response = apply_computed_fields_to_response(query_response, computed_fields)

        return query_response

    @require_auth
    async def query_unverified(self, subgrove_id: str, query: Dict[str, Any]) -> QueryResponse:
        """Query indexed data without proof verification.

        Use this method when performance is more important than cryptographic
        verification.

        Args:

            subgrove_id: Subgrove/dataset identifier
            query: Query parameters

        Returns:
            Query response with documents
        """
        # Convert dict to QueryRequest for validation
        query_request = QueryRequest(**query)

        # Explicitly disable proof for performance
        query_dict = query_request.model_dump(exclude_none=True)
        query_dict["include_proof"] = False

        response = await self.client._request(
            "POST",
            f"/query/{subgrove_id}",
            json=query_dict,
            authenticated=True
        )
        query_response = QueryResponse(**response["data"])

        # Apply computed fields if registered for this app/dataset
        computed_fields = self.client._computed_fields.get(subgrove_id, subgrove_id)
        if computed_fields:
            query_response = apply_computed_fields_to_response(query_response, computed_fields)

        return query_response

    @require_auth
    async def batch_store(self, subgrove_id: str, items: List[Dict[str, Any]]) -> None:
        """Store multiple items in a subgrove.

        Args:

            subgrove_id: Subgrove/dataset identifier
            items: List of items with "key" and "value" fields
        """
        # Convert list of {key, value} to dict
        data = {item["key"]: item["value"] for item in items}
        await self.store(subgrove_id, data)

    async def get_checkpoint_state_root(self, subgrove_id: str, checkpoint_id: str) -> "CheckpointInfo":
        """Get checkpoint information including state root.

        Args:
            subgrove_id: Subgrove/dataset identifier
            checkpoint_id: Checkpoint ID (hex string)

        Returns:
            Checkpoint information
        """
        from .types import CheckpointInfo
        response = await self.client._request(
            "GET",
            f"/checkpoints/{subgrove_id}/{checkpoint_id}/state-root"
        )
        return CheckpointInfo(**response["data"])

    async def query_historical(
        self,
        subgrove_id: str,
        checkpoint_id: str,
        query: Dict[str, Any]
    ) -> "HistoricalQueryResponse":
        """Query historical indexed data from a checkpoint.

        Routes through consensus to available indexer nodes that serve
        historical data for this checkpoint.

        Args:
            subgrove_id: Subgrove/dataset identifier
            checkpoint_id: Checkpoint ID (hex string)
            query: Query parameters (path, key, query_type, include_proof)

        Returns:
            Historical query response with data and optional proof
        """
        from .types import HistoricalQueryRequest, HistoricalQueryResponse

        query_request = HistoricalQueryRequest(**query)
        response = await self.client._request(
            "POST",
            f"/historical/query/{subgrove_id}/{checkpoint_id}",
            json=query_request.model_dump(exclude_none=True)
        )
        return HistoricalQueryResponse(**response["data"])

    async def query_historical_verified(
        self,
        subgrove_id: str,
        checkpoint_id: str,
        query: Dict[str, Any]
    ) -> "HistoricalQueryResponse":
        """Query historical data with automatic proof verification.

        Forces proof inclusion and verifies the proof against the
        checkpoint's state root.

        Args:
            subgrove_id: Subgrove/dataset identifier
            checkpoint_id: Checkpoint ID (hex string)
            query: Query parameters (path, key, query_type)

        Returns:
            Verified historical query response

        Raises:
            ProofVerificationError: If proof verification fails
            WillowError: If proof is missing from response
        """
        from .types import HistoricalQueryRequest, HistoricalQueryResponse
        from .errors import WillowError, ProofVerificationError

        # Force proof inclusion
        query["include_proof"] = True

        result = await self.query_historical(subgrove_id, checkpoint_id, query)

        # Verify the proof against checkpoint state root
        result.verify_proof()

        return result


class RegistrationOperations:
    """Registration operations for Willow client.

    Provides methods for registering and querying apps, subgroves,
    and DID permissions.
    """

    def __init__(self, client: "WillowClient"):
        self.client = client

    @require_auth
    async def register_subgrove(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new subgrove/dataset.

        Args:
            request: Subgrove registration request data

        Returns:
            Registration result
        """
        # Handle subgrove_id -> dataset_id alias for compatibility
        if "subgrove_id" in request:
            request["dataset_id"] = request.pop("subgrove_id")

        dataset_request = RegisterDatasetRequest(**request)
        response = await self.client._request(
            "POST",
            "/register/subgrove",
            json=dataset_request.model_dump(by_alias=True, exclude_none=True),
            authenticated=True
        )
        return response["data"]

    # Alias for compatibility
    register_dataset = register_subgrove

    async def list_subgroves(self) -> List[SubgroveRegistration]:
        """List all subgroves.

        Returns:
            List of subgrove registrations
        """
        response = await self.client._request("GET", "/subgroves")
        return [SubgroveRegistration(**sg) for sg in response.get("data", [])]

    # Alias for compatibility
    list_datasets = list_subgroves

    async def get_subgrove(self, subgrove_id: str) -> SubgroveRegistration:
        """Get subgrove registration details.

        Args:

            subgrove_id: Subgrove identifier

        Returns:
            Subgrove registration details
        """
        response = await self.client._request("GET", f"/subgroves/{subgrove_id}")
        return SubgroveRegistration(**response["data"])

    # Alias for compatibility
    get_dataset = get_subgrove

    async def get_permissions(self, did: str) -> DidPermissions:
        """Get permissions for a DID.

        Args:
            did: DID to query permissions for

        Returns:
            DID permissions including owned apps, admin access, etc.
        """
        response = await self.client._request("GET", f"/permissions/{did}")
        return DidPermissions(**response["data"])


class ProofOperations:
    """Proof operations for Willow client.

    Provides methods for fetching Merkle proofs for data verification.
    """

    def __init__(self, client: "WillowClient"):
        self.client = client

    async def get(self, subgrove_id: str, key: str) -> Dict[str, Any]:
        """Get Merkle proof for a data item.

        Args:

            subgrove_id: Subgrove identifier
            key: Item key

        Returns:
            Proof data including proof hex and value
        """
        response = await self.client._request(
            "GET",
            f"/proof/{subgrove_id}/{key}"
        )
        return ProofData(**response["data"]).model_dump()


class TokenOperations:
    """Token operations for Willow client.

    Provides methods for querying token information and balances.
    """

    def __init__(self, client: "WillowClient"):
        self.client = client

    async def get_info(self) -> TokenInfo:
        """Get token information.

        Returns:
            Token info including name, symbol, decimals, supply
        """
        response = await self.client._request("GET", "/token/info")
        return TokenInfo(**response["data"])

    async def get_balance(self, did: str) -> BalanceInfo:
        """Get balance for a DID.

        Args:
            did: DID to query balance for

        Returns:
            Balance information
        """
        response = await self.client._request("GET", f"/token/balance/{did}")
        return BalanceInfo(**response["data"])

    async def get_subgrove_balance(self, subgrove_id: str) -> BalanceInfo:
        """Get balance for a subgrove.

        Args:
            subgrove_id: Subgrove identifier

        Returns:
            Balance information
        """
        response = await self.client._request("GET", f"/token/balance/subgrove/{subgrove_id}")
        return BalanceInfo(**response["data"])

    async def get_fee_schedule(self) -> FeeSchedule:
        """Get the current fee schedule.

        Returns:
            Fee schedule with storage, query, and indexing fees
        """
        response = await self.client._request("GET", "/token/fees")
        return FeeSchedule(**response["data"])


class ValidatorOperations:
    """Validator operations for Willow client.

    Provides methods for querying validator information.
    """

    def __init__(self, client: "WillowClient"):
        self.client = client

    async def list(self) -> List[ValidatorInfo]:
        """List all validators.

        Returns:
            List of validator information
        """
        response = await self.client._request("GET", "/validators")
        return [ValidatorInfo(**v) for v in response.get("data", [])]

    async def get(self, validator_did: str) -> ValidatorInfo:
        """Get validator information.

        Args:
            validator_did: Validator DID

        Returns:
            Validator information
        """
        response = await self.client._request("GET", f"/validators/{validator_did}")
        return ValidatorInfo(**response["data"])

    async def get_total_staked(self) -> int:
        """Get total staked amount across all validators.

        Returns:
            Total staked amount
        """
        response = await self.client._request("GET", "/validators/total-staked")
        return response["data"]["total_staked"]

    async def get_active_count(self) -> int:
        """Get count of active validators.

        Returns:
            Number of active validators
        """
        response = await self.client._request("GET", "/validators/active-count")
        return response["data"]["count"]


class IndexingOperations:
    """Indexing operations for Willow client.

    Provides methods for GraphQL queries and indexer management.
    """

    def __init__(self, client: "WillowClient"):
        self.client = client

    async def graphql_query(
        self,
        subgrove_id: str,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        include_proof: bool = False,
        source: QuerySource = QuerySource.AUTO,
    ) -> RoutedQueryResult[GraphQLResponse]:
        """Execute a GraphQL query against a subgrove with source routing.

        The ``source`` argument makes the trust model part of the API:

        - :attr:`QuerySource.VALIDATOR` — consensus-verified chain-tip.
          Raises :class:`ValidatorHasNoDataError` for ``VerifyOnly`` subgroves.
        - :attr:`QuerySource.INDEXER` — historical/analytics via an indexer.
          Raises :class:`NoIndexersReachableError` if none serves the subgrove.
        - :attr:`QuerySource.AUTO` (default) — indexer if one serves this
          subgrove, otherwise validator. On indexer failure falls back with
          ``fallback=True``.

        Args:
            subgrove_id: Subgrove identifier
            query: GraphQL query string
            variables: Optional query variables
            include_proof: Whether to request a Merkle proof (default: ``False``)
            source: Routing preference (default: ``AUTO``)

        Returns:
            :class:`RoutedQueryResult` wrapping the :class:`GraphQLResponse`
            along with which backend served it.
        """
        request_data: Dict[str, Any] = {"query": query}
        if variables:
            request_data["variables"] = variables
        request_data["include_proof"] = include_proof

        raw = await self.client._route_query(
            "graphql", subgrove_id, request_data, source
        )
        return RoutedQueryResult(
            result=GraphQLResponse(**raw.result),
            source=raw.source,
            indexer_did=raw.indexer_did,
            fallback=raw.fallback,
        )

    async def sql_query(
        self,
        subgrove_id: str,
        query: str,
        include_proof: bool = False,
        source: QuerySource = QuerySource.AUTO,
    ) -> RoutedQueryResult[SqlResponse]:
        """Execute a SQL query against a subgrove with source routing.

        See :meth:`graphql_query` for ``source`` semantics.

        Args:
            subgrove_id: The subgrove to query
            query: SQL SELECT query string
            include_proof: Whether to include Merkle proof
            source: Routing preference (default: ``AUTO``)

        Returns:
            :class:`RoutedQueryResult` wrapping the :class:`SqlResponse`.
        """
        request = SqlRequest(query=query, include_proof=include_proof)
        body = request.model_dump(exclude_none=True)

        raw = await self.client._route_query("sql", subgrove_id, body, source)
        return RoutedQueryResult(
            result=SqlResponse(**raw.result),
            source=raw.source,
            indexer_did=raw.indexer_did,
            fallback=raw.fallback,
        )

    async def list_subgroves(self) -> List[SubgroveInfo]:
        """List all subgroves.

        Returns:
            List of subgrove information
        """
        response = await self.client._request("GET", "/indexing/subgroves")
        return [SubgroveInfo(**sg) for sg in response.get("data", [])]

    async def get_subgrove(self, subgrove_id: str) -> SubgroveInfo:
        """Get subgrove information.

        Args:
            subgrove_id: Subgrove identifier

        Returns:
            Subgrove information
        """
        response = await self.client._request("GET", f"/indexing/subgroves/{subgrove_id}")
        return SubgroveInfo(**response["data"])

    async def get_indexing_status(self, subgrove_id: str) -> SubgroveIndexingStatus:
        """Get indexing status for a subgrove.

        Args:
            subgrove_id: Subgrove identifier

        Returns:
            Indexing status with progress information
        """
        response = await self.client._request("GET", f"/indexing/subgroves/{subgrove_id}/status")
        return SubgroveIndexingStatus(**response["data"])

    async def list_indexers(self) -> List[IndexerInfo]:
        """List all indexers.

        Returns:
            List of indexer information
        """
        response = await self.client._request("GET", "/indexing/indexers")
        return [IndexerInfo(**idx) for idx in response.get("data", [])]

    async def get_indexer(self, indexer_did: str) -> IndexerInfo:
        """Get indexer information.

        Args:
            indexer_did: Indexer DID

        Returns:
            Indexer information
        """
        response = await self.client._request("GET", f"/indexing/indexers/{indexer_did}")
        return IndexerInfo(**response["data"])

    async def get_verification_stats(self) -> VerificationStats:
        """Get verification statistics.

        Returns:
            Verification statistics
        """
        response = await self.client._request("GET", "/indexing/verification-stats")
        return VerificationStats(**response["data"])


class WillowClientBuilder:
    """Builder for WillowClient with fluent configuration."""

    def __init__(self, api_url: str = "http://localhost:3031"):
        self._api_url = api_url
        self._indexer_url: Optional[str] = None
        self._timeout = 30.0
        self._retry_config: Optional[RetryConfig] = None
        self._proof_options: Optional[ProofVerificationOptions] = None
        self._light_client_config: Optional[Dict[str, Any]] = None

    def timeout(self, timeout: float) -> "WillowClientBuilder":
        """Set request timeout in seconds."""
        self._timeout = timeout
        return self

    def retry_config(self, config: RetryConfig) -> "WillowClientBuilder":
        """Set retry configuration."""
        self._retry_config = config
        return self

    def proof_verification_options(self, options: ProofVerificationOptions) -> "WillowClientBuilder":
        """Set proof verification options."""
        self._proof_options = options
        return self

    def light_client_config(self, config: Dict[str, Any]) -> "WillowClientBuilder":
        """Set light client configuration."""
        self._light_client_config = config
        return self

    def indexer_url(self, url: str) -> "WillowClientBuilder":
        """Set indexer node URL for routing GraphQL/SQL queries."""
        self._indexer_url = url
        return self

    def build(self) -> "WillowClient":
        """Build and return the WillowClient instance."""
        return WillowClient(
            api_url=self._api_url,
            timeout=self._timeout,
            retry_config=self._retry_config,
            proof_verification_options=self._proof_options,
            indexer_url=self._indexer_url,
        )


class WillowClient:
    """Main client for interacting with Willow.

    Provides a unified interface for all Willow operations including
    authentication, data storage, queries, and more.

    Example:
        ```python
        async with WillowClient("http://localhost:3031") as client:
            # Generate and register DID
            did_info = generate_did()
            await client.register_did(did_info["did_document"])

            # Set identity for per-request signing
            client.set_identity(
                did_info["did"],
                did_info["private_key"],
                did_info["public_key_id"]
            )

            # Store data
            await client.data.store("my-data", {"key": "value"})
        ```
    """

    def __init__(
        self,
        api_url: str = "http://localhost:3031",
        timeout: float = 30.0,
        retry_config: Optional[RetryConfig] = None,
        proof_verification_options: Optional[ProofVerificationOptions] = None,
        indexer_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        """Initialize Willow client.

        Args:
            api_url: Base URL for Willow API
            timeout: Request timeout in seconds
            retry_config: Optional retry configuration
            proof_verification_options: Optional proof verification configuration
            indexer_url: Optional indexer node URL for routing GraphQL/SQL queries
            api_key: Managed-tier API key (``wk_...``). When set, the SDK
                sends ``X-API-Key`` on every request. Mint a key at
                https://dashboard.willow.tech/account. Required for queries
                and writes against managed ``api.willow.tech`` /
                ``indexer.willow.tech``.
        """
        self.api_url = api_url.rstrip("/")
        self.indexer_url = indexer_url.rstrip("/") if indexer_url else None
        self.timeout = timeout
        self.retry_config = retry_config or RetryConfig()
        self.api_key = api_key
        self._did: Optional[str] = None
        self._private_key: Optional[str] = None
        self._public_key_id: Optional[str] = None
        self._algorithm: SignatureAlgorithm = "Ed25519"

        # Configure proof verification if options provided
        if proof_verification_options:
            configure_proof_verification(proof_verification_options)

        # Light client for trustless verification
        self._light_client: Optional["LightClient"] = None
        self._light_client_init_lock = asyncio.Lock()

        # Computed fields registry for SDK-side derived field computation
        self._computed_fields = ComputedFieldRegistry()

        # Initialize sub-clients
        self.data = DataOperations(self)
        self.registration = RegistrationOperations(self)
        self.proof = ProofOperations(self)
        self.token = TokenOperations(self)
        self.validators = ValidatorOperations(self)
        self.indexing = IndexingOperations(self)
        self.privacy = PrivacyOperations(self)
        self.files = FileOperations(self.api_url, api_key=api_key)

        # HTTP client. ``X-API-Key`` is set as a default header so it
        # rides on every request through this client (data, query, proof,
        # token, validator, indexing, privacy — all routes through
        # ``self._http``). Per-request auth headers (DID signature) are
        # merged on top at call sites and do not replace the default.
        default_headers = {"X-API-Key": api_key} if api_key else {}
        self._http = httpx.AsyncClient(timeout=timeout, headers=default_headers)

        # Client-side completeness checks. The on-chain anchor is read from the
        # validator's CometBFT RPC (derived from api_url, typically :3031 ->
        # :26657, matching the light client); the matched-log preimage comes
        # from the configured indexer.
        self.completeness = CompletenessOperations(
            self._http,
            self.api_url.replace(":3031", ":26657"),
            self.indexer_url,
        )

        # Indexer discovery client. When ``indexer_url`` is set, discovery
        # is bypassed and a synthetic single-entry list is returned so the
        # routing layer stays uniform.
        self.indexers = WillowIndexers(self._http, self.api_url, self.indexer_url)

        # GraphQL subscriptions over WebSocket. Shares the indexer
        # discovery client so `source=SubscribeSource.INDEXER` works
        # without any extra setup.
        from .subscriptions import WillowSubscriptions as _WillowSubscriptions
        self.subscriptions = _WillowSubscriptions(self.api_url, self.indexers)

    @classmethod
    def builder(cls, api_url: str = "http://localhost:3031") -> WillowClientBuilder:
        """Create a builder for configuring the client.

        Args:
            api_url: Base URL for Willow API

        Returns:
            WillowClientBuilder instance
        """
        return WillowClientBuilder(api_url)

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def close(self):
        """Close HTTP client."""
        await self._http.aclose()

    async def health(self) -> HealthStatus:
        """Check API health status.

        Returns:
            Health status information
        """
        response = await self._request("GET", "/health")
        return HealthStatus(**response.get("data", response))

    async def _route_query(
        self,
        path_prefix: str,
        subgrove_id: str,
        body: Dict[str, Any],
        source: QuerySource,
    ) -> RoutedQueryResult[Dict[str, Any]]:
        """Shared source-routing helper for ``/graphql/:sg`` and ``/sql/:sg``.

        Returns a :class:`RoutedQueryResult` wrapping the raw JSON body. The
        caller parses that body into the appropriate pydantic model — this
        keeps the routing logic generic.
        """
        path = f"/{path_prefix}/{subgrove_id}"

        async def _call_validator() -> Dict[str, Any]:
            headers: Dict[str, str] = {}
            if self.is_authenticated():
                headers = sign_request(
                    self._did, self._private_key, self._public_key_id,
                    "POST", path, self._algorithm,
                )
            url = f"{self.api_url}{path}"
            resp = await self._http.post(url, json=body, headers=headers)
            if resp.status_code == 404 or resp.status_code == 403:
                reason = "not available"
                try:
                    reason = resp.json().get("error") or reason
                except Exception:
                    pass
                raise ValidatorHasNoDataError(subgrove_id, reason)
            resp.raise_for_status()
            data = resp.json()
            # Validator wraps in ApiResponse({success, data}); indexer returns raw.
            if isinstance(data, dict) and "data" in data and "success" in data:
                return data.get("data") or {}
            return data

        async def _call_indexer(info: IndexerInfo) -> Dict[str, Any]:
            headers: Dict[str, str] = {}
            if self.is_authenticated():
                headers = sign_request(
                    self._did, self._private_key, self._public_key_id,
                    "POST", path, self._algorithm,
                )
            endpoint = info.effective_query_endpoint().rstrip("/")
            url = f"{endpoint}{path}"
            resp = await self._http.post(url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and "data" in data and "success" in data:
                return data.get("data") or {}
            return data

        if source == QuerySource.VALIDATOR:
            result = await _call_validator()
            return RoutedQueryResult(result=result, source=ServedBy.VALIDATOR)

        if source == QuerySource.INDEXER:
            candidates = await self.indexers.for_subgrove(subgrove_id)
            if not candidates:
                raise NoIndexersReachableError(
                    subgrove_id, "no indexer serves this subgrove"
                )
            errors: List[str] = []
            for info in candidates:
                try:
                    result = await _call_indexer(info)
                    return RoutedQueryResult(
                        result=result,
                        source=ServedBy.INDEXER,
                        indexer_did=info.indexer_did,
                    )
                except httpx.HTTPStatusError as e:
                    if e.response.status_code >= 500:
                        self.indexers.evict(info.indexer_did)
                    errors.append(f"{info.indexer_did}: HTTP {e.response.status_code}")
                except Exception as e:  # pragma: no cover - transport errors
                    errors.append(f"{info.indexer_did}: {e}")
            raise NoIndexersReachableError(subgrove_id, "; ".join(errors))

        # QuerySource.AUTO
        candidates = await self.indexers.for_subgrove(subgrove_id)
        had_candidates = bool(candidates)
        for info in candidates:
            try:
                result = await _call_indexer(info)
                return RoutedQueryResult(
                    result=result,
                    source=ServedBy.INDEXER,
                    indexer_did=info.indexer_did,
                )
            except httpx.HTTPStatusError as e:
                if e.response.status_code >= 500:
                    self.indexers.evict(info.indexer_did)
            except Exception:  # pragma: no cover
                pass
        result = await _call_validator()
        return RoutedQueryResult(
            result=result,
            source=ServedBy.VALIDATOR,
            fallback=had_candidates,
        )

    async def register_did(self, did_document: DidDocument) -> DidDocument:
        """Register a DID document.

        Willow DIDs are self-certifying: the id is derived from the public key
        (see ``generate_did`` / ``derive_did``), not chosen. Because the id is
        known before registration, onboarding is a two-step bootstrap:

        1. Pre-fund: a funded account transfers >= the registration fee to the
           derived ``did_document.id`` (e.g. via the consensus client's
           ``transfer``).
        2. Register: the holder calls this method; the fee is paid from that
           pre-funded balance.

        Args:
            did_document: DID document to register (its ``id`` must be the
                self-certifying DID derived from the key).

        Returns:
            Registered DID document
        """
        response = await self._request(
            "POST",
            "/did",
            json=did_document.model_dump(by_alias=True)
        )
        return DidDocument(**response["data"])

    def set_identity(
        self,
        did: str,
        private_key_hex: str,
        public_key_id: str,
        algorithm: SignatureAlgorithm = "Ed25519",
    ) -> None:
        """Set identity for per-request authentication.

        Each authenticated request will be signed with the provided
        private key. No session is created on the server.

        Args:
            did: DID to authenticate as
            private_key_hex: Hex-encoded private key
            public_key_id: Public key ID from DID document
            algorithm: Signature algorithm of this identity ("Ed25519" or
                "secp256k1"). Willow DIDs are self-certifying and no longer
                encode the algorithm in the string, so it cannot be inferred
                from ``did`` — pass "secp256k1" for Ethereum/wallet identities
                so per-request auth is signed with the right algorithm.
                Defaults to "Ed25519" (the SDK's default identity type).
        """
        self._did = did
        self._private_key = private_key_hex
        self._public_key_id = public_key_id
        self._algorithm = algorithm

    def is_authenticated(self) -> bool:
        """Check if client has identity set for per-request signing."""
        return self._did is not None and self._private_key is not None

    def clear_identity(self) -> None:
        """Clear identity (logout)."""
        self._did = None
        self._private_key = None
        self._public_key_id = None
        self._algorithm = "Ed25519"

    def register_computed_fields(
        self,
        dataset_id: str,
        fields: ComputedFieldSet
    ) -> None:
        """Register computed fields for a specific dataset.

        Computed fields are derived values calculated client-side from proven data.
        For example, token prices computed from proven reserves.

        Args:
            dataset_id: The dataset ID
            fields: The computed field definitions to apply

        Example:
            >>> from willow.computed_fields import UNISWAP_V2_PAIR_FIELDS
            >>> client.register_computed_fields('pairs', UNISWAP_V2_PAIR_FIELDS)
        """
        self._computed_fields.register(dataset_id, dataset_id, fields)

    def unregister_computed_fields(self, dataset_id: str) -> bool:
        """Remove computed fields for a dataset.

        Args:
            dataset_id: The dataset ID

        Returns:
            True if fields were removed, False if they weren't registered.
        """
        return self._computed_fields.unregister(dataset_id, dataset_id)

    def has_computed_fields(self, dataset_id: str) -> bool:
        """Check if computed fields are registered for a dataset.

        Args:
            dataset_id: The dataset ID

        Returns:
            True if fields are registered, False otherwise.
        """
        return self._computed_fields.has(dataset_id, dataset_id)

    async def _get_or_create_light_client(self) -> "LightClient":
        """Get or create a light client for trustless verification.

        Auto-initializes a light client using trust-on-first-use: the
        first block received from validators is trusted, and every
        subsequent block is verified against it. Pin a known-good
        checkpoint header instead for production deployments.
        """
        if self._light_client is not None:
            return self._light_client

        async with self._light_client_init_lock:
            # Double-check after acquiring lock
            if self._light_client is not None:
                return self._light_client

            # Import here to avoid circular imports
            from .light_client import LightClient, LightClientConfig
            from .light_client.types import TrustThreshold

            config = LightClientConfig(
                chain_id="willow-chain",
                # Derive CometBFT RPC endpoint from API URL (typically :3031 -> :26657)
                validator_endpoints=[self.api_url.replace(":3031", ":26657")],
                trust_threshold=TrustThreshold(numerator=2, denominator=3),
                trusting_period_secs=86400,  # 24 hours
                max_clock_drift_secs=30,
                auto_sync=False,
                min_validators_for_consensus=1,  # For single-node development
                request_timeout_secs=30,
                sync_interval_secs=60
            )

            lc = LightClient(config)
            await lc.initialize_with_trust_on_first_use()
            self._light_client = lc
            return lc

    async def get_root_hash(self) -> str:
        """Get the verified root hash using the light client.

        Uses the light client for trustless verification. Auto-initializes
        with trust-on-first-use if no light client is configured.

        Returns:
            Verified root hash as hex string from the light client

        Raises:
            WillowError: If root hash is not available
        """
        # Always use light client for trustless verification
        # This auto-initializes the light client on first use (trust-on-first-use)
        light_client = await self._get_or_create_light_client()
        return await light_client.get_verified_root_hash()

    async def get_root_hash_local(self) -> str:
        """Get the current local root hash from the node.

        This method returns the node's current local state root hash, which may not
        yet be confirmed by blockchain consensus. Use this method only when you need
        the most recent state and don't require blockchain verification.

        Returns:
            Current local root hash as hex string

        Raises:
            WillowError: If root hash is not available or request fails
        """
        response = await self._request("GET", "/state/root-hash")
        if "data" not in response or "root_hash" not in response["data"]:
            raise WillowError("No root hash in response")
        return response["data"]["root_hash"]

    async def _request(
        self,
        method: str,
        path: str,
        json: Optional[Any] = None,
        authenticated: bool = False
    ) -> Dict[str, Any]:
        """Make HTTP request to Willow API.

        Args:
            method: HTTP method
            path: API path
            json: JSON body
            authenticated: Whether to include auth headers

        Returns:
            Response data

        Raises:
            WillowError: On API errors
            NetworkError: On network errors
            NotAuthenticatedError: If authentication required but not present
        """
        url = f"{self.api_url}{path}"

        # Check authentication if required
        if authenticated and not self.is_authenticated():
            raise NotAuthenticatedError()

        # Sign request with identity if authenticated
        headers = {}
        if authenticated and self.is_authenticated():
            headers = sign_request(
                self._did, self._private_key, self._public_key_id, method, path,
                self._algorithm,
            )

        try:
            response = await self._http.request(
                method,
                url,
                json=json,
                headers=headers
            )

            # Parse response
            response_data = response.json()

            # Handle errors
            if response.status_code >= 400:
                raise parse_api_error(response_data, response.status_code)

            # Check success flag
            api_response = ApiResponse(**response_data)
            if not api_response.success:
                raise WillowError(
                    api_response.error or "Request failed",
                    status_code=response.status_code
                )

            return response_data

        except httpx.NetworkError as e:
            raise NetworkError(f"Network error: {str(e)}")
        except httpx.TimeoutException:
            raise NetworkError("Request timed out")
        except WillowError:
            raise
        except Exception as e:
            raise WillowError(f"Unexpected error: {str(e)}")
