"""Main client for Willow SDK.

This module provides the main WillowClient class for interacting with
the Willow decentralized data indexing protocol.
"""

import asyncio
import httpx
import json as _json
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
    Permission,
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
from .auth import _KEY_TYPES, sign_challenge, sign_request, sign_request_with_nonce, SignatureAlgorithm
from .errors import (
    WillowError,
    AuthenticationError,
    NetworkError,
    NonceWindowFullError,
    NotAuthenticatedError,
    NotLandedError,
    ProofVerificationError,
    TransactionError,
    parse_api_error,
)
from .nonces import USED, WINDOW, NonceTracker, refusal_outcome
from .consensus.types import (
    DataStoreTx,
    RegisterDidTx,
    RegisterSubgroveTx,
    create_sign_message,
    create_transaction_wrapper,
)
from .signed_messages import did_document_body
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
from .files import FileOperations, _tx_submit_result
from .completeness import CompletenessOperations

if TYPE_CHECKING:
    from .light_client import LightClient

logger = logging.getLogger(__name__)


def _encode_json_body(payload: Any) -> Optional[bytes]:
    """Serialize a JSON request body once, so the bytes signed are the bytes sent."""
    if payload is None:
        return None
    return _json.dumps(
        payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _key_algorithm(body: Dict[str, Any], public_key_id: str) -> Optional[SignatureAlgorithm]:
    """The algorithm of the key ``public_key_id`` in a DID document body, from
    its key type; ``None`` if the document has no such key or names another
    type."""
    for key in body["public_keys"]:
        if key["id"] == public_key_id:
            for algorithm, key_type in _KEY_TYPES.items():
                if key["type"] == key_type:
                    return algorithm
            return None
    return None


def _envelope_data(body: Any) -> Any:
    """``data`` of an API envelope (``{success, data, error}``), raising its
    ``error`` when ``success`` is false; any other body as it is."""
    if isinstance(body, dict) and "success" in body and ("data" in body or "error" in body):
        if not body.get("success"):
            raise WillowError(body.get("error") or "Request failed")
        return body.get("data")
    return body


def _unsupported_data_write(operation: str, route: str, kind: str) -> WillowError:
    return WillowError(
        f"{operation} is not supported: the node API does not serve {route}. Data "
        f"changes only through a {kind} transaction submitted to POST /tx/submit, "
        f"which this SDK does not build."
    )


# The field types the node's subgrove schema takes.
_SCHEMA_FIELD_TYPES = ("string", "number", "boolean", "array", "object", "bytes")


def _schema_json(schema: Any) -> str:
    """A ``SchemaDefinition`` as the node's schema JSON text.

    The node maps each field to its type name and lists required fields in
    ``required_fields``; a field's ``required`` flag joins that list. The node
    supports no schema indexes, so a schema with ``indexes`` or a field
    flagged ``indexed`` is refused (``ValueError``).
    """
    if schema.indexes:
        raise ValueError("Schema indexes are not supported: the node refuses a schema that declares indexes")
    fields: Dict[str, str] = {}
    required = list(schema.required_fields)
    for name, definition in schema.fields.items():
        field_type = getattr(definition, "type", None) or getattr(definition, "field_type", None)
        field_type = getattr(field_type, "value", field_type)
        if field_type not in _SCHEMA_FIELD_TYPES:
            raise ValueError(
                f"schema field {name!r} has type {field_type!r}; the node takes "
                + ", ".join(_SCHEMA_FIELD_TYPES)
            )
        if getattr(definition, "indexed", False):
            raise ValueError(
                f"schema field {name!r} is flagged indexed: schema indexes are not supported"
            )
        fields[name] = field_type
        if definition.required and name not in required:
            required.append(name)
    return _json.dumps(
        {"version": schema.version, "fields": fields, "indexes": [], "required_fields": required},
        separators=(",", ":"),
    )


class DataOperations:
    """Data operations for Willow client.

    Provides methods for storing, retrieving, updating, and querying data
    with automatic proof verification for secure operations.
    """

    def __init__(self, client: "WillowClient"):
        self.client = client

    @require_auth
    async def store(self, subgrove_id: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Store each key of ``data`` in a subgrove, one StoreData transaction each.

        Each value must be a JSON object (a ``dict``): the node stores only
        objects. Each transaction is signed by the identity set on the client
        over ``store_data_message`` (its data the value's JSON text,
        ``json.dumps(value, separators=(",", ":"), sort_keys=True,
        allow_nan=False)``) and submitted to ``POST /tx/submit``, one at a
        time, each under a nonce the client hands out (see
        ``WillowClient.wait_until_landed``). The node accepts at most 24
        nonces above the account's base, so past 24 writes in flight the next
        waits for earlier ones to land.

        StoreData writes a new key; it is refused in its block for a key that
        already exists, and a write refused in its block still spends its
        nonce. Writes in flight may land in any order: wait for a write to
        land before sending one that depends on it.

        Args:

            subgrove_id: Subgrove/dataset identifier
            data: Key -> JSON object to store under it

        Returns:
            For each key, in order, the ``{tx_hash, code, log, did, nonce}``
            of the accepted transaction

        Raises:
            TypeError: A value is not a ``dict``. Nothing is sent.
            ValueError: The subgrove ID, a key, or the DID holds a line break,
                or a value holds NaN or an infinity. Nothing is sent.
            TransactionError: CheckTx refused a transaction.
            NonceWindowFullError: Every nonce the node accepts stayed taken.
            NetworkError: A submission failed in transit.

            On any of the last three, ``error.submitted`` holds the results
            of the keys submitted before it and ``error.failed_key`` the key
            that wasn't; the keys after it were not sent.
        """
        if not isinstance(data, dict):
            raise TypeError("data must map each key to a JSON object (a dict)")
        for key, value in data.items():
            if not isinstance(value, dict):
                raise TypeError(f"the value for key {key!r} must be a JSON object (a dict)")
        client = self.client
        did = client._did or ""
        writes = [
            (key, DataStoreTx(
                subgrove_id=subgrove_id,
                key=key,
                data=_json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False),
                owner_did=did,
                public_key_id=client._public_key_id or "",
            ))
            for key, value in data.items()
        ]
        for _, tx in writes:
            create_sign_message("DataStore", tx)  # refuse a line break before sending any
        submitted: List[Dict[str, Any]] = []
        for key, tx in writes:
            try:
                # The account's base is read for the first write only.
                submitted.append(
                    await client._sign_and_submit("DataStore", tx, read_base=not submitted)
                )
            except Exception as e:
                e.submitted = submitted  # type: ignore[attr-defined]
                e.failed_key = key  # type: ignore[attr-defined]
                raise
        return submitted

    @require_auth
    async def store_item(
        self,
        subgrove_id: str,
        key: str,
        value: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Store a single item in a subgrove (one StoreData transaction; see ``store``).

        Args:

            subgrove_id: Subgrove/dataset identifier
            key: Item key
            value: Item value, a JSON object (``dict``)

        Returns:
            The ``{tx_hash, code, log, did, nonce}`` of the accepted
            transaction
        """
        (result,) = await self.store(subgrove_id, {key: value})
        return result

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
            authenticated=True,
            read=True,
        )
        data = data_response["data"]

        # Then get the proof
        try:
            proof_response = await self.client._request(
                "GET",
                f"/proof/{subgrove_id}/{key}",
                authenticated=True,
                read=True,
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
            authenticated=True,
            read=True,
        )
        return response["data"]

    async def update(self, subgrove_id: str, key: str, data: Dict[str, Any]) -> None:
        """Not supported: raises ``WillowError``.

        The node API does not serve ``PUT /data/{subgrove_id}/{key}``; data
        changes only through an UpdateData transaction submitted to
        ``POST /tx/submit``, which this SDK does not build.
        """
        raise _unsupported_data_write(
            "client.data.update", "PUT /data/{subgrove_id}/{key}", "UpdateData"
        )

    async def delete(self, subgrove_id: str, key: str) -> None:
        """Not supported: raises ``WillowError``.

        The node API does not serve ``DELETE /data/{subgrove_id}/{key}``; data
        is deleted only through a DeleteData transaction submitted to
        ``POST /tx/submit``, which this SDK does not build.
        """
        raise _unsupported_data_write(
            "client.data.delete", "DELETE /data/{subgrove_id}/{key}", "DeleteData"
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
            authenticated=True,
            read=True,
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
        computed_fields = self.client._computed_fields.get(subgrove_id)
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
            authenticated=True,
            read=True,
        )
        query_response = QueryResponse(**response["data"])

        # Apply computed fields if registered for this app/dataset
        computed_fields = self.client._computed_fields.get(subgrove_id)
        if computed_fields:
            query_response = apply_computed_fields_to_response(query_response, computed_fields)

        return query_response

    @require_auth
    async def batch_store(self, subgrove_id: str, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Store multiple items in a subgrove, one StoreData transaction each (see ``store``).

        Args:

            subgrove_id: Subgrove/dataset identifier
            items: List of items with "key" and "value" fields

        Returns:
            For each item, the ``{tx_hash, code, log, did, nonce}`` of its
            transaction
        """
        # Convert list of {key, value} to dict
        data = {item["key"]: item["value"] for item in items}
        return await self.store(subgrove_id, data)

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
        """Register a new DataStorage subgrove with a RegisterSubgrove transaction.

        The request (``RegisterDatasetRequest`` fields) becomes a
        RegisterSubgrove transaction with every field explicit, signed by the
        identity set on the client over ``register_subgrove_message`` and
        submitted to ``POST /tx/submit``. ``owner_did`` must be that identity.
        ``readers`` become the mode's free readers. The schema is sent as the
        node's schema JSON: each field's type, with required fields listed in
        ``required_fields``; ``dataset_path`` has no on-chain counterpart and
        is not sent. The subgrove ID must be 1 to 64 ASCII letters, digits,
        ``-``, or ``_``, starting with a letter or digit, and the schema can
        declare no indexes (no ``indexes``, no field flagged ``indexed``):
        the node refuses either. For other modes and fields, use
        ``ConsensusClient.register_subgrove``.

        Args:
            request: Subgrove registration request data

        Returns:
            The ``{tx_hash, code, log, did, nonce}`` of the accepted
            transaction

        Raises:
            ValueError: ``owner_did`` is not the client's identity, the
                subgrove ID is not one the node takes, or the schema is
                missing, declares indexes, or has a type the node does not
                take. Nothing is sent.
            TransactionError: CheckTx refused the transaction.
        """
        request = dict(request)
        # Handle subgrove_id -> dataset_id alias for compatibility
        if "subgrove_id" in request:
            request["dataset_id"] = request.pop("subgrove_id")

        dataset_request = RegisterDatasetRequest(**request)
        if dataset_request.owner_did != self.client._did:
            raise ValueError(
                "owner_did must be the identity set on the client: the owner signs the registration"
            )
        if dataset_request.schema_ is None:
            raise ValueError("schema is required")
        tx = RegisterSubgroveTx(
            subgrove_id=dataset_request.dataset_id,
            schema=_schema_json(dataset_request.schema_),
            owner_did=dataset_request.owner_did,
            mode={"DataStorage": {
                "name": dataset_request.name,
                "writers": list(dataset_request.writers),
                "free_readers": list(dataset_request.readers),
                "read_pricing": None,
            }},
            public_key_id=self.client._public_key_id or "",
            name=dataset_request.name,
        )
        return await self.client._sign_and_submit("RegisterSubgrove", tx)

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
            DID permissions: the subgroves the DID owns, administers, writes,
            and reads, and each grant as the API returns it.
        """
        # The API answers { success, data: [Permission, ...] }.
        response = await self.client._request("GET", f"/did/{did}/permissions")
        return DidPermissions.from_permissions(
            did, [Permission(**p) for p in response.get("data") or []]
        )


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
        # Nonce-signed when an identity is set, for the DID's read rights.
        response = await self.client._request(
            "GET",
            f"/proof/{subgrove_id}/{key}",
            read=True,
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
        # The API answers { subgrove_id, balance, total_spent, last_funded }.
        response = await self.client._request("GET", f"/token/subgrove/balance/{subgrove_id}")
        return BalanceInfo(**response["data"])

    async def get_fee_schedule(self) -> FeeSchedule:
        """Get the current fee schedule.

        Returns:
            Fee schedule with storage, query, and indexing fees
        """
        response = await self.client._request("GET", "/fees/schedule")
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

    async def _active_validators(self) -> List[Dict[str, Any]]:
        # GET /validators lists the active, unjailed validators, each with
        # its total_stake. The API has no separate total or count route.
        response = await self.client._request("GET", "/validators")
        return list(response.get("data") or [])

    async def get_total_staked(self) -> int:
        """Get the total stake of the active validators.

        Returns:
            Total staked amount
        """
        return sum(int(v.get("total_stake", 0)) for v in await self._active_validators())

    async def get_active_count(self) -> int:
        """Get count of active validators.

        Returns:
            Number of active validators
        """
        return len(await self._active_validators())


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
        # The indexed subgroves, in the same shape as GET /subgroves/{id}.
        response = await self.client._request("GET", "/subgroves/indexed")
        return [SubgroveInfo(**sg) for sg in response.get("data", [])]

    async def get_subgrove(self, subgrove_id: str) -> SubgroveInfo:
        """Get subgrove information.

        Args:
            subgrove_id: Subgrove identifier

        Returns:
            Subgrove information
        """
        response = await self.client._request("GET", f"/subgroves/{subgrove_id}")
        return SubgroveInfo(**response["data"])

    async def get_indexing_status(self, subgrove_id: str) -> SubgroveIndexingStatus:
        """Get indexing status for a subgrove.

        Args:
            subgrove_id: Subgrove identifier

        Returns:
            Indexing status: its status ("indexing" or "pending_indexers"),
            active indexer count, deployment block, and query count
        """
        response = await self.client._request("GET", f"/subgroves/{subgrove_id}/status")
        return SubgroveIndexingStatus(**response["data"])

    async def list_indexers(self) -> List[IndexerInfo]:
        """List all indexers.

        Returns:
            List of indexer information
        """
        response = await self.client._request("GET", "/indexers")
        return [IndexerInfo(**idx) for idx in response.get("data", [])]

    async def get_indexer(self, indexer_did: str) -> IndexerInfo:
        """Get indexer information.

        Args:
            indexer_did: Indexer DID

        Returns:
            Indexer information
        """
        response = await self.client._request("GET", f"/indexers/{indexer_did}")
        return IndexerInfo(**response["data"])

    async def get_verification_stats(self) -> VerificationStats:
        """Get verification statistics.

        Returns:
            Verification statistics
        """
        response = await self.client._request("GET", "/verification/stats")
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
            # Generate a DID and set it as the client's identity
            did_info = generate_did()
            client.set_identity(
                did_info["did"],
                did_info["private_key"],
                did_info["public_key_id"]
            )

            # Register it (pre-fund the derived DID with the fee first), and
            # wait for the registration to land before the DID signs anything
            await client.wait_until_landed(
                await client.register_did(did_info["did_document"])
            )

            # Store a JSON object under a key (a StoreData transaction)
            await client.data.store("my-data", {"key": {"value": 1}})
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

        # The nonces handed out per signing DID (see ``willow.nonces``).
        self._nonces = NonceTracker()
        self._nonce_poll_interval = 1.0
        self._nonce_wait_timeout = 60.0

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

        ``GET /health`` answers the health object itself, not an envelope.

        Returns:
            Health status information
        """
        try:
            response = await self._http.request("GET", f"{self.api_url}/health")
        except httpx.NetworkError as e:
            raise NetworkError(f"Network error: {str(e)}")
        except httpx.TimeoutException:
            raise NetworkError("Request timed out")
        try:
            body = response.json()
        except ValueError:
            body = None
        if response.status_code >= 400:
            raise parse_api_error(
                body if isinstance(body, dict) else {"error": response.text or f"HTTP {response.status_code}"},
                response.status_code,
            )
        body = _envelope_data(body)
        if not isinstance(body, dict):
            raise WillowError("The API answered no health status", status_code=response.status_code)
        return HealthStatus(**body)

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
            # A /sql or /graphql read sent to the API: nonce-signed, the only
            # form that carries the identity's read rights, on the routes
            # that check them.
            url = f"{self.api_url}{path}"
            payload = _encode_json_body(body)
            headers = {"Content-Type": "application/json"}
            headers.update(self._nonce_headers("POST", url, payload))
            resp = await self._http.post(url, content=payload, headers=headers)
            if resp.status_code == 404 or resp.status_code == 403:
                reason = "not available"
                try:
                    reason = resp.json().get("error") or reason
                except Exception:
                    pass
                raise ValidatorHasNoDataError(subgrove_id, reason)
            resp.raise_for_status()
            # Validator wraps in ApiResponse({success, data}); indexer returns raw.
            return _envelope_data(resp.json()) or {}

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
            return _envelope_data(resp.json()) or {}

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

    async def register_did(
        self,
        did_document: DidDocument,
        private_key_hex: Optional[str] = None,
        public_key_id: Optional[str] = None,
        algorithm: Optional[SignatureAlgorithm] = None,
    ) -> Dict[str, Any]:
        """Register a DID document with a RegisterDid transaction.

        Willow DIDs are self-certifying: the id is derived from the public key
        (see ``generate_did`` / ``derive_did``), not chosen. Because the id is
        known before registration, onboarding is a two-step bootstrap:

        1. Pre-fund: a funded account transfers >= the registration fee to the
           derived ``did_document.id`` (e.g. via the consensus client's
           ``transfer``).
        2. Register: the holder calls this method; the fee is paid from that
           pre-funded balance.

        The transaction is signed with the document's own key over the node's
        compact JSON of the document (``register_did_message``), under nonce
        1, and submitted to ``POST /tx/submit``. It returns once CheckTx
        accepts it; the DID can sign other transactions and requests only
        after it lands, so ``await client.wait_until_landed(result)`` first.

        Args:
            did_document: DID document to register (its ``id`` must be the
                self-certifying DID derived from the key).
            private_key_hex: The key to sign with. Defaults to the identity
                set on the client, which must then be ``did_document.id``.
            public_key_id: The signing key's id in the document. Defaults to
                the identity's, or the document's first authentication key.
            algorithm: The key's algorithm. Defaults to the one the
                document's key type names (``Ed25519VerificationKey2018`` or
                ``EcdsaSecp256k1VerificationKey2019``), else the identity's,
                else "Ed25519".

        Returns:
            The ``{tx_hash, code, log, did, nonce}`` of the accepted
            transaction

        Raises:
            NotAuthenticatedError: No key given and no identity set for this DID.
            TransactionError: CheckTx refused the transaction.
        """
        body = did_document_body(did_document)
        fallback_algorithm: SignatureAlgorithm = "Ed25519"
        if private_key_hex is None:
            if not self.is_authenticated() or self._did != body["id"]:
                raise NotAuthenticatedError(
                    "register_did signs with the document's key: pass private_key_hex, "
                    "or call set_identity as the DID being registered first"
                )
            private_key_hex = self._private_key
            public_key_id = public_key_id or self._public_key_id
            fallback_algorithm = self._algorithm
        if public_key_id is None:
            if not body["authentication"]:
                raise ValueError("did_document lists no authentication key")
            public_key_id = body["authentication"][0]
        algorithm = algorithm or _key_algorithm(body, public_key_id) or fallback_algorithm
        did = body["id"]
        tx = RegisterDidTx(did_document=body, signature="", public_key_id=public_key_id, nonce=1)
        tx.signature = sign_challenge(
            create_sign_message("RegisterDid", tx), private_key_hex or "", algorithm
        )
        self._nonces.hold(did, 1)
        response = await self._post_transaction(create_transaction_wrapper("RegisterDid", tx))
        try:
            result = _tx_submit_result(response)
        except TransactionError as e:
            self._nonces.settle(did, 1, refusal_outcome(e, response.status_code))
            raise
        return dict(result, did=did, nonce=1)

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
        self._computed_fields.register(dataset_id, fields)

    def unregister_computed_fields(self, dataset_id: str) -> bool:
        """Remove computed fields for a dataset.

        Args:
            dataset_id: The dataset ID

        Returns:
            True if fields were removed, False if they weren't registered.
        """
        return self._computed_fields.unregister(dataset_id)

    def has_computed_fields(self, dataset_id: str) -> bool:
        """Check if computed fields are registered for a dataset.

        Args:
            dataset_id: The dataset ID

        Returns:
            True if fields are registered, False otherwise.
        """
        return self._computed_fields.has(dataset_id)

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

    def _api_target(self, url: str) -> str:
        """The path and query the API receives for ``url``.

        That is the request target httpx sends (URL-encoded, query included),
        less any path the API base URL carries: a proxy mounted under a path
        strips it before the API sees the request.
        """
        target = httpx.URL(url).raw_path.decode("ascii")
        base = httpx.URL(self.api_url).raw_path.decode("ascii").rstrip("/")
        if base and target.startswith(base + "/"):
            target = target[len(base):]
        return target

    def _nonce_headers(
        self, method: str, url: str, body: Optional[bytes]
    ) -> Dict[str, str]:
        """Nonce-signed auth headers for one read sent to the API, or none
        without an identity.

        The signature is over the method, the path and query the API
        receives, and ``body``, which must be the exact bytes sent. Each call
        draws a fresh nonce, so call it for each attempt of a request.
        """
        if not self.is_authenticated():
            return {}
        return sign_request_with_nonce(
            self._did or "",
            self._private_key or "",
            self._public_key_id or "",
            method,
            self._api_target(url),
            body,
            self._algorithm,
        )

    def _legacy_headers(self, method: str, url: str) -> Dict[str, str]:
        """Auth headers in the older ``{METHOD}:{PATH}:{TIMESTAMP}`` form, over
        the path the API receives for ``url``."""
        return sign_request(
            self._did or "",
            self._private_key or "",
            self._public_key_id or "",
            method,
            self._api_target(url),
            self._algorithm,
        )

    async def _account_nonce(self, did: str) -> int:
        """The account's nonce (``GET /account/{did}/nonce``): the next
        transaction signs the one after it."""
        response = await self._request("GET", f"/account/{did}/nonce")
        data = response.get("data")
        nonce = data.get("nonce") if isinstance(data, dict) else None
        if isinstance(nonce, bool) or not isinstance(nonce, int):
            raise WillowError(f"The API answered no nonce for {did}")
        return nonce

    def _sign_transaction(self, tx_type: str, tx: Any) -> Dict[str, Any]:
        """``tx`` signed by the identity set on the client over the message
        built from its own fields (``create_sign_message``), as ``/tx/submit``
        takes it. Set the nonce first."""
        message = create_sign_message(tx_type, tx)
        tx.signature = sign_challenge(message, self._private_key or "", self._algorithm)
        return create_transaction_wrapper(tx_type, tx)

    async def _take_nonce(self, did: str, read_base: bool = True) -> int:
        """A nonce for ``did``'s next transaction: the lowest one in the
        node's window this client hasn't handed out (see ``willow.nonces``).
        While every one is taken, waits for the account's base to advance.

        ``read_base=False`` takes one above the base last read, when one is
        free, without reading it again: for the writes after the first of a
        batch.

        Raises:
            NonceWindowFullError: The window stayed full for
                ``_nonce_wait_timeout`` seconds.
        """
        if not read_base:
            nonce = self._nonces.take(did, 0)
            if nonce is not None:
                return nonce
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._nonce_wait_timeout
        while True:
            nonce = self._nonces.take(did, await self._account_nonce(did))
            if nonce is not None:
                return nonce
            if loop.time() >= deadline:
                raise NonceWindowFullError(
                    f"every nonce the node accepts for {did} is taken by a transaction "
                    f"that hasn't landed; wait for earlier ones to land"
                )
            await asyncio.sleep(self._nonce_poll_interval)

    async def _sign_and_submit(
        self, tx_type: str, tx: Any, read_base: bool = True
    ) -> Dict[str, Any]:
        """Sign ``tx`` as the identity under a nonce it hands out, and submit it.

        A transaction CheckTx refuses gives its nonce back, unless the
        refusal says the nonce is held by a pending transaction or already
        used. When it is already used, no transaction under it can run, so
        ``tx`` is signed again under a fresh nonce. A submission that fails in
        transit keeps its nonce until its lease runs out, since it may have
        reached the node; its ``NetworkError`` carries the ``did`` and
        ``nonce`` it was signed under.

        Returns:
            The ``{tx_hash, code, log, did, nonce}`` of the accepted
            transaction.
        """
        did = self._did or ""
        create_sign_message(tx_type, tx)  # refuse what can't be signed before taking a nonce
        error: Optional[TransactionError] = None
        for _ in range(WINDOW):
            tx.nonce = await self._take_nonce(did, read_base)
            read_base = True  # a retry follows a nonce the base may have passed
            try:
                signed = self._sign_transaction(tx_type, tx)
            except BaseException:
                self._nonces.release(did, tx.nonce)
                raise
            try:
                response = await self._post_transaction(signed)
            except NetworkError as e:
                # It may have reached the node: say under which nonce.
                e.did, e.nonce = did, tx.nonce  # type: ignore[attr-defined]
                raise
            try:
                return dict(_tx_submit_result(response), did=did, nonce=tx.nonce)
            except TransactionError as e:
                outcome = refusal_outcome(e, response.status_code)
                self._nonces.settle(did, tx.nonce, outcome)
                if outcome != USED:
                    raise
                error = e
        assert error is not None
        raise error

    async def _post_transaction(self, tx: Dict[str, Any]) -> httpx.Response:
        """POST a JSON transaction to the API's ``/tx/submit``.

        Raises:
            NetworkError: On network errors.
        """
        try:
            return await self._http.request(
                "POST",
                f"{self.api_url}/tx/submit",
                content=_encode_json_body(tx),
                headers={"Content-Type": "application/json"},
            )
        except httpx.NetworkError as e:
            raise NetworkError(f"Network error: {str(e)}")
        except httpx.TimeoutException:
            raise NetworkError("Request timed out")

    async def _submit_transaction(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a JSON transaction to the API's ``POST /tx/submit``.

        Returns:
            The ``{tx_hash, code, log}`` of a transaction CheckTx accepted.

        Raises:
            TransactionError: Unless CheckTx accepted the transaction.
            NetworkError: On network errors.
        """
        return _tx_submit_result(await self._post_transaction(tx))

    async def wait_until_landed(
        self,
        *writes: Any,
        timeout: float = 60.0,
        poll_interval: float = 1.0,
    ) -> None:
        """Wait until each write's nonce has been used in a block.

        Each of ``writes`` is what a write returned: a ``{..., did, nonce}``
        dict (``register_did``, ``data.store_item``,
        ``registration.register_subgrove``, the ``privacy`` grants) or a list
        of them (``data.store``, ``data.batch_store``). A write returns once
        CheckTx accepts it; send one that depends on it (a write after the
        DID's registration, a store into a subgrove just registered) only
        after it lands. Writes in flight together may land in any order.

        This polls ``GET /account/{did}/nonce`` until the account's base
        reaches each write's nonce. The base advances only over used nonces
        with no gap below them, so it also waits for every earlier write from
        that DID. A write refused in its block uses its nonce too: read what
        it wrote to know it took effect. A RegisterDid uses its nonce only
        when it succeeds.

        Raises:
            NotLandedError: A nonce wasn't used within ``timeout`` seconds.
            ValueError: A write carries no ``did`` and ``nonce``.
        """
        targets: Dict[str, int] = {}
        pending: List[Any] = list(writes)
        while pending:
            write = pending.pop()
            if isinstance(write, (list, tuple)):
                pending.extend(write)
                continue
            did = write.get("did") if isinstance(write, dict) else None
            nonce = write.get("nonce") if isinstance(write, dict) else None
            if not isinstance(did, str) or isinstance(nonce, bool) or not isinstance(nonce, int):
                raise ValueError("each write must be the {..., did, nonce} result a write returned")
            targets[did] = max(targets.get(did, 0), nonce)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        for did, nonce in targets.items():
            while True:
                base = self._nonces.observe(did, await self._account_nonce(did))
                if base >= nonce:
                    break
                if loop.time() >= deadline:
                    raise NotLandedError(
                        f"nonce {nonce} of {did} was not used within {timeout} s: the "
                        f"account's base nonce is {base}"
                    )
                await asyncio.sleep(poll_interval)

    async def _request(
        self,
        method: str,
        path: str,
        json: Optional[Any] = None,
        authenticated: bool = False,
        read: bool = False,
    ) -> Dict[str, Any]:
        """Make HTTP request to Willow API.

        With an identity set, a ``read`` request is signed with a one-time
        nonce over its method, path and query, and body (see
        ``sign_request_with_nonce``), the only form that carries the DID's
        read rights. Any other authenticated request is signed in the older
        ``{METHOD}:{PATH}:{TIMESTAMP}`` form (see ``sign_request``).

        Args:
            method: HTTP method
            path: API path
            json: JSON body
            authenticated: Require an identity, and sign the request with it
            read: A read the DID's read rights apply to (``GET /data``,
                ``GET /proof``, ``POST /query``): nonce-signed whenever an
                identity is set

        Returns:
            Response data

        Raises:
            WillowError: On API errors
            NetworkError: On network errors
            NotAuthenticatedError: If authentication required but not present
        """
        url = f"{self.api_url}{path}"
        method = method.upper()

        # Check authentication if required
        if authenticated and not self.is_authenticated():
            raise NotAuthenticatedError()

        try:
            body = _encode_json_body(json)
            headers: Dict[str, str] = {}
            if body is not None:
                headers["Content-Type"] = "application/json"
            if read:
                headers.update(self._nonce_headers(method, url, body))
            elif authenticated:
                headers.update(self._legacy_headers(method, url))

            response = await self._http.request(
                method,
                url,
                content=body,
                headers=headers
            )

            # Handle errors. The auth middleware refuses with a bare status
            # (such as 401, 400, or 429) and no body.
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                except ValueError:
                    error_data = None
                if not isinstance(error_data, dict):
                    text = response.text.strip() if isinstance(response.text, str) else ""
                    error_data = {
                        "error": text or response.reason_phrase or f"HTTP {response.status_code}"
                    }
                raise parse_api_error(error_data, response.status_code)

            # Parse response
            response_data = response.json()

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
