"""Main client for Willow SDK.

This module provides the main WillowClient class for interacting with
the Willow decentralized data indexing protocol.
"""

import asyncio
import base64
import httpx
import json as _json
import logging
from dataclasses import dataclass
from typing import Callable, Optional, Dict, Any, FrozenSet, List, Set, Tuple

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
    _HISTORICAL_UNSUPPORTED,
    _QUERY_UNSUPPORTED,
)
from .auth import _key_algorithm, sign_challenge, sign_request, sign_request_with_nonce, SignatureAlgorithm
from .errors import (
    UnsupportedError,
    WillowError,
    AuthenticationError,
    NetworkError,
    NonceWindowFullError,
    NotAuthenticatedError,
    NotLandedError,
    ProofHeightOutOfRangeError,
    ProofVerificationError,
    TransactionError,
    parse_api_error,
)
from .nonces import (
    FREE, HELD, UNKNOWN, USED, InterruptedWrite, NonceTracker, parse_nonce_state, refusal_outcome,
)
from .consensus.types import (
    DataStoreTx,
    RegisterDidTx,
    RegisterSubgroveTx,
    create_sign_message,
    create_transaction_wrapper,
)
from .signed_messages import SCHEMA_FIELD_TYPES as _SCHEMA_FIELD_TYPES, did_document_body
from .indexers import (
    WillowIndexers,
    QuerySource,
    RoutedQueryResult,
    ServedBy,
    ValidatorHasNoDataError,
    NoIndexersReachableError,
)
from .utils import require_auth
from .proof import (
    ProofVerificationOptions,
    configure_proof_verification,
    json_values_equal,
    stored_value,
    subgrove_data_path,
)
from .grovedb import GroveDBVerificationError, verify_item_at_path
from .computed_fields import (
    ComputedFieldRegistry,
    ComputedFieldSet,
    apply_computed_fields_to_response,
)
from .privacy import PrivacyOperations
from .files import FileOperations, _tx_submit_result
from .completeness import CompletenessOperations

logger = logging.getLogger(__name__)


def _encode_json_body(payload: Any) -> Optional[bytes]:
    """Serialize a JSON request body once, so the bytes signed are the bytes sent."""
    if payload is None:
        return None
    return _json.dumps(
        payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


# Transport failures that leave before a request is sent: it never reached the API.
_NEVER_SENT = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout, httpx.UnsupportedProtocol)


def _envelope_data(body: Any) -> Any:
    """``data`` of an API envelope (``{success, data, error}``), raising its
    ``error`` when ``success`` is false; any other body as it is."""
    if isinstance(body, dict) and "success" in body and ("data" in body or "error" in body):
        if not body.get("success"):
            raise WillowError(body.get("error") or "Request failed")
        return body.get("data")
    return body


#: How many blocks behind the consensus RPC's latest height a verified read's
#: state may be (see ``DataOperations.get_verified``), unless the client's
#: ``max_proof_lag_blocks`` says otherwise.
DEFAULT_MAX_PROOF_LAG_BLOCKS = 20


@dataclass(frozen=True)
class VerifiedValue:
    """A value ``data.get_verified`` verified, and where.

    ``value`` is the value the proof proves. ``height`` is the height of the
    newest header found that carries the proof's root as its ``app_hash``
    (the latest header when it still carries it), as the consensus RPC
    serves it: the value is as of that header's state, the state after
    block ``height - 1``. ``root_hash`` is that root, as hex.
    """

    value: Any
    height: int
    root_hash: str


class _WriteResult(dict):
    """A write's ``{tx_hash, code, log, did, nonce}``, remembering the
    hand-out of its nonce it was sent under (see ``wait_until_landed``)."""


_NO_TRUSTED_HEADER_SOURCE = (
    "no trusted header source: set consensus_rpc_url to the CometBFT RPC of a node you trust "
    "(data.get_unverified reads the value without verification)"
)


def _unsupported_data_write(operation: str, route: str, kind: str) -> WillowError:
    return WillowError(
        f"{operation} is not supported: the node API does not serve {route}. Data "
        f"changes only through a {kind} transaction submitted to POST /tx/submit, "
        f"which this SDK does not build."
    )


def _schema_json(schema: Any) -> str:
    """A ``SchemaDefinition`` as the node's schema JSON text (the node's
    ``SchemaDefinition``).

    The node maps each field to its type name and lists required fields in
    ``required_fields``; a field's ``required`` flag joins that list. The node
    supports no schema indexes, so a schema with ``indexes`` or a field
    flagged ``indexed`` is refused (``ValueError``), as is a ``version``
    outside u32 (when the transaction is signed).
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

    Provides methods for storing and reading data. ``get`` verifies the
    value it returns against a proof and a trusted root, or raises;
    ``get_unverified`` and ``query_unverified`` return what the API serves.
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

            On any of the last three, and on ``asyncio.CancelledError``,
            ``error.submitted`` holds the results of the keys submitted
            before it and ``error.failed_key`` the key that wasn't; the keys
            after it were not sent.
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
            except (Exception, asyncio.CancelledError) as e:
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
        """Get a single item from a subgrove, verified against its proof and
        the headers the configured consensus RPC serves: ``get_verified``'s
        value. See ``get_verified`` for what is checked and trusted.

        Args:

            subgrove_id: Subgrove/dataset identifier
            key: Item key

        Returns:
            The data item

        Raises:
            ProofHeightOutOfRangeError: The proof's state is not current
                (see ``get_verified``).
            ProofVerificationError: It isn't verified (see ``get_verified``).
            WillowError: A read was refused (a key that isn't there, say).
        """
        return (await self.get_verified(subgrove_id, key)).value

    @require_auth
    async def get_verified(self, subgrove_id: str, key: str) -> VerifiedValue:
        """Get a single item from a subgrove, verified against its proof and
        the headers the configured consensus RPC serves, with the header it
        is proven at.

        Reads the value (``GET /data/{subgrove_id}/{key}``) and its proof
        (``GET /proof/{subgrove_id}/{key}``) from the API. The proof must
        prove an Item at ``key`` under the subgrove's data path
        (``subgrove_data_path(subgrove_id)``) whose JSON is the value served,
        and the root it computes must be the ``app_hash`` of the CometBFT
        header at the proof's ``height + 1`` (the state after block
        ``height``), as the node at ``consensus_rpc_url`` serves it
        (``GET /header?height=``). A header the chain hasn't produced yet is
        waited for, up to the client's ``timeout``.

        The API chooses the height, so a replayed old proof would otherwise
        verify as current. The proof's state must be current within the
        client's ``max_proof_lag_blocks`` (default 20) of the latest height
        the consensus RPC reports. The node proves at the last block with
        transactions, and a block without transactions leaves the app hash
        as it was, so a header ``G`` (which carries the state after block
        ``G - 1``) is recent when ``latest - (G - 1) <= max_proof_lag_blocks``,
        and the proof is accepted when a recent header carries its root:
        the header after its block, the latest header, or one between. A
        proof no recent header carries, or one naming a height more than
        ``max_proof_lag_blocks`` ahead of the latest, raises
        ``ProofHeightOutOfRangeError``.

        Trust: the SDK does not verify CometBFT commit signatures. It trusts
        the consensus node you configure for its headers and its latest
        height, as a client trusts its own node, and nothing the API serves.
        Point ``consensus_rpc_url`` at a node you run or trust, not at the
        API.

        Args:

            subgrove_id: Subgrove/dataset identifier
            key: Item key

        Returns:
            A ``VerifiedValue``: the value the proof proves, the height of
            the newest header found that carries its root, and the root.
            Nothing is returned unverified.

        Raises:
            ProofHeightOutOfRangeError: The proof's state is not current, as
                above (the proof may be genuine but stale).
            ProofVerificationError: No ``consensus_rpc_url`` is configured
                (raised before any request), the API returned no proof or no
                height, the proof doesn't prove the value served at ``key``
                under the subgrove's data, the consensus RPC serves no header
                for the proof's state, or the roots differ.
            WillowError: A read was refused (a key that isn't there, say).
        """
        if not self.client.consensus_rpc_url:
            raise ProofVerificationError(_NO_TRUSTED_HEADER_SOURCE)
        data_response = await self.client._request(
            "GET",
            f"/data/{subgrove_id}/{key}",
            authenticated=True,
            read=True,
        )
        proof_response = await self.client._request(
            "GET",
            f"/proof/{subgrove_id}/{key}",
            authenticated=True,
            read=True,
        )
        try:
            return await self._verified_value(subgrove_id, key, data_response, proof_response)
        except ProofVerificationError:
            raise
        except Exception as e:
            # A malformed answer fails as an unverified one does.
            raise ProofVerificationError(f"Proof verification failed for key {key!r}: {e}") from e

    async def _verified_value(
        self, subgrove_id: str, key: str, data_response: Any, proof_response: Any
    ) -> VerifiedValue:
        """What ``data.get_verified`` returns from the API's two answers, or
        ``ProofVerificationError``."""
        data = data_response.get("data")
        proof = proof_response.get("data")
        proof_hex = proof.get("proof") if isinstance(proof, dict) else None
        if not isinstance(proof_hex, str) or not proof_hex:
            raise ProofVerificationError(
                f"The API returned no proof for key {key!r}: the value is not verified. "
                "Use get_unverified to read it without verification."
            )
        height = proof.get("height")
        if isinstance(height, bool) or not isinstance(height, int) or height < 0:
            raise ProofVerificationError(
                f"The proof for key {key!r} names no block height: there is no root to check it against"
            )

        try:
            # The chain stores only Items in a subgrove's data tree, so a
            # 63-byte element there is an Item (see verify_item_at_path).
            root_hash, item = verify_item_at_path(
                bytes.fromhex(proof_hex), subgrove_data_path(subgrove_id), key,
                only_items_at_path=True,
            )
        except (ValueError, GroveDBVerificationError) as e:
            raise ProofVerificationError(f"Proof verification failed for key {key!r}: {e}") from e
        proven = stored_value(item.value)
        if not json_values_equal(proven, data):
            raise ProofVerificationError(
                f"The value the API served for key {key!r} is not the value its proof proves"
            )

        proven_at = await self.client._header_carrying(root_hash, height, f"key {key!r}")
        return VerifiedValue(value=proven, height=proven_at, root_hash=root_hash.hex())

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
        """Not supported: raises ``UnsupportedError`` without a request.

        A verified query would need its documents bound to the proof: the
        node returns documents without their keys and proves the subgrove's
        whole data tree, so nothing ties a document to a proven value or to
        the query's filter, order, offset, and limit. ``query_unverified``
        returns the API's documents unverified; ``get`` verifies one key.
        """
        raise UnsupportedError(_QUERY_UNSUPPORTED)

    @require_auth
    async def query_unverified(self, subgrove_id: str, query: Dict[str, Any]) -> QueryResponse:
        """Query indexed data without proof verification.

        The documents are what the API serves; nothing verifies them.

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
        historical data for this checkpoint. The answer, its proof, and its
        state root are what the API serves: the SDK verifies none of them.

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
        """Deprecated and not supported: raises ``UnsupportedError`` without a
        request.

        The node serves no historical proof, and the checkpoint state root a
        historical answer carries is not a trusted root, so nothing can be
        verified. ``query_historical`` returns the unverified answer.
        """
        raise UnsupportedError(_HISTORICAL_UNSUPPORTED)


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
                subgrove ID is not one the node takes, a writer or reader
                isn't a DID, or the schema is missing, declares indexes, has
                a type the node does not take, or has a version outside u32.
                Nothing is sent.
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
        """Get the API's Merkle proof for a data item, unverified.

        Check it with ``ProofVerifier.verify_item_proof`` against a root you
        trust, or use ``data.get``, which does.

        Args:

            subgrove_id: Subgrove identifier
            key: Item key

        Returns:
            Proof data including proof hex and value, as the API serves it
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

        - :attr:`QuerySource.VALIDATOR` — the validator's chain-tip data.
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
            along with which backend served it. The answer, and any proof it
            carries, is what that backend serves: the SDK verifies neither.
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
            :class:`RoutedQueryResult` wrapping the :class:`SqlResponse`. The
            answer, and any proof it carries, is what the backend serves:
            the SDK verifies neither.
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
        self._consensus_rpc_url: Optional[str] = None
        self._max_proof_lag_blocks = DEFAULT_MAX_PROOF_LAG_BLOCKS

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
        """Kept for compatibility, and ignored: the client makes no light
        client (``data.get`` reads headers from ``consensus_rpc_url``)."""
        self._light_client_config = config
        return self

    def indexer_url(self, url: str) -> "WillowClientBuilder":
        """Set indexer node URL for routing GraphQL/SQL queries."""
        self._indexer_url = url
        return self

    def consensus_rpc_url(self, url: str) -> "WillowClientBuilder":
        """Set the CometBFT RPC URL of a node you trust: ``data.get`` reads
        the headers it checks proofs against from it, and the client reads
        which nonces are used from it."""
        self._consensus_rpc_url = url
        return self

    def max_proof_lag_blocks(self, blocks: int) -> "WillowClientBuilder":
        """Set how many blocks behind the consensus RPC's latest height a
        verified read's state may be (see ``DataOperations.get_verified``)."""
        self._max_proof_lag_blocks = blocks
        return self

    def build(self) -> "WillowClient":
        """Build and return the WillowClient instance."""
        return WillowClient(
            api_url=self._api_url,
            timeout=self._timeout,
            retry_config=self._retry_config,
            proof_verification_options=self._proof_options,
            indexer_url=self._indexer_url,
            consensus_rpc_url=self._consensus_rpc_url,
            max_proof_lag_blocks=self._max_proof_lag_blocks,
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
        consensus_rpc_url: Optional[str] = None,
        max_proof_lag_blocks: int = DEFAULT_MAX_PROOF_LAG_BLOCKS,
    ):
        """Initialize Willow client.

        Args:
            api_url: Base URL for Willow API
            timeout: Request timeout in seconds
            retry_config: Optional retry configuration
            proof_verification_options: Optional configuration of the global
                proof verifier (``ProofVerifier``, ``verify_item_proof``,
                ``verify_query_proof``). ``data.get`` checks its proof
                against a header from ``consensus_rpc_url`` instead.
            indexer_url: Optional indexer node URL for routing GraphQL/SQL
                queries. Requests to it carry the API key; requests to
                indexers found through discovery do not.
            api_key: Managed-tier API key (``wk_...``). When set, the SDK
                sends ``X-API-Key`` on its HTTP requests to the API (and to
                ``indexer_url``), never to a discovered indexer or the
                consensus RPC. Mint a key at
                https://dashboard.willow.tech/account. Required for queries
                and writes against managed ``api.willow.tech`` /
                ``indexer.willow.tech``.
            consensus_rpc_url: The CometBFT RPC URL (typically port 26657)
                of a node you run or trust: the client's trusted source of
                chain state. ``data.get`` and ``get_root_hash`` read headers
                from it (``GET /header``) and raise
                ``ProofVerificationError`` without it; the SDK does not
                verify commit signatures, so it trusts this node, as a
                client trusts its own node. Don't point it at the API: a
                header the API serves verifies nothing the API serves. The
                client also reads which of the nonces above an account's
                base are used (ABCI query
                ``/store/account_nonce_state/{did}``), so
                ``wait_until_landed`` sees a write land even while a lower
                nonce is unused (without it, only the base, from
                ``GET /account/{did}/nonce``), and
                ``completeness`` reads its on-chain anchors from it (and
                raises ``CompletenessError`` without it).
                Requests to it carry no ``X-API-Key``.
            max_proof_lag_blocks: How many blocks behind the latest height
                ``consensus_rpc_url`` reports a verified read's state may be
                (see ``DataOperations.get_verified``): a non-negative
                integer, 20 by default.
        """
        if (
            isinstance(max_proof_lag_blocks, bool)
            or not isinstance(max_proof_lag_blocks, int)
            or max_proof_lag_blocks < 0
        ):
            raise ValueError(
                f"max_proof_lag_blocks must be a non-negative integer, not {max_proof_lag_blocks!r}"
            )
        self.max_proof_lag_blocks = max_proof_lag_blocks
        self.api_url = api_url.rstrip("/")
        self.indexer_url = indexer_url.rstrip("/") if indexer_url else None
        self.timeout = timeout
        self.retry_config = retry_config or RetryConfig()
        self.api_key = api_key
        self.consensus_rpc_url = consensus_rpc_url.rstrip("/") if consensus_rpc_url else None
        self._did: Optional[str] = None
        self._private_key: Optional[str] = None
        self._public_key_id: Optional[str] = None
        self._algorithm: SignatureAlgorithm = "Ed25519"

        # The nonces handed out per signing DID (see ``willow.nonces``).
        self._nonces = NonceTracker()
        self._nonce_poll_interval = 1.0
        self._nonce_wait_timeout = 60.0
        #: Writes cancelled after they were signed, while their submission
        #: was in flight, keyed by ``(did, nonce)`` (see ``InterruptedWrite``
        #: and ``resubmit``).
        self.interrupted_writes: Dict[Tuple[str, int], InterruptedWrite] = {}

        # Configure proof verification if options provided
        if proof_verification_options:
            configure_proof_verification(proof_verification_options)

        # Seconds between reads of a header the chain hasn't produced yet.
        self._header_poll_interval = 0.5

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
        self.files = FileOperations(self.api_url, api_key=api_key, client=self)

        # HTTP client. ``X-API-Key`` is set as a default header so it
        # rides on every request through this client (data, query, proof,
        # token, validator, indexing, privacy — all routes through
        # ``self._http``). Per-request auth headers (DID signature) are
        # merged on top at call sites and do not replace the default.
        default_headers = {"X-API-Key": api_key} if api_key else {}
        self._http = httpx.AsyncClient(timeout=timeout, headers=default_headers)
        # The consensus RPC is another host: its requests carry no API key.
        self._rpc_http = httpx.AsyncClient(timeout=timeout)
        # Indexers found through discovery are hosts their operators choose:
        # their requests carry no API key either. Only an indexer_url the
        # caller configures gets it (see _route_query).
        self._indexer_http = httpx.AsyncClient(timeout=timeout)

        # Client-side completeness checks. The on-chain anchor is read from
        # consensus_rpc_url, without the API key, and never from the API's
        # host: without it the anchor reads raise. The matched-log preimage
        # comes from the configured indexer.
        self.completeness = CompletenessOperations(
            self._http,
            self.consensus_rpc_url,
            self.indexer_url,
            rpc_http=self._rpc_http,
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
        await self._rpc_http.aclose()
        await self._indexer_http.aclose()

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
            # The API key goes only to an indexer_url the caller configured,
            # never to an indexer discovery found.
            http = self._http if self.indexers.has_explicit_override() else self._indexer_http
            resp = await http.post(url, json=body, headers=headers)
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
            NetworkError: The submission failed in transit. As for any write
                (see ``resubmit``), its ``transaction`` is set when it may
                have reached the node.
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
        return await self._submit_signed(did, 1, create_transaction_wrapper("RegisterDid", tx))

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

    async def _consensus_header(self, height: Optional[int] = None) -> Optional[Tuple[int, bytes]]:
        """The ``(height, app_hash)`` of the CometBFT header at ``height``
        (the latest without one), as the node at ``consensus_rpc_url`` serves
        it (``GET /header``), sent without the API key; ``None`` when the
        node answers an error (a height it hasn't produced, or has pruned).

        Raises:
            ProofVerificationError: No ``consensus_rpc_url``, the request
                failed, or the answer isn't a header (at ``height``).
        """
        if not self.consensus_rpc_url:
            raise ProofVerificationError(_NO_TRUSTED_HEADER_SOURCE)
        where = "the latest header" if height is None else f"the header at height {height}"
        try:
            response = await self._rpc_http.get(
                f"{self.consensus_rpc_url}/header",
                params=None if height is None else {"height": str(height)},
            )
            body = response.json()
        except (httpx.HTTPError, ValueError, RecursionError) as e:
            raise ProofVerificationError(f"No trusted root: reading {where} from the consensus RPC failed: {e}") from e
        if isinstance(body, dict) and body.get("error") is not None and body.get("result") is None:
            return None
        result = body.get("result") if isinstance(body, dict) else None
        header = result.get("header") if isinstance(result, dict) else None
        served = header.get("height") if isinstance(header, dict) else None
        app_hash = header.get("app_hash") if isinstance(header, dict) else None
        try:
            if isinstance(served, bool) or not isinstance(served, (str, int)):
                raise ValueError("no height")
            served = int(served)
            root = bytes.fromhex(app_hash) if isinstance(app_hash, str) else b""
            if len(root) != 32:
                raise ValueError("no 32-byte app_hash")
        except ValueError as e:
            raise ProofVerificationError(
                f"No trusted root: the consensus RPC answered no header for {where} ({e})"
            ) from e
        if response.status_code != 200 or (height is not None and served != height):
            raise ProofVerificationError(
                f"No trusted root: the consensus RPC answered a header at height {served} "
                f"(HTTP {response.status_code}) for {where}"
            )
        return served, root

    async def get_root_hash(self) -> str:
        """The ``app_hash`` (hex) of the latest header the node at
        ``consensus_rpc_url`` serves: the root of the state after the block
        before it. The SDK verifies no commit signature: it trusts that node.

        Raises:
            ProofVerificationError: No ``consensus_rpc_url`` is configured,
                or it served no header.
        """
        header = await self._consensus_header()
        if header is None:
            raise ProofVerificationError("No trusted root: the consensus RPC served no latest header")
        return header[1].hex()

    async def _trusted_app_hash(self, height: int) -> bytes:
        """The ``app_hash`` of the CometBFT header at ``height``, as the node
        at ``consensus_rpc_url`` serves it. A header the chain hasn't
        produced yet is waited for, for up to ``timeout`` seconds.

        Raises:
            ProofVerificationError: No such header.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout
        produced = False
        while True:
            header = await self._consensus_header(height)
            if header is not None:
                return header[1]
            latest = None if produced else await self._consensus_header()
            if latest is None or loop.time() >= deadline:
                raise ProofVerificationError(
                    f"No trusted root: the consensus RPC serves no header at height {height}"
                )
            # Produced since the read above: read it once more.
            produced = latest[0] >= height
            if not produced:
                await asyncio.sleep(self._header_poll_interval)

    async def _header_carrying(self, root: bytes, height: int, what: str) -> int:
        """The height of the newest header found that carries ``root``, the
        root of a proof of the state after block ``height``, when that state
        is current (see ``DataOperations.get_verified``).

        Raises:
            ProofHeightOutOfRangeError: ``height`` is more than
                ``max_proof_lag_blocks`` ahead of the latest, or no header
                within that lag of it carries ``root``.
            ProofVerificationError: The header after block ``height`` doesn't
                carry ``root``, or the consensus RPC serves no header needed.
        """
        lag = self.max_proof_lag_blocks
        latest = await self._consensus_header()
        if latest is None:
            raise ProofVerificationError("No trusted root: the consensus RPC served no latest header")
        latest_height, latest_root = latest
        if height - latest_height > lag:
            raise ProofHeightOutOfRangeError(
                f"The proof for {what} is of the state after block {height}, "
                f"{height - latest_height} blocks ahead of the chain's latest ({latest_height}); "
                f"at most max_proof_lag_blocks ({lag}) is accepted"
            )
        after = height + 1
        trusted_root = await self._trusted_app_hash(after)
        if root != trusted_root:
            raise ProofVerificationError(
                f"Root hash mismatch for {what}: the proof computes {root.hex()}, "
                f"the header at height {after} has app_hash {trusted_root.hex()}"
            )
        if latest_height >= after and latest_root == root:
            return latest_height
        if latest_height - height <= lag:
            return after

        async def carries(h: int) -> bool:
            header = await self._consensus_header(h)
            if header is None:
                raise ProofVerificationError(f"No trusted root: the consensus RPC serves no header at height {h}")
            return header[1] == root

        # The header after the proof's block is not recent: a header G is
        # recent when latest - (G - 1) <= lag. A header carries one app hash
        # from the block that wrote it until the next block with
        # transactions, so the oldest recent header carries the root if any
        # recent one does; then find the newest that does.
        oldest = latest_height - lag + 1
        if oldest > latest_height or not await carries(oldest):
            raise ProofHeightOutOfRangeError(
                f"The proof for {what} is stale: it is of the state after block {height}, "
                f"{latest_height - height} blocks behind the chain's latest ({latest_height}), and no "
                f"header within max_proof_lag_blocks ({lag}) of it carries its root"
            )
        low, high = oldest, latest_height - 1
        while low < high:
            middle = (low + high + 1) // 2
            if await carries(middle):
                low = middle
            else:
                high = middle - 1
        return low

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

    async def _nonce_state(self, did: str) -> Tuple[int, FrozenSet[int]]:
        """``did``'s base and the nonces above it the node reports used.

        With ``consensus_rpc_url``, from the ABCI query
        ``/store/account_nonce_state/{did}``; without it, or when that query
        fails, the base alone from ``GET /account/{did}/nonce``. A base the
        consensus RPC answers replaces a higher one only the API answered.
        """
        if self.consensus_rpc_url:
            try:
                base, used = await self._query_nonce_state(did)
                self._nonces.trust_base(did, base)
                return base, used
            except (WillowError, httpx.HTTPError, ValueError, RecursionError) as e:
                # RecursionError: an answer nested too deep to read.
                logger.warning(f"Could not read the nonce state of {did} over RPC, reading the base: {e}")
        return await self._account_nonce(did), frozenset()

    async def _query_nonce_state(self, did: str) -> Tuple[int, FrozenSet[int]]:
        """The ABCI query ``/store/account_nonce_state/{did}`` (see
        ``parse_nonce_state``), sent without the API key."""
        response = await self._rpc_http.post(
            self.consensus_rpc_url or "",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "abci_query",
                "params": {
                    "path": f"/store/account_nonce_state/{did}",
                    "data": "",
                    "height": "0",
                    "prove": False,
                },
            },
        )
        if response.status_code != 200:
            raise WillowError(f"nonce state query: HTTP {response.status_code}")
        body = response.json()
        result = body.get("result") if isinstance(body, dict) else None
        answer = result.get("response") if isinstance(result, dict) else None
        if not isinstance(answer, dict):
            raise WillowError(f"nonce state query: malformed answer {body!r}")
        if answer.get("code", 0) != 0:
            raise WillowError(f"nonce state query: {answer.get('log') or 'code ' + str(answer.get('code'))}")
        return parse_nonce_state(base64.b64decode(answer.get("value") or "", validate=True))

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
            nonce = self._nonces.take(did, *await self._nonce_state(did))
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
        """Sign ``tx`` as the identity under a nonce it hands out, and submit
        it (see ``_submit_under_nonce``).

        Returns:
            The ``{tx_hash, code, log, did, nonce}`` of the accepted
            transaction.
        """
        create_sign_message(tx_type, tx)  # refuse what can't be signed before taking a nonce

        def sign(nonce: int) -> Dict[str, Any]:
            tx.nonce = nonce
            return self._sign_transaction(tx_type, tx)

        return await self._submit_under_nonce(self._did or "", sign, read_base)

    async def _submit_under_nonce(
        self,
        did: str,
        sign: Callable[[int], Dict[str, Any]],
        read_base: bool = True,
        nonce: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Submit the transaction ``sign(n)`` builds, signed by ``did`` under
        a nonce ``n`` this client hands out, or under ``nonce`` when given.

        A transaction CheckTx refuses gives its nonce back, unless the
        refusal says the nonce is held by a pending transaction, already
        used, or spent. The write is never signed again under another nonce:
        a refusal can follow from this very transaction having reached the
        node (an API may pass it on and answer that its nonce is used), and a
        second copy under another nonce would run it twice. See
        ``_submit_signed`` for what each refusal carries.

        Raises:
            ValueError: ``nonce`` is outside the node's window, used, or
                handed to another write within its lease. Nothing is sent.
        """
        if nonce is not None:
            base, used = await self._nonce_state(did)
            if not self._nonces.claim(did, base, nonce, used):
                raise ValueError(
                    f"nonce {nonce} of {did} is not free: it is outside the 24 above the "
                    f"account's base, used, or handed to another write; leave it out and "
                    f"the client picks one"
                )
        n = nonce if nonce is not None else await self._take_nonce(did, read_base)
        try:
            signed = sign(n)
        except BaseException:
            self._nonces.release(did, n)
            raise
        return await self._submit_signed(did, n, signed)

    async def _submit_signed(
        self, did: str, nonce: int, transaction: Dict[str, Any], resubmission: bool = False
    ) -> Dict[str, Any]:
        """Submit a transaction signed under ``nonce`` of ``did``, and record
        what its answer leaves the nonce as.

        A submission that never left (the connection was refused or timed
        out) gives its nonce back, unless it is a ``resubmission``, whose
        earlier copy may have reached the node. One that may have reached
        the node (it failed in transit after connecting, or the API answered
        a gateway error with no CheckTx answer) keeps its nonce until its
        lease runs out, and its error carries the signed ``transaction`` for
        ``resubmit``. So does a ``resubmission`` refused for anything but its
        nonce being used: the earlier copy may be pending or have landed,
        whatever the refusal says. A refusal that the nonce is already used,
        at or below the base, or spent marks it used, and its error carries
        the ``transaction`` and says to read what the write wrote before
        sending it again: some transaction used the nonce, which may be this
        one. Every error carries the ``did`` and ``nonce``. A cancellation
        records the write in ``interrupted_writes`` before it propagates.
        """
        handout = self._nonces.handout(did, nonce)

        def mark(write: Any) -> Any:
            write._handout = handout
            write._tracker = self._nonces
            return write

        try:
            response = await self._post_transaction(transaction)
        except asyncio.CancelledError as e:
            self.interrupted_writes[(did, nonce)] = mark(InterruptedWrite(did, nonce, transaction, handout))
            e.did, e.nonce, e.transaction = did, nonce, transaction  # type: ignore[attr-defined]
            mark(e)
            raise
        except NetworkError as e:
            e.did, e.nonce = did, nonce
            if getattr(e, "_sent", True) or resubmission:
                e.transaction = transaction
                mark(e)
            else:
                self._nonces.release(did, nonce, handout)
            raise
        try:
            return mark(_WriteResult(_tx_submit_result(response), did=did, nonce=nonce))
        except TransactionError as e:
            e.did, e.nonce = did, nonce
            outcome = refusal_outcome(e, response.status_code, nonce)
            if resubmission and outcome in (FREE, HELD):
                outcome = UNKNOWN
            self._nonces.settle(did, nonce, outcome, handout)
            if outcome == UNKNOWN:
                e.transaction = transaction
                mark(e)
            elif outcome == USED:
                # Some transaction used its nonce: this one, if it reached the
                # node before the answer (an earlier copy, or an API that
                # passed it on), or another one the same DID signed.
                e.transaction = transaction
                e.message = (
                    f"nonce {nonce} of {did} is used ({e.message}): some transaction used "
                    f"it, which may be this one, so it was not signed again under another "
                    f"nonce; read what the write wrote before sending it again"
                )
                e.args = (e.message,)
                mark(e)
            raise

    async def resubmit(self, failed: Any) -> Dict[str, Any]:
        """Send again, under its own nonce, a write that may have reached the node.

        ``failed`` is the ``NetworkError`` or ``TransactionError`` a write
        raised with its ``transaction`` set: it failed in transit after
        connecting, or the API answered a gateway error, so the transaction
        may have reached the node. It can also be an ``InterruptedWrite``
        from ``interrupted_writes`` (a write cancelled while its submission
        was in flight); resubmitting a write removes it from there. This
        sends those exact bytes again, as the node's retry rule asks:
        whichever copy lands first spends the nonce, and the other is
        refused, so the write runs at most once. Don't send it again as a new
        write: under another nonce both copies could run.

        Returns:
            The ``{tx_hash, code, log, did, nonce}`` once CheckTx accepts
            it. When the node already holds an identical copy ("tx already
            exists in cache"), that counts as accepted: ``code`` 0 and no
            ``tx_hash``. Wait for it with ``wait_until_landed``.

        Raises:
            ValueError: ``failed`` carries no ``transaction`` (a write that
                never left: call it again instead).
            WillowError: This client has handed the nonce to another write
                since (``resubmit`` came after the 120 s lease ran out),
                whether or not that write has landed, so nothing is sent.
                Read what the write wrote to learn whether it took effect.
            TransactionError: CheckTx refused it; the error carries
                ``transaction`` again. A refusal that its nonce is already
                used, or at or below the base, means some transaction used
                that nonce: this write's earlier copy, or another one signed
                by the same DID elsewhere. Read what the write wrote to learn
                whether it took effect; a copy refused in its block spends
                its nonce too. Any other refusal leaves the nonce taken: CheckTx
                checks some rules (a subgrove that exists, a funded balance)
                before the nonce, so it can follow from the earlier copy
                having landed, or the earlier copy may still be pending.
            NetworkError: It failed in transit again; ``resubmit`` it again.
        """
        transaction = getattr(failed, "transaction", None)
        did = getattr(failed, "did", None)
        nonce = getattr(failed, "nonce", None)
        if (
            not isinstance(transaction, dict)
            or not isinstance(did, str)
            or isinstance(nonce, bool)
            or not isinstance(nonce, int)
        ):
            raise ValueError(
                "resubmit takes the error of a write that may have reached the node "
                "(its transaction set); a write that never left is sent by calling it again"
            )
        interrupted = self.interrupted_writes.get((did, nonce))
        if interrupted is not None and interrupted.transaction == transaction:
            del self.interrupted_writes[(did, nonce)]
        if not self._nonces.reclaim(did, nonce, getattr(failed, "_handout", None)):
            raise WillowError(
                f"nonce {nonce} of {did} was handed to another write after this one's "
                f"lease ran out, so it can't be resubmitted under it; read what the write "
                f"wrote to learn whether it took effect"
            )
        failed._handout = self._nonces.handout(did, nonce)  # type: ignore[attr-defined]
        return await self._submit_signed(did, nonce, transaction, resubmission=True)

    async def _post_transaction(self, tx: Dict[str, Any]) -> httpx.Response:
        """POST a JSON transaction to the API's ``/tx/submit``.

        Raises:
            NetworkError: On network errors. Its ``_sent`` is ``False`` when
                the request never left (the connection was refused or timed
                out, or no pooled connection came free), else ``True``.
        """
        try:
            return await self._http.request(
                "POST",
                f"{self.api_url}/tx/submit",
                content=_encode_json_body(tx),
                headers={"Content-Type": "application/json"},
            )
        except httpx.RequestError as e:
            if isinstance(e, httpx.TimeoutException):
                error = NetworkError(f"Request timed out: {e}" if str(e) else "Request timed out")
            else:
                error = NetworkError(f"Network error: {str(e)}")
            error._sent = not isinstance(e, _NEVER_SENT)  # type: ignore[attr-defined]
            raise error from e

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
        ``registration.register_subgrove``, the ``privacy`` grants,
        ``resubmit``) or a list of them (``data.store``,
        ``data.batch_store``); or the error a write raised, which carries its
        ``did`` and ``nonce``. A write returns once CheckTx accepts it; send
        one that depends on it (a write after the DID's registration, a store
        into a subgrove just registered) only after it lands. Writes in
        flight together may land in any order.

        A nonce counts as used once it is at or below the account's base, or
        the node reports it used above the base. Only with
        ``consensus_rpc_url`` does the client read the nonces used above the
        base (otherwise only those CheckTx has refused as already used): the
        base advances only over used nonces with no gap below them, so
        without it a write counts as landed only once every lower nonce of
        its DID is used too. A nonce no transaction uses (one given back
        after CheckTx refused its write, or one whose write failed in transit
        and was never resubmitted) then holds back every write above it,
        until this client hands that nonce to a later write and that write
        lands.

        A write refused in its block uses its nonce too: read what it wrote
        to know it took effect. A RegisterDid uses its nonce only when it
        succeeds.

        Only a write that may run can be waited on: one CheckTx accepted, or
        one that may have reached the node (its error carries
        ``transaction``). The error of a write that was never sent or that
        CheckTx refused (``transaction`` is ``None``), or a refused
        ``BroadcastResult``, raises ``ValueError``: it never ran, and a later
        write may take its nonce. (A refusal that the nonce is used is the
        exception: it carries ``transaction``, since this write may be the
        one that used it, and the wait returns at once; read what it wrote
        to learn whether it took effect.) A write that never lands keeps its nonce
        for 120 s; after that this client may hand the nonce to another
        write, and waiting on the first then raises (``ValueError`` before
        the wait, ``NotLandedError`` during it) instead of reporting the
        other write's landing as its own.

        Raises:
            NotLandedError: A nonce wasn't used within ``timeout`` seconds,
                or this client handed it to another write while waiting.
            ValueError: A write carries no ``did`` and ``nonce``, never ran,
                or its nonce has been given back or handed to another write
                by this client.
        """
        targets: Dict[str, Dict[int, List[Any]]] = {}
        pending: List[Any] = list(writes)
        while pending:
            write = pending.pop()
            if isinstance(write, (list, tuple)):
                pending.extend(write)
                continue
            if isinstance(write, dict):
                did, nonce = write.get("did"), write.get("nonce")
            else:
                did, nonce = getattr(write, "did", None), getattr(write, "nonce", None)
            if not isinstance(did, str) or isinstance(nonce, bool) or not isinstance(nonce, int):
                raise ValueError("each write must be the {..., did, nonce} result a write returned")
            refused = isinstance(write, BaseException) or getattr(write, "success", True) is False
            if refused and getattr(write, "transaction", None) is None:
                raise ValueError(
                    f"nonce {nonce} of {did}: this write was never sent, or CheckTx refused it, so it "
                    f"never ran and there is nothing to wait for (a later write may take its nonce)"
                )
            if not self._still_its_nonce(write, did, nonce):
                raise ValueError(
                    f"nonce {nonce} of {did} was given back or handed to another write after this "
                    f"write's lease ran out: waiting on it would wait on that write; read what this "
                    f"write wrote to learn whether it took effect"
                )
            targets.setdefault(did, {}).setdefault(nonce, []).append(write)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        for did, nonces in targets.items():
            while True:
                base, used = await self._nonce_state(did)
                base = self._nonces.observe(did, base, used)
                for n, those in nonces.items():
                    if not all(self._still_its_nonce(write, did, n) for write in those):
                        raise NotLandedError(
                            f"nonce {n} of {did} was handed to another write after this write's "
                            f"lease ran out, before it landed: read what it wrote to learn whether "
                            f"it took effect"
                        )
                waiting = sorted(n for n in nonces if not self._nonces.is_used(did, n))
                if not waiting:
                    break
                if loop.time() >= deadline:
                    raise NotLandedError(
                        f"nonce {', '.join(map(str, waiting))} of {did} was not used within "
                        f"{timeout} s: the account's base nonce is {base}"
                    )
                await asyncio.sleep(poll_interval)

    def _still_its_nonce(self, write: Any, did: str, nonce: int) -> bool:
        """Whether this client hasn't given back or handed to another write
        the nonce a write it sent went out under (``True`` for a write it
        didn't send)."""
        if getattr(write, "_tracker", None) is not self._nonces:
            return True
        return self._nonces.still_handed_to(did, nonce, getattr(write, "_handout", None))

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
