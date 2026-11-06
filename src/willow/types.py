"""Type definitions for Willow SDK.

This module contains all data structures used for communicating with
the Willow API, including request/response types, DID documents, and
indexing-related structures.
"""

from typing import Dict, List, Optional, Any, Literal, Union
from pydantic import AliasChoices, BaseModel, Field
from enum import Enum


# ============================================================================
# Enums
# ============================================================================

class SignatureAlgorithm(str, Enum):
    """Signature algorithm for DIDs."""
    ED25519 = "Ed25519"
    SECP256K1 = "secp256k1"


class ValidatorStatus(str, Enum):
    """Validator status."""
    ACTIVE = "active"
    JAILED = "jailed"
    UNBONDING = "unbonding"
    INACTIVE = "inactive"


class SubgroveStatus(str, Enum):
    """Subgrove status."""
    ACTIVE = "active"
    SYNCING = "syncing"
    SYNCED = "synced"
    PAUSED = "paused"
    FAILED = "failed"


class IndexerStatus(str, Enum):
    """Indexer status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SLASHED = "slashed"


class PermissionRole(str, Enum):
    """Permission role."""
    OWNER = "owner"
    ADMIN = "admin"
    WRITER = "writer"
    READER = "reader"


class IndexType(str, Enum):
    """Index type for datasets."""
    UNIQUE = "unique"
    HASH = "hash"
    RANGE = "range"
    FULLTEXT = "fulltext"
    COMPOUND = "compound"


class FieldTypeEnum(str, Enum):
    """Field type enumeration."""
    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    OBJECT = "object"
    ARRAY = "array"
    BYTES = "bytes"


# ============================================================================
# DID Types
# ============================================================================

class ServiceEndpoint(BaseModel):
    """Service endpoint in DID document."""
    id: str
    service_type: str = Field(alias="type")
    endpoint: str = Field(alias="service_endpoint")

    model_config = {"populate_by_name": True}


class PublicKey(BaseModel):
    """Public key in a DID document."""
    id: str
    key_type: str = Field(alias="type")
    controller: Optional[str] = None
    public_key_hex: Optional[str] = Field(None, alias="public_key_hex")
    public_key_base58: Optional[str] = Field(None, alias="public_key_base58")

    model_config = {"populate_by_name": True}


class DidDocument(BaseModel):
    """DID Document structure."""
    id: str
    public_keys: List[PublicKey] = Field(alias="public_keys")
    authentication: List[str] = Field(default_factory=list)
    service: List[ServiceEndpoint] = Field(default_factory=list)
    created: int
    updated: int
    proof: Optional[Any] = None

    model_config = {"populate_by_name": True}


class DidInfo(BaseModel):
    """DID information including keys."""
    did: str
    private_key: bytes
    public_key: bytes
    public_key_id: str
    did_document: DidDocument
    algorithm: SignatureAlgorithm

    model_config = {"arbitrary_types_allowed": True}

    def private_key_hex(self) -> str:
        """Get hex-encoded private key."""
        return self.private_key.hex()

    def public_key_hex(self) -> str:
        """Get hex-encoded public key."""
        return self.public_key.hex()


# ============================================================================
# Schema Types
# ============================================================================

class FieldType(BaseModel):
    """Schema field type definition."""
    type: FieldTypeEnum
    indexed: bool = False
    required: bool = False


class SchemaField(BaseModel):
    """Schema field definition."""
    field_type: str = Field(alias="type")
    required: bool = False
    indexed: bool = False

    model_config = {"populate_by_name": True}


class IndexDefinition(BaseModel):
    """Index definition for a dataset."""
    name: str
    fields: List[str]
    unique: bool = False
    index_type: Optional[IndexType] = Field(None, alias="type")

    model_config = {"populate_by_name": True}


class SchemaDefinition(BaseModel):
    """Dataset schema definition."""
    version: int
    fields: Dict[str, Union[FieldType, SchemaField]]
    indexes: Optional[List[IndexDefinition]] = None
    required_fields: List[str] = Field(default_factory=list, alias="required_fields")

    model_config = {"populate_by_name": True}


# ============================================================================
# Retention Types
# ============================================================================

class RetentionWindow(BaseModel):
    """How long real-time indexed data is retained on consensus nodes."""
    type: str  # "Blocks", "Seconds", or "Indefinite"
    value: Optional[int] = None


# ============================================================================
# Registration Types
# ============================================================================

class RegisterDatasetRequest(BaseModel):
    """Dataset/subgrove registration request."""
    dataset_id: str = Field(alias="dataset_id")
    name: str
    dataset_path: List[str] = Field(default_factory=list, alias="dataset_path")
    # Trailing underscore avoids shadowing BaseModel.schema(); wire format
    # is unchanged via the alias.
    schema_: Optional[SchemaDefinition] = Field(default=None, alias="schema")
    owner_did: str = Field(alias="owner_did")
    writers: List[str] = Field(default_factory=list)
    readers: List[str] = Field(default_factory=list)
    signature: Optional[bytes] = None
    public_key_id: Optional[str] = None
    nonce: Optional[int] = None

    model_config = {"populate_by_name": True}


# Alias for compatibility
RegisterSubgroveRequest = RegisterDatasetRequest


class SubgroveRegistration(BaseModel):
    """Subgrove/dataset registration info."""
    subgrove_id: str = Field(alias="subgrove_id")
    name: str
    subgrove_path: List[str] = Field(default_factory=list, alias="subgrove_path")
    schema_: Optional[SchemaDefinition] = Field(default=None, alias="schema")
    owner_did: str = Field(alias="owner_did")
    writers: List[str] = Field(default_factory=list)
    readers: List[str] = Field(default_factory=list)
    retention_window: Optional[RetentionWindow] = None
    created_at: int = Field(alias="created_at")
    updated_at: int = Field(alias="updated_at")

    model_config = {"populate_by_name": True}


# Alias for compatibility
DatasetRegistration = SubgroveRegistration


# ============================================================================
# API Response Types
# ============================================================================

class ApiResponse(BaseModel):
    """Generic API response wrapper."""
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None


class ProofData(BaseModel):
    """Proof response data: the GroveDB proof of a key (hex), the path and
    key it is at (hex segments), and the block ``height`` whose resulting
    state it proves (that state's root is the ``app_hash`` of the header at
    ``height + 1``)."""
    proof: str
    value: Optional[Dict[str, Any]] = None
    path: Optional[List[str]] = None
    key: Optional[str] = None
    height: Optional[int] = None


# ============================================================================
# Query Types
# ============================================================================

class QueryFilter(BaseModel):
    """Query filter for indexed data."""
    field: str
    value: Optional[Any] = None
    eq: Optional[Any] = Field(None, alias="$eq")
    ne: Optional[Any] = Field(None, alias="$ne")
    gt: Optional[Any] = Field(None, alias="$gt")
    gte: Optional[Any] = Field(None, alias="$gte")
    lt: Optional[Any] = Field(None, alias="$lt")
    lte: Optional[Any] = Field(None, alias="$lte")
    in_values: Optional[List[Any]] = Field(None, alias="$in")
    contains: Optional[str] = Field(None, alias="$contains")

    model_config = {"populate_by_name": True}


class QuerySearch(BaseModel):
    """Fulltext search parameters."""
    field: str
    query: str


class QuerySort(BaseModel):
    """Sort parameters for queries."""
    field: str
    order: Literal["asc", "desc"] = "asc"


class QueryRequest(BaseModel):
    """Query request for indexed data."""
    filters: Optional[Dict[str, Any]] = None
    search: Optional[QuerySearch] = None
    sort: Optional[QuerySort] = None
    limit: Optional[int] = None
    offset: Optional[int] = None
    include_proof: Optional[bool] = None


class QueryResponse(BaseModel):
    """Query response with documents."""
    documents: List[Dict[str, Any]]
    total: int
    limit: Optional[int] = None
    offset: Optional[int] = None
    proof: Optional[str] = None
    verified_root_hash: Optional[str] = Field(None, alias="verified_root_hash")

    model_config = {"populate_by_name": True}

    def verify_proof(self) -> str:
        """Not supported: raises ``UnsupportedError``.

        A query's documents come without their keys, and its proof covers
        the subgrove's whole data tree, so nothing binds the documents to the
        proof and the query's filter, order, offset, and limit. To check that
        each document is a value proven under a subgrove's data, call
        ``willow.proof.ProofVerifier.verify_query_proof(proof, documents,
        subgrove_data_path(id))`` (synchronous; it returns a
        ``ProofVerificationResult``); it proves nothing about the query.
        """
        from .errors import UnsupportedError
        raise UnsupportedError(_QUERY_UNSUPPORTED)


_QUERY_UNSUPPORTED = (
    "Verifying a query is not supported: its documents come without their keys and "
    "nothing binds them to the proof, the query's filter, order, offset, or limit. "
    "Use client.data.query_unverified for unverified documents, or client.data.get for "
    "a verified key."
)


# ============================================================================
# Historical Query Types (for checkpoint data)
# ============================================================================

class HistoricalQueryRequest(BaseModel):
    """Request for querying historical checkpoint data."""
    path: List[List[int]]  # GroveDB path as byte arrays
    key: Optional[List[int]] = None  # Key to query (for single-key queries)
    query_type: Optional[str] = None  # Query type: "get", "get_range", "get_path"
    include_proof: Optional[bool] = None  # Whether to include proof


class HistoricalQueryResponse(BaseModel):
    """Response from historical query."""
    success: bool
    provider_did: Optional[str] = None
    provider_endpoint: Optional[str] = None
    state_root: str  # The checkpoint's state root as its indexer submitted it (not necessarily a data root)
    block_range: tuple[int, int]  # Block range covered by the checkpoint
    data: Any  # Query results from the indexer
    proof: Optional[str] = None  # The provider's GroveDB proof (hex) of its own store, not checked against the checkpoint
    can_reindex: Optional[bool] = None  # Whether data can be re-indexed
    error: Optional[str] = None

    def verify_proof(self) -> str:
        """Deprecated and not supported: raises ``UnsupportedError``.

        ``proof`` is the provider's proof of its own store, which the API
        doesn't check against the checkpoint, and nothing requires the
        checkpoint's ``state_root`` to commit to that store.
        """
        from .errors import UnsupportedError
        raise UnsupportedError(_HISTORICAL_UNSUPPORTED)


_HISTORICAL_UNSUPPORTED = (
    "Verifying a historical query is deprecated and not supported: the API passes the "
    "provider's proof through without checking it against the checkpoint, and nothing "
    "requires the checkpoint's state root to commit to the provider's store. Use "
    "query_historical for the unverified answer."
)


class CheckpointInfo(BaseModel):
    """Information about a checkpoint."""
    checkpoint_id: str
    subgrove_id: str
    state_root: str  # State root hash (hex)
    block_range: tuple[int, int]
    indexer_did: str
    submitted_at: int  # Unix timestamp
    is_trusted: bool


# ============================================================================
# Data Operation Types
# ============================================================================

class StoreDataRequest(BaseModel):
    """Store data request."""
    subgrove_id: str = Field(alias="subgrove_id")
    key: str
    data: Any
    owner_did: str = Field(alias="owner_did")
    signature: bytes
    public_key_id: str = Field(alias="public_key_id")
    nonce: int

    model_config = {"populate_by_name": True}


class FundSubgroveRequest(BaseModel):
    """Fund subgrove request."""
    subgrove_id: str = Field(alias="subgrove_id")
    amount: int
    from_did: str = Field(alias="from_did")
    signature: bytes
    public_key_id: str = Field(alias="public_key_id")
    nonce: int

    model_config = {"populate_by_name": True}


class DeregisterSubgroveRequest(BaseModel):
    """Deregister subgrove request."""
    subgrove_id: str = Field(alias="subgrove_id")
    owner_did: str = Field(alias="owner_did")
    signature: bytes
    public_key_id: str = Field(alias="public_key_id")
    nonce: int

    model_config = {"populate_by_name": True}


# ============================================================================
# Token Types
# ============================================================================

class TokenInfo(BaseModel):
    """Token information."""
    name: str
    symbol: str
    decimals: int
    genesis_supply: int = Field(alias="genesis_supply")
    minted_supply: int = Field(alias="minted_supply")
    max_supply: int = Field(alias="max_supply")
    circulating_supply: int = Field(alias="circulating_supply")

    model_config = {"populate_by_name": True}


class BalanceInfo(BaseModel):
    """Balance information for a DID or subgrove.

    Reads both API shapes: a DID's ``{did, available, staked, locked}`` and a
    subgrove's ``{subgrove_id, balance, total_spent, last_funded}``.
    """
    account: str = Field(validation_alias=AliasChoices("account", "did", "subgrove_id"))
    balance: int = Field(validation_alias=AliasChoices("balance", "available"))
    staked: int = 0
    unbonding: int = Field(0, validation_alias=AliasChoices("unbonding", "locked"))


class TransferRequest(BaseModel):
    """Token transfer request."""
    from_did: str = Field(alias="from_did")
    to_did: str = Field(alias="to_did")
    amount: int
    memo: Optional[str] = None

    model_config = {"populate_by_name": True}


# ============================================================================
# Fee Types
# ============================================================================

class FeeSchedule(BaseModel):
    """Fee schedule for operations."""
    did_registration: int = Field(alias="did_registration")
    subgrove_registration: int = Field(alias="subgrove_registration")
    base_tx_cost: int = Field(alias="base_tx_cost")
    cost_per_byte: int = Field(alias="cost_per_byte")
    query_fee: int = Field(alias="query_fee")
    transfer_fee_percentage: int = Field(alias="transfer_fee_percentage")
    max_tx_size_bytes: int = Field(alias="max_tx_size_bytes")
    max_data_payload_bytes: int = Field(alias="max_data_payload_bytes")

    model_config = {"populate_by_name": True}


# ============================================================================
# Validator Types
# ============================================================================

class ValidatorInfo(BaseModel):
    """Validator information."""
    validator_did: str = Field(alias="validator_did")
    name: Optional[str] = None
    stake_amount: int = Field(alias="stake_amount")
    status: ValidatorStatus
    voting_power: int = Field(alias="voting_power")
    consensus_pubkey: Optional[str] = Field(None, alias="consensus_pubkey")

    model_config = {"populate_by_name": True}


class StakeRequest(BaseModel):
    """Stake request."""
    validator_did: str = Field(alias="validator_did")
    amount: int
    consensus_pubkey: str = Field(alias="consensus_pubkey")

    model_config = {"populate_by_name": True}


class UnstakeRequest(BaseModel):
    """Unstake request."""
    validator_did: str = Field(alias="validator_did")
    amount: int

    model_config = {"populate_by_name": True}


# ============================================================================
# GraphQL / Indexing Types
# ============================================================================

class GraphQLRequest(BaseModel):
    """GraphQL query request."""
    query: str
    variables: Optional[Dict[str, Any]] = None
    include_proof: Optional[bool] = None


class GraphQLError(BaseModel):
    """GraphQL error."""
    message: str
    path: Optional[List[str]] = None


class EthereumAnchor(BaseModel):
    """Ethereum anchor for cross-chain verification."""
    block_number: int = Field(alias="block_number")
    tx_hash: bytes = Field(alias="tx_hash")
    contract: str

    model_config = {"populate_by_name": True, "arbitrary_types_allowed": True}


class MerkleProof(BaseModel):
    """Merkle proof for a single data item."""
    key: str
    value_hash: bytes = Field(alias="value_hash")
    siblings: List[bytes]
    path: str

    model_config = {"populate_by_name": True, "arbitrary_types_allowed": True}


class QueryProof(BaseModel):
    """Cryptographic proof for query results."""
    merkle_proofs: List[MerkleProof] = Field(alias="merkle_proofs")
    state_root: bytes = Field(alias="state_root")
    block_height: int = Field(alias="block_height")
    ethereum_anchor: Optional[EthereumAnchor] = Field(None, alias="ethereum_anchor")

    model_config = {"populate_by_name": True, "arbitrary_types_allowed": True}


class GraphQLResponse(BaseModel):
    """GraphQL query response."""
    data: Optional[Dict[str, Any]] = None
    errors: Optional[List[GraphQLError]] = None
    proof: Optional[QueryProof] = None


class SqlRequest(BaseModel):
    """Request body for SQL queries."""
    query: str
    include_proof: Optional[bool] = None


class SqlResponse(BaseModel):
    """Response from a SQL query."""
    columns: List[str]
    rows: List[List[Any]]
    total: Optional[int] = None
    warnings: List[str] = Field(default_factory=list)
    proof: Optional[QueryProof] = None


# ============================================================================
# Subgrove / Indexer Types
# ============================================================================

class SubgroveInfo(BaseModel):
    """Subgrove information."""
    subgrove_id: str = Field(alias="subgrove_id")
    name: str
    owner_did: str = Field(alias="owner_did")
    status: SubgroveStatus
    latest_block: int = Field(alias="latest_block")
    indexers: List[str] = Field(default_factory=list)
    #: Willow chain height at which the subgrove was registered.
    deployment_block: Optional[int] = None
    #: Chain the subgrove indexes (e.g. ``mainnet``); ``None`` for others.
    chain: Optional[str] = None

    model_config = {"populate_by_name": True}


class SubgroveIndexingStatus(BaseModel):
    """Subgrove indexing status.

    ``GET /subgroves/{id}/status`` answers ``subgrove_id``, ``owner_did``,
    ``deployment_block``, ``total_queries``, ``active_indexers`` (a count),
    and ``status`` ("indexing" or "pending_indexers"). The progress fields
    are ``None`` unless a server reports them.
    """
    subgrove_id: str = Field(alias="subgrove_id")
    status: str
    owner_did: Optional[str] = None
    deployment_block: Optional[int] = None
    total_queries: Optional[int] = None
    active_indexers: Optional[int] = None
    synced_block: Optional[int] = Field(None, alias="synced_block")
    target_block: Optional[int] = Field(None, alias="target_block")
    progress_percentage: Optional[float] = Field(None, alias="progress_percentage")
    last_error: Optional[str] = Field(None, alias="last_error")

    model_config = {"populate_by_name": True}


class IndexerInfo(BaseModel):
    """Indexer information."""
    indexer_did: str = Field(alias="indexer_did")
    subgroves: List[str] = Field(default_factory=list)
    stake_amount: int = Field(alias="stake_amount")
    #: Monitoring / health endpoint (historically also used for queries).
    endpoint: str
    #: Optional dedicated endpoint for client query traffic (GraphQL/SQL).
    #: When ``None``, callers should fall back to ``endpoint``. See
    #: :meth:`effective_query_endpoint`.
    query_endpoint: Optional[str] = Field(default=None, alias="query_endpoint")
    status: IndexerStatus
    performance_score: float = Field(alias="performance_score")
    last_update: int = Field(alias="last_update")

    model_config = {"populate_by_name": True}

    def effective_query_endpoint(self) -> str:
        """URL clients should POST GraphQL/SQL queries to.

        Prefers :attr:`query_endpoint` when set; falls back to
        :attr:`endpoint` otherwise.
        """
        return self.query_endpoint or self.endpoint


# ============================================================================
# Verification Types
# ============================================================================

class VerificationStats(BaseModel):
    """Verification statistics."""
    total_blocks: int = Field(alias="total_blocks")
    verified_blocks: int = Field(alias="verified_blocks")
    unverified_blocks: int = Field(alias="unverified_blocks")
    finalized_blocks: int = Field(alias="finalized_blocks")
    failed_blocks: int = Field(alias="failed_blocks")
    verification_rate: float = Field(alias="verification_rate")

    model_config = {"populate_by_name": True}


class BlockVerificationStatus(BaseModel):
    """Block verification status."""
    block_number: int = Field(alias="block_number")
    status: str
    verified_at: Optional[int] = Field(None, alias="verified_at")
    finalized_at: Optional[int] = Field(None, alias="finalized_at")
    confidence: Optional[float] = None

    model_config = {"populate_by_name": True}


class PathQueryData(BaseModel):
    """Path query data for proof verification."""
    path: List[str]
    query: Any


class VerifyProofRequest(BaseModel):
    """Verify proof request."""
    proof: str
    documents: List[Dict[str, Any]]
    path_query: Optional[PathQueryData] = Field(None, alias="path_query")

    model_config = {"populate_by_name": True}


class VerifyProofResponse(BaseModel):
    """Verify proof response."""
    valid: bool
    root_hash: Optional[str] = Field(None, alias="root_hash")
    error: Optional[str] = None

    model_config = {"populate_by_name": True}


# ============================================================================
# Identity Extensions
# ============================================================================

class Permission(BaseModel):
    """A role a DID holds on a subgrove, as ``GET /did/{did}/permissions`` lists it."""
    did: str
    subgrove_id: str
    role: PermissionRole
    granted_by: str
    granted_at: int


class DidPermissions(BaseModel):
    """DID permissions response."""
    did: str
    owned_subgroves: List[str] = Field(default_factory=list, alias="owned_subgroves")
    admin_subgroves: List[str] = Field(default_factory=list, alias="admin_subgroves")
    write_access: List[str] = Field(default_factory=list, alias="write_access")
    read_access: List[str] = Field(default_factory=list, alias="read_access")
    #: Each grant as the API returns it.
    permissions: List[Permission] = Field(default_factory=list)

    model_config = {"populate_by_name": True}

    @classmethod
    def from_permissions(cls, did: str, permissions: List[Permission]) -> "DidPermissions":
        """Group a DID's grants by role."""
        by_role: Dict[PermissionRole, List[str]] = {role: [] for role in PermissionRole}
        for permission in permissions:
            by_role[permission.role].append(permission.subgrove_id)
        return cls(
            did=did,
            owned_subgroves=by_role[PermissionRole.OWNER],
            admin_subgroves=by_role[PermissionRole.ADMIN],
            write_access=by_role[PermissionRole.WRITER],
            read_access=by_role[PermissionRole.READER],
            permissions=permissions,
        )


# ============================================================================
# Health / Status Types
# ============================================================================

class ComponentHealth(BaseModel):
    """Individual component health (``system`` reports figures, no status)."""
    status: Optional[str] = None
    message: Optional[str] = None

    model_config = {"extra": "allow"}


class HealthStatus(BaseModel):
    """Health check response.

    ``GET /health`` answers ``timestamp`` as RFC 3339 text and its components
    under ``checks``.
    """
    status: str
    timestamp: Union[int, str]
    version: Optional[str] = None
    components: Dict[str, ComponentHealth] = Field(
        default_factory=dict, validation_alias=AliasChoices("components", "checks")
    )


# ============================================================================
# Retry Configuration
# ============================================================================

class RetryConfig(BaseModel):
    """Retry configuration for HTTP requests."""
    max_attempts: int = 3
    initial_delay_ms: int = Field(100, alias="initial_delay_ms")
    max_delay_ms: int = Field(10000, alias="max_delay_ms")
    exponential_base: float = Field(2.0, alias="exponential_base")

    model_config = {"populate_by_name": True}
