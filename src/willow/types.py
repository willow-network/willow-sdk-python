"""Type definitions for Willow SDK.

This module contains all data structures used for communicating with
the Willow API, including request/response types, DID documents, and
indexing-related structures.
"""

from typing import Dict, List, Optional, Any, Literal, Union
from pydantic import BaseModel, Field
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
    """Proof response data."""
    proof: str
    value: Optional[Dict[str, Any]] = None


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
        """
        Verify the proof and return computed root hash.

        Returns:
            Computed root hash

        Raises:
            WillowError: If proof is missing or verification fails
        """
        from .proof import verify_query_proof
        if not self.proof:
            from .errors import WillowError
            raise WillowError("Query response does not contain proof data")
        return verify_query_proof(self.proof, self.documents)


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
    state_root: str  # Checkpoint state root for proof verification
    block_range: tuple[int, int]  # Block range covered by the checkpoint
    data: Any  # Query results from the indexer
    proof: Optional[str] = None  # Merkle proof (hex-encoded)
    can_reindex: Optional[bool] = None  # Whether data can be re-indexed
    error: Optional[str] = None

    def verify_proof(self) -> str:
        """
        Verify the proof against the checkpoint state root.

        Returns:
            Computed root hash

        Raises:
            WillowError: If proof verification fails
        """
        from .proof import verify_query_proof
        from .errors import WillowError, ProofVerificationError

        if not self.proof:
            raise WillowError("Historical query response does not contain proof data")

        # Verify proof and get computed root hash
        documents = self.data if isinstance(self.data, list) else [self.data]
        computed_root = verify_query_proof(self.proof, documents)

        # Compare with checkpoint state root
        normalized_computed = computed_root.lower().lstrip("0x")
        normalized_expected = self.state_root.lower().lstrip("0x")

        if normalized_computed != normalized_expected:
            raise ProofVerificationError(
                f"Historical proof verification failed: computed root {computed_root} "
                f"does not match checkpoint state root {self.state_root}"
            )

        return computed_root


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
    """Balance information for a DID or app."""
    account: str
    balance: int
    staked: int = 0
    unbonding: int = 0


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

    model_config = {"populate_by_name": True}


class SubgroveIndexingStatus(BaseModel):
    """Subgrove indexing status with detailed progress."""
    subgrove_id: str = Field(alias="subgrove_id")
    synced_block: int = Field(alias="synced_block")
    target_block: int = Field(alias="target_block")
    progress_percentage: float = Field(alias="progress_percentage")
    status: str
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

class DidPermissions(BaseModel):
    """DID permissions response."""
    did: str
    owned_subgroves: List[str] = Field(default_factory=list, alias="owned_subgroves")
    admin_subgroves: List[str] = Field(default_factory=list, alias="admin_subgroves")
    write_access: List[str] = Field(default_factory=list, alias="write_access")
    read_access: List[str] = Field(default_factory=list, alias="read_access")

    model_config = {"populate_by_name": True}


# ============================================================================
# Health / Status Types
# ============================================================================

class ComponentHealth(BaseModel):
    """Individual component health."""
    status: str
    message: Optional[str] = None


class HealthStatus(BaseModel):
    """Health check response."""
    status: str
    timestamp: int
    version: Optional[str] = None
    components: Dict[str, ComponentHealth] = Field(default_factory=dict)


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
