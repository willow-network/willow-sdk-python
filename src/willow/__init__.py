"""
Willow Python SDK

A Python SDK for interacting with the Willow decentralized data indexing protocol.

Example usage:
    ```python
    from willow import WillowClient, generate_did

    async def main():
        async with WillowClient("http://localhost:3031") as client:
            # Generate and register DID
            did_info = generate_did()
            await client.register_did(did_info["did_document"])

            # Authenticate
            await client.authenticate(
                did_info["did"],
                did_info["private_key"],
                did_info["public_key_id"]
            )

            # Store data with automatic proof verification
            await client.data.store("my-app", "my-data", {"key": "value"})

            # Query with automatic proof verification
            result = await client.data.query("my-app", "my-data", {
                "filters": {"key": {"$eq": "value"}}
            })
    ```
"""

from .client import (
    WillowClient,
    WillowClientBuilder,
    DataOperations,
    RegistrationOperations,
    ProofOperations,
    TokenOperations,
    ValidatorOperations,
    IndexingOperations,
)
from .auth import (
    generate_did,
    sign_challenge,
    verify_signature,
    detect_algorithm_from_did,
)
from .errors import (
    WillowError,
    NetworkError,
    HttpError,
    AuthenticationError,
    NotAuthenticatedError,
    SessionExpiredError,
    ValidationError,
    NotFoundError,
    PermissionDeniedError,
    ProofVerificationError,
    LightClientError,
    CryptoError,
    InvalidSignatureError,
    SerializationError,
    ConfigError,
    TimeoutError,
    RateLimitError,
    ConsensusError,
    TransactionError,
    InsufficientFundsError,
    parse_api_error,
)
from .types import (
    # Enums
    SignatureAlgorithm,
    ValidatorStatus,
    SubgraphStatus,
    IndexerStatus,
    PermissionRole,
    IndexType,
    FieldTypeEnum,
    # DID Types
    ServiceEndpoint,
    PublicKey,
    DidDocument,
    DidInfo,
    # Authentication Types
    AuthenticationChallenge,
    AuthenticationResponse,
    Session,
    # Schema Types
    FieldType,
    SchemaField,
    IndexDefinition,
    SchemaDefinition,
    # Registration Types
    RegisterAppRequest,
    RegisterDatasetRequest,
    RegisterSubgroveRequest,
    AppRegistration,
    SubgroveRegistration,
    DatasetRegistration,
    # API Response Types
    ApiResponse,
    ProofData,
    # Query Types
    QueryFilter,
    QuerySearch,
    QuerySort,
    QueryRequest,
    QueryResponse,
    # Data Operation Types
    StoreDataRequest,
    FundAppRequest,
    # Token Types
    TokenInfo,
    BalanceInfo,
    TransferRequest,
    FeeSchedule,
    # Validator Types
    ValidatorInfo,
    StakeRequest,
    UnstakeRequest,
    # GraphQL / Indexing Types
    GraphQLRequest,
    GraphQLError,
    GraphQLResponse,
    EthereumAnchor,
    MerkleProof,
    QueryProof,
    # Subgraph / Indexer Types
    SubgraphInfo,
    SubgraphIndexingStatus,
    IndexerInfo,
    # Verification Types
    VerificationStats,
    BlockVerificationStatus,
    PathQueryData,
    VerifyProofRequest,
    VerifyProofResponse,
    # Identity Extensions
    DidPermissions,
    # Health / Status Types
    ComponentHealth,
    HealthStatus,
    # Configuration Types
    RetryConfig,
)
from .utils import (
    generate_id,
    sleep,
    retry,
    validate_did,
    validate_hex_string,
    RateLimiter,
)
from .proof import (
    ProofVerifier,
    ProofVerificationResult,
    ProofVerificationOptions,
    GroveDBProofVerifier,
    configure_proof_verification,
    verify_query_proof,
    verify_query_response,
    verify_item_proof,
    extract_root_hash_from_proof,
    verify_proof_quick,
    verify_proof_with_expected_root,
)
# GroveDB module for low-level proof verification
from . import grovedb
from .light_client import (
    LightClient,
    LightClientConfig,
    LightClientConfigBuilder,
    LightBlock,
    Header,
    TrustedHeader,
    QueryProof as LightClientQueryProof,
    VerificationResult,
    LightClientError as LightClientModuleError,
)
from .consensus import (
    ConsensusClient,
    ConsensusConfig,
    ConsensusConfigBuilder,
    RegisterDidTx,
    RegisterAppTx,
    RegisterSubgroveTx,
    TransferTx,
    BroadcastResult,
    TransactionStatus,
    ConsensusError as ConsensusModuleError,
)

__version__ = "0.2.0"

__all__ = [
    # Client
    "WillowClient",
    "WillowClientBuilder",
    "DataOperations",
    "RegistrationOperations",
    "ProofOperations",
    "TokenOperations",
    "ValidatorOperations",
    "IndexingOperations",
    # Auth
    "generate_did",
    "sign_challenge",
    "verify_signature",
    "detect_algorithm_from_did",
    # Errors
    "WillowError",
    "NetworkError",
    "HttpError",
    "AuthenticationError",
    "NotAuthenticatedError",
    "SessionExpiredError",
    "ValidationError",
    "NotFoundError",
    "PermissionDeniedError",
    "ProofVerificationError",
    "LightClientError",
    "CryptoError",
    "InvalidSignatureError",
    "SerializationError",
    "ConfigError",
    "TimeoutError",
    "RateLimitError",
    "ConsensusError",
    "TransactionError",
    "InsufficientFundsError",
    "parse_api_error",
    # Enums
    "SignatureAlgorithm",
    "ValidatorStatus",
    "SubgraphStatus",
    "IndexerStatus",
    "PermissionRole",
    "IndexType",
    "FieldTypeEnum",
    # DID Types
    "ServiceEndpoint",
    "PublicKey",
    "DidDocument",
    "DidInfo",
    # Authentication Types
    "AuthenticationChallenge",
    "AuthenticationResponse",
    "Session",
    # Schema Types
    "FieldType",
    "SchemaField",
    "IndexDefinition",
    "SchemaDefinition",
    # Registration Types
    "RegisterAppRequest",
    "RegisterDatasetRequest",
    "RegisterSubgroveRequest",
    "AppRegistration",
    "SubgroveRegistration",
    "DatasetRegistration",
    # API Response Types
    "ApiResponse",
    "ProofData",
    # Query Types
    "QueryFilter",
    "QuerySearch",
    "QuerySort",
    "QueryRequest",
    "QueryResponse",
    # Data Operation Types
    "StoreDataRequest",
    "FundAppRequest",
    # Token Types
    "TokenInfo",
    "BalanceInfo",
    "TransferRequest",
    "FeeSchedule",
    # Validator Types
    "ValidatorInfo",
    "StakeRequest",
    "UnstakeRequest",
    # GraphQL / Indexing Types
    "GraphQLRequest",
    "GraphQLError",
    "GraphQLResponse",
    "EthereumAnchor",
    "MerkleProof",
    "QueryProof",
    # Subgraph / Indexer Types
    "SubgraphInfo",
    "SubgraphIndexingStatus",
    "IndexerInfo",
    # Verification Types
    "VerificationStats",
    "BlockVerificationStatus",
    "PathQueryData",
    "VerifyProofRequest",
    "VerifyProofResponse",
    # Identity Extensions
    "DidPermissions",
    # Health / Status Types
    "ComponentHealth",
    "HealthStatus",
    # Configuration Types
    "RetryConfig",
    # Utilities
    "generate_id",
    "sleep",
    "retry",
    "validate_did",
    "validate_hex_string",
    "RateLimiter",
    # Proof Verification
    "ProofVerifier",
    "ProofVerificationResult",
    "ProofVerificationOptions",
    "GroveDBProofVerifier",
    "configure_proof_verification",
    "verify_query_proof",
    "verify_query_response",
    "verify_item_proof",
    "extract_root_hash_from_proof",
    "verify_proof_quick",
    "verify_proof_with_expected_root",
    # GroveDB module
    "grovedb",
    # Light Client
    "LightClient",
    "LightClientConfig",
    "LightClientConfigBuilder",
    "LightBlock",
    "Header",
    "TrustedHeader",
    "LightClientQueryProof",
    "VerificationResult",
    "LightClientModuleError",
    # Consensus
    "ConsensusClient",
    "ConsensusConfig",
    "ConsensusConfigBuilder",
    "RegisterDidTx",
    "RegisterAppTx",
    "RegisterSubgroveTx",
    "TransferTx",
    "BroadcastResult",
    "TransactionStatus",
    "ConsensusModuleError",
]
