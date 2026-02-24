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

            # Set identity for per-request signing
            client.set_identity(
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
    # Historical Query Types
    HistoricalQueryRequest,
    HistoricalQueryResponse,
    CheckpointInfo,
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
from .computed_fields import (
    ComputedFieldDefinition,
    ComputedFieldSet,
    ComputedFieldRegistry,
    ComputeFunction,
    apply_computed_fields,
    apply_computed_fields_to_response,
    UNISWAP_V2_PAIR_FIELDS,
    UNISWAP_V2_TOKEN_FIELDS,
    UNISWAP_V2_AGGREGATION_FIELDS,
    GENERIC_AMM_PAIR_FIELDS,
    LENDING_PROTOCOL_FIELDS,
    LP_SHARE_FIELDS,
    global_computed_field_registry,
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

# Pre-funded test account for local devnet development.
# This account is pre-registered and funded in the devnet genesis.
# Use it for SDK testing and development - DO NOT use in production!
#
# Example usage:
#     from willow import WillowClient, DEVNET_TEST_ACCOUNT
#
#     async with WillowClient("http://localhost:3031") as client:
#         client.set_identity(
#             DEVNET_TEST_ACCOUNT["did"],
#             DEVNET_TEST_ACCOUNT["private_key"],
#             DEVNET_TEST_ACCOUNT["public_key_id"]
#         )
DEVNET_TEST_ACCOUNT = {
    "did": "did:willow:devnet-test",
    "private_key": "b5ecc03536f5e039e3c5bc46ad178d7faf80cee5f063016a4f4084e163409b3c",
    "public_key": "c153874d3d284a11e3cb12b524e1a9cc32fef966d56b903c79688a95d5193c8f",
    "public_key_id": "did:willow:devnet-test#key-1",
}

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
    # Test Account
    "DEVNET_TEST_ACCOUNT",
    # Computed Fields
    "ComputedFieldDefinition",
    "ComputedFieldSet",
    "ComputedFieldRegistry",
    "ComputeFunction",
    "apply_computed_fields",
    "apply_computed_fields_to_response",
    "UNISWAP_V2_PAIR_FIELDS",
    "UNISWAP_V2_TOKEN_FIELDS",
    "UNISWAP_V2_AGGREGATION_FIELDS",
    "GENERIC_AMM_PAIR_FIELDS",
    "LENDING_PROTOCOL_FIELDS",
    "LP_SHARE_FIELDS",
    "global_computed_field_registry",
]
