"""
Willow Python SDK

A Python SDK for interacting with the Willow decentralized data indexing protocol.

Example usage:
    ```python
    from willow import WillowClient, generate_did

    async def main():
        # consensus_rpc_url: the CometBFT RPC of a node you trust, whose
        # headers verified reads are checked against
        async with WillowClient(
            "http://localhost:3031", consensus_rpc_url="http://localhost:26657"
        ) as client:
            # Generate a DID and set it as the client's identity
            did_info = generate_did()
            client.set_identity(
                did_info["did"],
                did_info["private_key"],
                did_info["public_key_id"]
            )

            # Register it (pre-fund the derived DID with the fees first), and
            # wait for it to land: the DID can sign nothing before it does
            registration = await client.register_did(did_info["did_document"])
            await client.wait_until_landed(registration)

            # Register a subgrove it owns and writes to, and wait for it
            subgrove = await client.registration.register_subgrove({
                "dataset_id": "my-data",
                "name": "My Data",
                "schema": {"version": 1, "fields": {"value": {"type": "number"}}},
                "owner_did": did_info["did"],
                "writers": [did_info["did"]],
                "readers": [],
            })
            await client.wait_until_landed(subgrove)

            # Store a JSON object under a key (a StoreData transaction), and
            # wait for it to land: a write returns once CheckTx accepts it
            writes = await client.data.store("my-data", {"key": {"value": 1}})
            await client.wait_until_landed(writes)

            # Read it back, verified against its proof and the consensus
            # node's header (raises ProofVerificationError when it can't be
            # verified; data.get_unverified reads it without verification)
            value = await client.data.get("my-data", "key")

            # Query (the documents are not verified)
            result = await client.data.query_unverified("my-data", {
                "filters": {"value": {"$eq": 1}}
            })
    ```
"""

from .client import (
    WillowClient,
    WillowClientBuilder,
    VerifiedValue,
    DEFAULT_MAX_PROOF_LAG_BLOCKS,
    DataOperations,
    RegistrationOperations,
    ProofOperations,
    TokenOperations,
    ValidatorOperations,
    IndexingOperations,
)
from .indexers import (
    WillowIndexers,
    QuerySource,
    RoutedQueryResult,
    ServedBy,
    ValidatorHasNoDataError,
    NoIndexersReachableError,
)
from .subscriptions import (
    WillowSubscriptions,
    SubscribeOptions,
    SubscribeSource,
    Subscription,
    SubscriptionPayload,
)
from .auth import (
    generate_did,
    derive_did,
    sign_challenge,
    verify_signature,
    detect_algorithm_from_did,
    sign_request,
    sign_request_with_nonce,
    signed_request_message,
    legacy_request_message,
    new_request_nonce,
)
from .signed_messages import (
    store_data_message,
    store_file_manifest_message,
    delete_file_manifest_message,
    register_subgrove_message,
    register_subgrove_unsigned_bincode,
    normalize_register_subgrove,
    grant_subgrove_key_message,
    rotate_subgrove_key_message,
    revoke_subgrove_key_message,
    unregister_storage_node_message,
    register_did_message,
    did_document_body,
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
    ProofHeightOutOfRangeError,
    UnsupportedError,
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
    NonceWindowFullError,
    NotLandedError,
    ResponseTooLargeError,
    parse_api_error,
)
from .nonces import InterruptedWrite
from .types import (
    # Enums
    SignatureAlgorithm,
    ValidatorStatus,
    SubgroveStatus,
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
    # Retention Types
    RetentionWindow,
    # Registration Types
    RegisterDatasetRequest,
    RegisterSubgroveRequest,
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
    FundSubgroveRequest,
    DeregisterSubgroveRequest,
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
    # Subgrove / Indexer Types
    SubgroveInfo,
    SubgroveIndexingStatus,
    IndexerInfo,
    # Verification Types
    VerificationStats,
    BlockVerificationStatus,
    PathQueryData,
    VerifyProofRequest,
    VerifyProofResponse,
    # Identity Extensions
    DidPermissions,
    Permission,
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
    subgrove_data_path,
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
    RegisterSubgroveTx,
    RetentionWindow as ConsensusRetentionWindow,
    TransferTx,
    StoreFileManifestTx,
    DeleteFileManifestTx,
    BroadcastResult,
    TransactionStatus,
    ConsensusError as ConsensusModuleError,
)
from .privacy import (
    PrivacyConfig,
    CommitmentFrequency,
    EncryptedKeyGrant,
    PrivacyOperations,
)
from .files import (
    FileManifest,
    FileOperations as FileOperations,
    encrypt_file,
    decrypt_file,
)

# Client-side completeness verification.
from .completeness import (
    Log,
    CompletenessError,
    CompletenessOperations,
    canonical_event_set_hash,
    commitment_from_anchor_value,
    log_from_indexer_json,
    logs_from_matched_logs_response,
    verify_served_events,
)

# Verifiable Ethereum state reads.
from .eth_state import (
    EthOperations,
    StateVerifyMode,
    VerifiedCall,
    VerifiedStateRead,
    VerifiedStorage,
    verify_mpt_proof,
    verify_state_proof,
)

# Canonical WillowManifest builder + SupportedChain helpers
from .manifest import (
    SUPPORTED_CHAINS,
    MANIFEST_SPEC_VERSION,
    WillowManifest,
    EvmDataSource,
    DataSource,
    ManifestValidationError,
    chain_family,
    evm_chain_id,
    from_evm_chain_id,
    is_supported_chain,
    serialize_manifest,
    parse_manifest,
    validate_manifest,
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
    "VerifiedValue",
    "DEFAULT_MAX_PROOF_LAG_BLOCKS",
    "DataOperations",
    "RegistrationOperations",
    "ProofOperations",
    "TokenOperations",
    "ValidatorOperations",
    "IndexingOperations",
    # Auth
    "generate_did",
    "derive_did",
    "sign_challenge",
    "verify_signature",
    "detect_algorithm_from_did",
    "sign_request",
    "sign_request_with_nonce",
    "signed_request_message",
    "legacy_request_message",
    "new_request_nonce",
    # Signed transaction messages
    "store_data_message",
    "store_file_manifest_message",
    "delete_file_manifest_message",
    "register_subgrove_message",
    "register_subgrove_unsigned_bincode",
    "normalize_register_subgrove",
    "grant_subgrove_key_message",
    "rotate_subgrove_key_message",
    "revoke_subgrove_key_message",
    "unregister_storage_node_message",
    "register_did_message",
    "did_document_body",
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
    "ProofHeightOutOfRangeError",
    "UnsupportedError",
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
    "NonceWindowFullError",
    "NotLandedError",
    "ResponseTooLargeError",
    "parse_api_error",
    "InterruptedWrite",
    # Enums
    "SignatureAlgorithm",
    "ValidatorStatus",
    "SubgroveStatus",
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
    # Retention Types
    "RetentionWindow",
    # Registration Types
    "RegisterDatasetRequest",
    "RegisterSubgroveRequest",
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
    "FundSubgroveRequest",
    "DeregisterSubgroveRequest",
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
    # Subgrove / Indexer Types
    "SubgroveInfo",
    "SubgroveIndexingStatus",
    "IndexerInfo",
    # Verification Types
    "VerificationStats",
    "BlockVerificationStatus",
    "PathQueryData",
    "VerifyProofRequest",
    "VerifyProofResponse",
    # Identity Extensions
    "DidPermissions",
    "Permission",
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
    "subgrove_data_path",
    # Completeness Verification
    "Log",
    "CompletenessError",
    "CompletenessOperations",
    "canonical_event_set_hash",
    "commitment_from_anchor_value",
    "log_from_indexer_json",
    "logs_from_matched_logs_response",
    "verify_served_events",
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
    "RegisterSubgroveTx",
    "TransferTx",
    "StoreFileManifestTx",
    "DeleteFileManifestTx",
    "BroadcastResult",
    "TransactionStatus",
    "ConsensusModuleError",
    # Privacy
    "PrivacyConfig",
    "CommitmentFrequency",
    "EncryptedKeyGrant",
    "PrivacyOperations",
    # File Storage
    "FileManifest",
    "FileOperations",
    "encrypt_file",
    "decrypt_file",
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
