# Willow Python SDK

Python SDK for interacting with Willow - a decentralized data indexing protocol with cryptographic proof verification.

## Installation

```bash
pip install willow-sdk
```

Or install from source:

```bash
cd sdk/willow-python
pip install -e .
```

## Transaction submission

Transactions submitted through this SDK go to the API server's
`POST /tx/submit` endpoint. The server accepts the JSON-encoded
transaction, bincode-encodes it (the chain's on-the-wire format), and
forwards to CometBFT's `broadcast_tx_sync`. `api_url` is therefore
**required** whenever you submit a tx; `consensus_rpc_url` is only
used for read-only RPC queries (status, block, validators) and may be
omitted or pointed at the same endpoint.

## Quick Start

```python
import asyncio
from willow import WillowClient, generate_did

async def main():
    # Initialize client with context manager
    async with WillowClient("http://localhost:3031") as client:
        # Generate a new DID
        did_info = generate_did()

        # Register DID
        await client.register_did(did_info["did_document"])

        # Authenticate
        session = await client.authenticate(
            did_info["did"],
            did_info["private_key"],
            did_info["public_key_id"]
        )

        # Store data (automatically verified on read)
        await client.data.store("users", {
            "user_1": {"name": "Alice", "email": "alice@example.com"}
        })

        # Retrieve data with automatic proof verification
        user = await client.data.get("users", "user_1")
        print(f"User: {user}")

asyncio.run(main())
```

## Features

- **DID Management**: Generate and register decentralized identifiers (Ed25519 and secp256k1)
- **Secure by Default**: Automatic cryptographic proof verification on all data reads
- **Full CRUD Operations**: Store, get, update, delete with authentication
- **Rich Query Support**: Filter, search, sort with proof verification
- **Token Operations**: Query balances, fees, and token info
- **Validator Operations**: List validators, check staking info
- **GraphQL Indexing**: Query blockchain data with proofs
- **File Storage**: Upload, download, list, and delete files with chunk Merkle verification
- **File Encryption**: XChaCha20-Poly1305 encryption/decryption for private files
- **Type Safety**: Full type hints and Pydantic models
- **Async/Await**: Modern async Python with httpx
- **Builder Pattern**: Fluent API for client configuration

## API Reference

### Client Initialization

```python
from willow import WillowClient, WillowClientBuilder, RetryConfig

# Simple initialization
client = WillowClient("http://localhost:3031")

# With custom timeout
client = WillowClient(
    api_url="http://localhost:3031",
    timeout=60.0
)

# Using builder pattern
client = (
    WillowClient.builder("http://localhost:3031")
    .timeout(60.0)
    .retry_config(RetryConfig(max_attempts=5))
    .build()
)

# As context manager (recommended)
async with WillowClient("http://localhost:3031") as client:
    # Client will be automatically closed
    pass
```

### DID Operations

```python
from willow import generate_did

# Generate new DID with Ed25519 (recommended)
did_info = generate_did()

# Generate with secp256k1 (Ethereum compatible)
did_info = generate_did(algorithm="secp256k1")

# Register DID
await client.register_did(did_info["did_document"])

# did_info contains:
# - did: str - The DID string
# - private_key: str - Hex-encoded private key
# - public_key: str - Hex-encoded public key
# - public_key_id: str - Key identifier for authentication
# - did_document: DidDocument - The DID document
# - algorithm: str - The signature algorithm used
```

### Authentication

```python
# Authenticate with private key
session = await client.authenticate(
    did="did:willow:ed25519:abc123",
    private_key_hex="your_private_key_hex",
    public_key_id="did:willow:ed25519:abc123#key-1"
)

# Check authentication status
if client.is_authenticated():
    print(f"Authenticated as: {client.get_session().did}")

# Logout
client.clear_session()
```

### Data Operations (Secure by Default)

```python
# Store data
await client.data.store("subgrove_id", {
    "key1": {"field": "value"},
    "key2": {"field": "value2"}
})

# Store single item
await client.data.store_item("subgrove_id", "key1", {"field": "value"})

# Get single item (with automatic proof verification)
item = await client.data.get("subgrove_id", "key1")

# Get without verification (for performance-critical scenarios)
item = await client.data.get_unverified("subgrove_id", "key1")

# Update item
await client.data.update("subgrove_id", "key1", {"field": "updated"})

# Delete item
await client.data.delete("subgrove_id", "key1")

# Batch store
await client.data.batch_store("subgrove_id", [
    {"key": "key1", "value": {"field": "value1"}},
    {"key": "key2", "value": {"field": "value2"}},
])
```

### Query Operations

```python
# Query with filters (automatically verified)
result = await client.data.query("subgrove_id", {
    "filters": {
        "status": {"$eq": "active"},
        "age": {"$gte": 18}
    },
    "sort": {"field": "created_at", "order": "desc"},
    "limit": 10,
    "offset": 0
})

# Available filter operators:
# $eq - Equal
# $ne - Not equal
# $gt - Greater than
# $gte - Greater than or equal
# $lt - Less than
# $lte - Less than or equal
# $in - In array
# $contains - Contains value (for arrays)
# $startsWith - String prefix matching

# Query without verification (for performance)
result = await client.data.query_unverified("subgrove_id", {...})

# Access results
for doc in result.documents:
    print(doc)
print(f"Total: {result.total}")
```

### Registration Operations

```python

# Register subgrove/dataset
await client.registration.register_subgrove({
    "subgrove_id": "my-data",

    "name": "My Data",
    "schema": {
        "version": 1,
        "fields": {
            "name": {"type": "string", "indexed": True},
            "email": {"type": "string", "indexed": True},
            "age": {"type": "number", "indexed": True}
        },
        "indexes": [
            {"name": "by_name", "fields": ["name"], "type": "hash"},
            {"name": "by_age", "fields": ["age"], "type": "range"}
        ]
    },
    "owner_did": did,
    "writers": [did],
    "readers": []
})

# List subgroves
subgroves = await client.registration.list_subgroves()

# Get specific subgrove
subgrove = await client.registration.get_subgrove("my-data")

# Get DID permissions
permissions = await client.registration.get_permissions(did)
print(f"Owned subgroves: {permissions.owned_subgroves}")
print(f"Write access: {permissions.write_access}")
```

### Token Operations

```python
# Get token info
token_info = await client.token.get_info()
print(f"Token: {token_info.name} ({token_info.symbol})")
print(f"Decimals: {token_info.decimals}")
print(f"Max supply: {token_info.max_supply}")

# Get balance for a DID
balance = await client.token.get_balance(did)
print(f"Balance: {balance.balance}")
print(f"Staked: {balance.staked}")

# Get subgrove balance

# Get fee schedule
fees = await client.token.get_fee_schedule()
print(f"Base TX cost: {fees.base_tx_cost} wei")
print(f"Cost per byte: {fees.cost_per_byte} wei")
print(f"Query fee: {fees.query_fee} wei")
```

### Validator Operations

```python
# List all validators
validators = await client.validators.list()
for v in validators:
    print(f"{v.validator_did}: {v.stake_amount} staked, status: {v.status}")

# Get specific validator
validator = await client.validators.get("did:willow:validator123")

# Get total staked
total = await client.validators.get_total_staked()

# Get active validator count
count = await client.validators.get_active_count()
```

### GraphQL Indexing Operations

```python
# Execute GraphQL query against a subgrove
response = await client.indexing.graphql_query(
    "my-subgrove",
    """
    query GetUsers($first: Int!) {
        users(first: $first) {
            id
            name
            balance
        }
    }
    """,
    variables={"first": 10}
)

if response.data:
    for user in response.data["users"]:
        print(user)

if response.errors:
    for error in response.errors:
        print(f"Error: {error.message}")

# List subgroves
subgroves = await client.indexing.list_subgroves()

# Get subgrove info
subgrove = await client.indexing.get_subgrove("my-subgrove")
print(f"Status: {subgrove.status}")
print(f"Latest block: {subgrove.latest_block}")

# Get indexing status
status = await client.indexing.get_indexing_status("my-subgrove")
print(f"Progress: {status.progress_percentage}%")

# List indexers
indexers = await client.indexing.list_indexers()

# Get verification stats
stats = await client.indexing.get_verification_stats()
print(f"Verification rate: {stats.verification_rate * 100}%")
```

### Proof Operations

```python
# Get Merkle proof (no auth required)
proof_data = await client.proof.get("subgrove_id", "key1")
proof_hex = proof_data["proof"]
value = proof_data["value"]

# Verify proof manually
from willow import ProofVerifier

result = ProofVerifier.verify_item_proof(proof_hex, "key1", value)
if result.error:
    print(f"Verification failed: {result.error}")
else:
    print(f"Root hash: {result.root_hash}")
```

### Health Check

```python
# Check API health
health = await client.health()
print(f"Status: {health.status}")
print(f"Version: {health.version}")
for name, component in health.components.items():
    print(f"  {name}: {component.status}")
```

### Root Hash Verification

```python
# Get verified root hash from blockchain consensus
verified_root = await client.get_root_hash()

# Get local root hash (may not yet be confirmed)
local_root = await client.get_root_hash_local()

# Compare to check sync status
if verified_root == local_root:
    print("Node is in sync with consensus")
```

## Error Handling

```python
from willow import (
    WillowError,
    NetworkError,
    AuthenticationError,
    NotAuthenticatedError,
    SessionExpiredError,
    ValidationError,
    NotFoundError,
    PermissionDeniedError,
    ProofVerificationError,
    RateLimitError,
)

try:
    data = await client.data.get("subgrove", "dataset", "key")
except NotAuthenticatedError:
    print("Please authenticate first")
except SessionExpiredError:
    print("Session expired, re-authenticating...")
    await client.authenticate(...)
except NotFoundError as e:
    print(f"Data not found: {e}")
except ProofVerificationError as e:
    print(f"Proof verification failed: {e}")
except PermissionDeniedError as e:
    print(f"Access denied: {e}")
except RateLimitError as e:
    print(f"Rate limited, retry after: {e.retry_after}s")
except NetworkError as e:
    print(f"Network error: {e}")
except WillowError as e:
    print(f"Willow error: {e}")
```

## Type Definitions

The SDK provides comprehensive type definitions via Pydantic models:

```python
from willow import (
    # Enums
    SignatureAlgorithm,
    ValidatorStatus,
    SubgroveStatus,
    IndexerStatus,

    # DID Types
    DidDocument,
    PublicKey,
    Session,

    # Data Types
    QueryRequest,
    QueryResponse,
    SchemaDefinition,

    # Token Types
    TokenInfo,
    BalanceInfo,
    FeeSchedule,

    # Validator Types
    ValidatorInfo,

    # Indexing Types
    SubgroveInfo,
    IndexerInfo,
    GraphQLResponse,
)
```

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=willow --cov-report=html

# Type checking
mypy src/willow

# Linting
flake8 src/willow
black src/willow --check
isort src/willow --check
```

## CLI Usage

The SDK includes a CLI for quick operations:

```bash
# Generate a new DID
willow-cli did generate

# Register and authenticate
willow-cli auth login --did <your-did> --key <private-key>

# Store data
willow-cli data store my-subgrove users '{"user1": {"name": "Alice"}}'

# Get data
willow-cli data get my-subgrove users user1

# Get proof
willow-cli proof get my-subgrove users user1
```

## License

MIT
