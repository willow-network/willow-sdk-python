# Willow Python SDK

Python SDK for Willow — a decentralized data indexing protocol with cryptographic proof verification.

> **Install from source.** Willow's SDKs are not yet published to package registries.
> The commands below install directly from this repository and work today.

## Installation

```bash
pip install git+https://github.com/willow-network/willow-sdk-python.git
```

Or install from source:

```bash
pip install -e .
```

## Transaction submission

Transactions submitted through this SDK go to the API server's `POST /tx/submit`. `api_url` is therefore **required** whenever you submit a tx; `consensus_rpc_url` is only used for read-only RPC queries (status, block, validators) and may be omitted or pointed at the same endpoint.

## Quick Start

```python
import asyncio
from willow import WillowClient, generate_did

async def main():
    async with WillowClient("http://localhost:3031") as client:
        # 1. Generate a DID
        did_info = generate_did()

        # 2. Register the DID
        await client.register_did(did_info["did_document"])

        # 3. Set identity for per-request signing (synchronous, no server session).
        client.set_identity(
            did_info["did"],
            did_info["private_key"],
            did_info["public_key_id"],
        )

        # 4. Store data
        await client.data.store("users", {
            "user_1": {"name": "Alice", "email": "alice@example.com"},
        })

        # 5. Retrieve with automatic proof verification
        user = await client.data.get("users", "user_1")
        print(f"User: {user}")

asyncio.run(main())
```

## Features

- **DID Management** — generate and register DIDs (Ed25519 and secp256k1)
- **Secure by default** — automatic cryptographic proof verification on data reads
- **Full CRUD** — store, get, update, delete with per-request signing
- **Rich query support** — filters, search, sort, pagination
- **Token operations** — balances, fees, token info
- **Validator operations** — list validators, staking info
- **GraphQL indexing** — query blockchain data with proofs
- **File storage** — upload, download, list, delete with chunk-level Merkle verification
- **File encryption** — XChaCha20-Poly1305 (`pynacl`) for private files
- **Type safety** — Pydantic models throughout
- **Async/await** — modern async Python over `httpx`

## API Reference

### Client Initialization

```python
from willow import WillowClient, RetryConfig

# Simple
client = WillowClient("http://localhost:3031")

# With custom timeout
client = WillowClient(api_url="http://localhost:3031", timeout=60.0)

# Builder pattern
client = (
    WillowClient.builder("http://localhost:3031")
    .timeout(60.0)
    .retry_config(RetryConfig(max_attempts=5))
    .build()
)

# Context manager (recommended — auto-closes the HTTP client)
async with WillowClient("http://localhost:3031") as client:
    ...
```

### DID Operations

```python
from willow import generate_did

# Ed25519 (default)
did_info = generate_did()

# secp256k1 (Ethereum-compatible)
did_info = generate_did(algorithm="secp256k1")

await client.register_did(did_info["did_document"])

# did_info keys: did, private_key, public_key, public_key_id, did_document, algorithm
```

### Authentication (per-request signing)

There is no server-side session. Each authenticated request is signed locally with the identity you set via `client.set_identity(...)`. The call is synchronous.

```python
client.set_identity(
    did="did:willow:ed25519:abc123",
    private_key_hex="your_private_key_hex",
    public_key_id="did:willow:ed25519:abc123#key-1",
)

if client.is_authenticated():
    print("Identity is set")

# To "log out", set an empty identity or simply construct a new client.
client.set_identity("", "", "")
```

### Data Operations (Secure by Default)

```python
# Store a whole dict of key -> value pairs in a subgrove
await client.data.store("subgrove_id", {
    "key1": {"field": "value"},
    "key2": {"field": "value2"},
})

# Store a single item
await client.data.store_item("subgrove_id", "key1", {"field": "value"})

# Get a single item (auto-verifies the proof)
item = await client.data.get("subgrove_id", "key1")

# Get without verification (faster; trust assumed)
item = await client.data.get_unverified("subgrove_id", "key1")

# Update
await client.data.update("subgrove_id", "key1", {"field": "updated"})

# Delete
await client.data.delete("subgrove_id", "key1")

# Batch store
await client.data.batch_store("subgrove_id", [
    {"key": "key1", "value": {"field": "value1"}},
    {"key": "key2", "value": {"field": "value2"}},
])
```

### Query Operations

```python
# Filtered query (proof verified)
result = await client.data.query("subgrove_id", {
    "filters": {
        "status": {"$eq": "active"},
        "age": {"$gte": 18},
    },
    "sort": {"field": "created_at", "order": "desc"},
    "limit": 10,
    "offset": 0,
})

# Filter operators: $eq, $ne, $gt, $gte, $lt, $lte, $in, $contains

# Skip verification
result = await client.data.query_unverified("subgrove_id", {"filters": {}})

for doc in result.documents:
    print(doc)
print(f"Total: {result.total}")
```

### Registration Operations

```python
await client.registration.register_subgrove({
    "dataset_id": "my-data",
    "name": "My Data",
    "dataset_path": ["collections"],
    "schema": {
        "version": 1,
        "fields": {
            "name": {"type": "string", "indexed": True},
            "email": {"type": "string", "indexed": True},
            "age": {"type": "number", "indexed": True},
        },
        "indexes": [
            {"name": "by_name", "fields": ["name"], "unique": False, "type": "hash"},
            {"name": "by_age", "fields": ["age"], "unique": False, "type": "range"},
        ],
    },
    "owner_did": did,
    "writers": [did],
    "readers": [],
})

subgroves = await client.registration.list_subgroves()
subgrove = await client.registration.get_subgrove("my-data")

permissions = await client.registration.get_permissions(did)
print(f"Owned: {permissions.owned_subgroves}")
print(f"Write access: {permissions.write_access}")
```

### Token Operations

```python
token_info = await client.token.get_info()
print(f"Token: {token_info.name} ({token_info.symbol})")
print(f"Decimals: {token_info.decimals}")
print(f"Max supply: {token_info.max_supply}")

balance = await client.token.get_balance(did)
print(f"Balance: {balance.balance}")
print(f"Staked: {balance.staked}")
print(f"Unbonding: {balance.unbonding}")

sg_balance = await client.token.get_subgrove_balance("my-subgrove")

fees = await client.token.get_fee_schedule()
print(f"Base TX cost: {fees.base_tx_cost} WILL")
print(f"Cost per byte: {fees.cost_per_byte} WILL")
print(f"Query fee: {fees.query_fee} WILL")
```

### Validator Operations

```python
validators = await client.validators.list()
for v in validators:
    print(f"{v.validator_did}: stake={v.stake_amount}, status={v.status}")

validator = await client.validators.get("did:willow:validator1")
total = await client.validators.get_total_staked()
count = await client.validators.get_active_count()
```

### GraphQL Indexing Operations

```python
response = await client.indexing.graphql_query(
    "my-subgrove",
    """
    query GetUsers($first: Int!) {
        users(first: $first) { id name balance }
    }
    """,
    variables={"first": 10},
)

if response.data:
    for user in response.data["users"]:
        print(user)
if response.errors:
    for error in response.errors:
        print(f"Error: {error.message}")

subgroves = await client.indexing.list_subgroves()
subgrove = await client.indexing.get_subgrove("my-subgrove")
print(f"Status: {subgrove.status}, latest block: {subgrove.latest_block}")

status = await client.indexing.get_indexing_status("my-subgrove")
print(f"Progress: {status.progress_percentage:.1f}%")

indexers = await client.indexing.list_indexers()
stats = await client.indexing.get_verification_stats()
print(f"Verification rate: {stats.verification_rate:.1%}")
```

### Proof Operations

```python
proof_data = await client.proof.get("subgrove_id", "key1")
proof_hex = proof_data["proof"]
value = proof_data["value"]

from willow import ProofVerifier

result = ProofVerifier.verify_item_proof(proof_hex, "key1", value)
if result.error:
    print(f"Verification failed: {result.error}")
else:
    print(f"Root hash: {result.root_hash}")
```

### Health Check

```python
health = await client.health()
print(f"Status: {health.status}")
print(f"Version: {health.version}")
for name, component in health.components.items():
    print(f"  {name}: {component.status}")
```

### Root Hash Verification

```python
verified_root = await client.get_root_hash()        # Consensus-verified
local_root = await client.get_root_hash_local()     # Node's local view

if verified_root == local_root:
    print("Node is in sync with consensus")
```

## Error Handling

```python
from willow import (
    WillowError,
    NetworkError,
    NotAuthenticatedError,
    ValidationError,
    NotFoundError,
    PermissionDeniedError,
    ProofVerificationError,
    RateLimitError,
)

try:
    data = await client.data.get("subgrove", "key")
except NotAuthenticatedError:
    print("Call client.set_identity(...) first")
except NotFoundError as e:
    print(f"Data not found: {e}")
except ProofVerificationError as e:
    print(f"Proof verification failed: {e}")
except PermissionDeniedError as e:
    print(f"Access denied: {e}")
except RateLimitError as e:
    print(f"Rate limited, retry after: {e}s")
except NetworkError as e:
    print(f"Network error: {e}")
except WillowError as e:
    print(f"Willow error: {e}")
```

## Type Definitions

```python
from willow import (
    SignatureAlgorithm,
    ValidatorStatus,
    SubgroveStatus,
    IndexerStatus,
    DidDocument,
    PublicKey,
    QueryRequest,
    QueryResponse,
    SchemaDefinition,
    TokenInfo,
    BalanceInfo,
    FeeSchedule,
    ValidatorInfo,
    SubgroveInfo,
    IndexerInfo,
    GraphQLResponse,
)
```

## Testing

```bash
pip install -e ".[dev]"
pytest
pytest --cov=willow --cov-report=html

mypy src/willow
flake8 src/willow
black src/willow --check
isort src/willow --check
```

## CLI Usage

```bash
# Generate a new DID and save it locally
willow-cli did generate --save

# Or save an existing identity (DID + private key + public key ID)
willow-cli auth login --did <did> --key <private-key-hex> --key-id <key-id>

# Status / clear
willow-cli auth status
willow-cli auth logout

# Data ops (reads the saved identity and signs per-request)
willow-cli data store my-subgrove items.json
willow-cli data get my-subgrove user1
willow-cli data update my-subgrove user1 updated.json
willow-cli data delete my-subgrove user1

# Proof
willow-cli proof get my-subgrove user1
```

## License

MIT
