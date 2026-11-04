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
    did=did_info["did"],
    private_key_hex=did_info["private_key"],
    public_key_id=did_info["public_key_id"],
    algorithm=did_info["algorithm"],  # "Ed25519" (default) or "secp256k1"
)

if client.is_authenticated():
    print("Identity is set")

# To "log out":
client.clear_identity()
```

### Request signing

With an identity set, the client signs these reads it sends to the API with a one-time nonce over the whole request: `GET /data/{subgrove}/{key}`, `GET /proof/{subgrove}/{key}`, and `POST /query`, `/sql`, and `/graphql`. Only this form carries the DID's read rights, on the routes that check them: a Reader permission on a subgrove, or a place on a priced subgrove's free-reader list. The client signs its other authenticated requests (writes, key-grant reads) in the older form described below.

The headers are `X-DID`, `X-Public-Key-ID`, `X-Signature`, `X-Timestamp`, and `X-Nonce`. The signature is over eight lines:

```
willow-request-v2
<DID>
<public key id>
<METHOD>
<path and query, exactly as sent>
<Unix timestamp>
<nonce>
<hex SHA-256 of the body>
```

- The server accepts a timestamp up to 300 s old and 30 s ahead, and each (DID, nonce) once. The client signs every request it sends anew, so a retried call carries a new nonce.
- A nonce is 16 to 128 characters of `A-Z a-z 0-9 - _`. `new_request_nonce()` makes one of 32 hex characters.
- Ed25519 signatures are sent as hex. secp256k1 signatures are over the Keccak-256 of the message and are sent as `0x`-prefixed hex.
- Requests sent to an indexer (`indexer_url`, or one found through `GET /indexers`) are not signed this way.
- A signed request is refused if its DID isn't registered on chain or its key isn't listed in the DID document's `authentication`, on public reads too. The server also refuses nonce-signed requests for about 30 s after it restarts.

To sign a request you send yourself:

```python
headers = sign_request_with_nonce(did, private_key_hex, public_key_id, "POST", "/query/my-subgrove", body_bytes, algorithm)
```

`sign_request(did, private_key_hex, public_key_id, method, path, algorithm)` makes the older `{METHOD}:{PATH}:{TIMESTAMP}` form, over the path without its query string. It proves the DID but carries none of its read rights, and it can be replayed with any body until the timestamp expires.

### Transaction signing (data and file writes)

StoreData, StoreFileManifest, and DeleteFileManifest transactions are signed over a message that binds the transaction's nonce and every field it writes. The kind is the first line; each other line is `Label: value`; lines are joined by `\n` with no trailing newline:

```
StoreData
Subgrove: <subgrove_id>
Key: <key>
Owner: <owner_did>
DataHash: <hex SHA-256 of the transaction's data bytes>
Nonce: <nonce>
```

```
StoreFileManifest
Subgrove: <subgrove_id>
Key: <file_key>
Owner: <owner_did>
Filename: <filename>
ContentType: <content_type>
TotalSize: <total_size>
ContentHash: <hex content_hash>
ChunkCount: <chunk_count>
ChunkSize: <chunk_size>
ChunkMerkleRoot: <hex chunk_merkle_root>
Encryption: none
Nonce: <nonce>
```

```
DeleteFileManifest
Subgrove: <subgrove_id>
Key: <file_key>
Owner: <owner_did>
Nonce: <nonce>
```

- `DataHash` is over the exact bytes sent in `data`: the JSON text's UTF-8 bytes.
- `Encryption` is `none` for a manifest without encryption, else `<key_epoch>:<hex 24-byte nonce>`.
- The nonce in the message is the nonce in the transaction, so a transaction sent under a new nonce needs a new signature.
- A subgrove ID, key, owner DID, filename, or content type holding a line break is refused with `ValueError` before anything is signed.
- Ed25519 signs the message's UTF-8 bytes; secp256k1 signs their Keccak-256.

`ConsensusClient` and `client.files` build these messages; `store_data_message`, `store_file_manifest_message`, and `delete_file_manifest_message` return the exact text for a transaction you sign yourself.

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
print(f"Status: {status.status}, active indexers: {status.active_indexers}")

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
