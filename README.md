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

Every write is a signed transaction submitted to the API server's `POST /tx/submit`: DID registration, subgrove registration, data and file writes, and key grants. The API accepts no writes over its REST routes. `api_url` is therefore **required** whenever you submit a tx; `consensus_rpc_url` is only used for read-only RPC queries (status, block, validators) and may be omitted or pointed at the same endpoint.

## Quick Start

```python
import asyncio
from willow import WillowClient, generate_did

async def main():
    async with WillowClient("http://localhost:3031") as client:
        # 1. Generate a DID
        did_info = generate_did()

        # 2. Set it as the client's identity (synchronous, no server session).
        #    It signs every transaction and authenticated request.
        client.set_identity(
            did_info["did"],
            did_info["private_key"],
            did_info["public_key_id"],
        )

        # 3. Register the DID (pre-fund it with the registration fee first),
        #    and wait for it to land: the DID can sign nothing before it does
        registration = await client.register_did(did_info["did_document"])
        await client.wait_until_landed(registration)

        # 4. Store data: one StoreData transaction per key
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
- **Signed transactions** — DID and subgrove registration, data and file writes, and key grants, each signed over every field and its nonce
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

# With a validator's CometBFT RPC, to read which nonces are used (see Nonces)
client = WillowClient("http://localhost:3031", consensus_rpc_url="http://localhost:26657")

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

# did_info keys: did, private_key, public_key, public_key_id, did_document, algorithm
```

A DID's id is derived from its key, so it can be funded before it exists: transfer the registration fee to `did_info["did"]` from a funded account, then register it. `register_did` submits a RegisterDid transaction signed with the document's own key, the identity set on the client (or pass `private_key_hex`):

```python
client.set_identity(did_info["did"], did_info["private_key"], did_info["public_key_id"], did_info["algorithm"])
result = await client.register_did(did_info["did_document"])  # {"tx_hash", "code", "log", "did", "nonce"}
await client.wait_until_landed(result)
```

It signs in the algorithm the document's key type names (`Ed25519VerificationKey2018` or `EcdsaSecp256k1VerificationKey2019`) unless you pass `algorithm`. It returns once CheckTx accepts the transaction; the DID can sign other transactions and requests only after it lands.

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

With an identity set, the client signs these reads it sends to the API with a one-time nonce over the whole request: `GET /data/{subgrove}/{key}`, `GET /proof/{subgrove}/{key}`, and `POST /query`, `/sql`, and `/graphql`. Only this form carries the DID's read rights, on the routes that check them: a Reader permission on a subgrove, or a place on a priced subgrove's free-reader list. The client signs its key-grant reads in the older form described below. Writes are transactions, signed as described under Transaction signing.

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

### Transaction signing

StoreData, StoreFileManifest, DeleteFileManifest, RegisterSubgrove, GrantSubgroveKey, RotateSubgroveKey, and UnregisterStorageNode transactions are signed over a message that binds the transaction's nonce and every field it writes. The kind is the first line; each other line is `Label: value`; lines are joined by `\n` (the byte 0x0A) with no trailing newline, and the message is UTF-8. Text fields go in verbatim, with no escaping or normalization; numbers are unsigned decimal; hex is lowercase.

Data and file writes:

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

- `DataHash` is over the exact bytes sent in `data`: the JSON text's UTF-8 bytes. `ConsensusClient.store_data` sends `json.dumps(data, separators=(",", ":"), sort_keys=True)`, which escapes non-ASCII characters.
- `Encryption` is `none` for a manifest without encryption, else `<key_epoch>:<hex 24-byte nonce>`.
- The nonce in the message is the nonce in the transaction, so a transaction sent under a new nonce needs a new signature.
- A write that lands in a block and is refused there (for example, data not found or no permission) after its signature and nonce verify still spends its nonce. To retry, sign again under the next free nonce. A write refused for its signature or nonce spends nothing.
- A subgrove ID, key, owner DID, filename, or content type holding a line break (the byte 0x0A) is refused with `ValueError` before anything is signed.
- Ed25519 signs the message's UTF-8 bytes; secp256k1 signs their Keccak-256.

Registrations, key grants, and storage-node removals:

```
RegisterSubgrove
Subgrove: <subgrove_id>
Owner: <owner_did>
Config: <hex SHA-256 of the transaction's bincode with an empty signature>
Nonce: <nonce>
```

```
GrantSubgroveKey
Subgrove: <subgrove_id>
Sender: <sender_did>
Grantee: <grantee_did>
GranteeKey: <grantee_public_key_id>
KeyEpoch: <key_epoch>
EphemeralKey: <hex ephemeral_public_key>
EncryptedKey: <hex encrypted_key>
GrantedBy: <granted_by>
GrantedAt: <granted_at>
Nonce: <nonce>
```

```
RotateSubgroveKey
Subgrove: <subgrove_id>
Sender: <sender_did>
NewEpoch: <new_epoch>
Grants: <number of new_grants>
<each grant's seven lines, Grantee to GrantedAt, in order>
Nonce: <nonce>
```

```
UnregisterStorageNode
Node: <node_did>
Nonce: <nonce>
```

- RegisterSubgrove's `Config` binds every field of the transaction. It is the SHA-256 of `bincode::serialize` (bincode 1.x default: fixed-width little-endian integers, u64 lengths, u32 enum variant indexes, a one-byte `Option` tag) of the `RegisterSubgroveTx` struct with `signature` empty and every other field as the node decodes the JSON sent. The SDK sends every field explicitly (`normalize_register_subgrove`) and hashes exactly that (`register_subgrove_unsigned_bincode`), for every mode: DataStorage, FileStorage, and BlockchainIndexing.
- RevokeSubgroveKey signs `RevokeSubgroveKey:<subgrove_id>:<revokee_did>:<sender_did>:<nonce>`, which binds every field it carries.
- RegisterDid signs the node's compact JSON of the DID document, its fields in the node's order (`id`, `public_keys`, `authentication`, `service`, `created`, `updated`, `proof`; each key `id`, `type`, `controller`, `public_key_base58`, `public_key_hex`), always under nonce 1. The SDK sends that same document (`did_document_body`).
- A subgrove ID, owner, sender, grantee, grantee key ID, granter, or node DID holding a line break is refused with `ValueError` before anything is signed.
- The node refuses a DataStorage or FileStorage registration whose subgrove ID is not 1 to 64 ASCII letters, digits, `-`, or `_` starting with a letter or digit, or whose schema declares indexes ("Schema indexes are not supported"), and refuses one in its block whose schema doesn't parse as its `SchemaDefinition` (`version` a u32, `fields` mapping each name to `"string"`, `"number"`, `"boolean"`, `"array"`, `"object"`, or `"bytes"`, `required_fields` a list of names). `register_subgrove_message`, and every flow that signs a registration, refuses all three with `ValueError` before anything is signed.

`ConsensusClient`, `client.files`, `client.data`, `client.registration`, `client.privacy`, and `client.register_did` build these messages. `store_data_message`, `store_file_manifest_message`, `delete_file_manifest_message`, `register_subgrove_message`, `grant_subgrove_key_message`, `rotate_subgrove_key_message`, `revoke_subgrove_key_message`, `unregister_storage_node_message`, and `register_did_message` return the exact text for a transaction you sign yourself.

### Nonces

The node accepts a transaction under a nonce among the 24 above the account's nonce (its base, `GET /account/{did}/nonce`) that is not used yet. The base advances only over used nonces with no gap below them, so a nonce taken and never used blocks the window until something uses it. `WillowClient` and `ConsensusClient` hand out nonces per signing DID:

- Each write takes the lowest nonce in the window the client hasn't handed out, so writes sent before earlier ones land, or concurrently, each get their own.
- A write CheckTx refuses gives its nonce back, leaving no gap, unless the refusal is the node's own refusal of that nonce: held by a pending transaction, already used, or at or below the base. When it is already used, no transaction under it can run, so the write is signed again under a fresh nonce.
- A nonce handed out more than 120 s ago whose write hasn't landed is free again.
- While all 24 are taken, the next write waits for earlier ones to land, and raises `NonceWindowFullError` if none does within 60 s. `client.data.store` with more than 24 keys sends the rest as earlier ones land.
- RegisterDid always signs nonce 1.

Nonces are tracked per client object, so send one identity's writes through one client. `client.files` signs under the nonce you pass in `signing["nonce"]`, which is required.

#### When a write fails

An error a write raises after choosing its nonce carries the `did` and `nonce` it was signed under. What to do depends on whether the transaction may have reached the node:

- It never left: a `NetworkError` whose `transaction` is `None` (the connection was refused, or timed out before connecting). Its nonce is free again. Call the write again.
- It may have reached the node: a `NetworkError` after connecting (a read timeout, a dropped connection), or a `TransactionError` for a gateway error with no CheckTx answer. Its `transaction` holds the signed transaction as sent, and its nonce stays taken. Send the same transaction again under the same nonce with `await client.resubmit(error)`: whichever copy lands first spends the nonce and the other is refused, so the write runs at most once. Don't call the write again: under another nonce, both copies could run.
- `resubmit` returns `{tx_hash, code, log, did, nonce}` once CheckTx accepts the copy. If the node already holds an identical copy ("tx already exists in cache"), that counts as accepted, with `code` 0 and no `tx_hash`. A `TransactionError` saying the nonce is already used, or at or below the base, means a transaction under it landed: the earlier copy. CheckTx checks some rules (a subgrove that exists, a funded balance) before the nonce, so a refusal of a copy can also follow from the earlier copy having landed: read what the write wrote to know whether it took effect.
- If `resubmit` comes after the 120 s lease and this client has handed the nonce to another write, it raises `WillowError` and sends nothing. Read what the write wrote to learn whether it took effect.
- A write CheckTx refused (a `TransactionError` whose `transaction` is `None`) never ran: fix what the refusal says and call the write again.

```python
from willow import NetworkError, TransactionError

try:
    result = await client.data.store_item("my-data", "k", {"v": 1})
except (NetworkError, TransactionError) as error:
    if error.transaction is None:
        raise  # never left, or refused at CheckTx: fix it and call the write again
    result = await client.resubmit(error)
await client.wait_until_landed(result)
```

`ConsensusClient` does the same: a `ConsensusError` raised after every retry failed in transit, or a `BroadcastResult` for a gateway error, carries `did`, `nonce`, and, when it may have reached the node, `transaction`; `await consensus.resubmit(error_or_result)` returns a `BroadcastResult`. Its own retries send the same bytes, and a retry refused because its nonce is used raises `ConsensusError` (the first attempt may have landed) instead of signing the write again under another nonce. Each `BroadcastResult` carries `http_status`, `did`, and `nonce`.

#### Waiting for writes to land

Writes in flight may land in any order, and a write returns once CheckTx accepts it. Wait for a write to land before sending one that depends on it: anything the DID signs after its registration, a store into a subgrove just registered, a delete of a file being uploaded. Each write returns `{tx_hash, code, log, did, nonce}`; `wait_until_landed` takes those, lists of them, or a write's error, and returns once each nonce is used:

```python
registration = await client.register_did(did_info["did_document"])
await client.wait_until_landed(registration)

results = await client.data.store("my-data", {"a": {"n": 1}, "b": {"n": 2}})
await client.wait_until_landed(results, timeout=60.0)  # NotLandedError after 60 s
```

A nonce counts as used once it is at or below the account's base, or the node reports it used above the base. With `consensus_rpc_url`, the client reads which nonces above the base are used (the ABCI query `/store/account_nonce_state/{did}`), so each write counts as landed when its own nonce is used. Without it, the client reads only the base (and the nonces CheckTx has refused as already used). The base advances only over used nonces with no gap below them, so a write counts as landed only once every lower nonce of its DID is used too. A nonce no transaction uses (one given back after CheckTx refused its write, or one whose write failed in transit and was never resubmitted) then holds back every write above it, until the client hands that nonce to a later write and that write lands.

A write refused in its block uses its nonce too, so read what it wrote to know it took effect. A RegisterDid uses its nonce only when it succeeds.

### Data Operations (Secure by Default)

```python
# Store a whole dict of key -> JSON object in a subgrove: one StoreData
# transaction per key, each under its own nonce
await client.data.store("subgrove_id", {
    "key1": {"field": "value"},
    "key2": {"field": "value2"},
})

# Store a single item
await client.data.store_item("subgrove_id", "key1", {"field": "value"})

# Batch store
await client.data.batch_store("subgrove_id", [
    {"key": "key3", "value": {"field": "value3"}},
    {"key": "key4", "value": {"field": "value4"}},
])

# Get a single item (auto-verifies the proof)
item = await client.data.get("subgrove_id", "key1")

# Get without verification (faster; trust assumed)
item = await client.data.get_unverified("subgrove_id", "key1")
```

- Each value must be a JSON object (a `dict`); anything else raises `TypeError` before anything is sent. The data sent is `json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False)`: a value holding NaN or an infinity raises `ValueError` before anything is sent.
- Each store returns the `{tx_hash, code, log, did, nonce}` of its transaction, or raises `TransactionError` if CheckTx refuses it. StoreData writes a new key: it is refused in its block for a key that already exists.
- `store` and `batch_store` send their keys one at a time. If one fails (`TransactionError`, `NonceWindowFullError`, or `NetworkError`), the error's `submitted` holds the results of the keys sent before it and `failed_key` the key that failed; the keys after it are not sent.
- `client.data.update` and `client.data.delete` raise `WillowError`: the node changes and deletes data only through UpdateData and DeleteData transactions, which this SDK does not build.

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

`register_subgrove` submits a DataStorage RegisterSubgrove transaction signed by the identity set on the client, which must be `owner_did`. The schema is sent as the node's schema JSON: each field's type, with required fields listed in `required_fields`. `dataset_path` has no on-chain counterpart and is not sent. `ConsensusClient.register_subgrove` takes every mode and field of the transaction.

The node refuses a DataStorage or FileStorage registration whose subgrove ID is not 1 to 64 ASCII letters, digits, `-`, or `_` starting with a letter or digit, or whose schema declares indexes ("Schema indexes are not supported"). Both raise `ValueError` before anything is signed, as does a field flagged `indexed` or a schema `version` outside u32. `ConsensusClient.register_subgrove` takes the schema as JSON text, which for a data or file subgrove must parse as the node's `SchemaDefinition`: `{"version": 1, "fields": {"name": "string"}, "indexes": [], "required_fields": ["name"]}`, each field's type one of `string`, `number`, `boolean`, `array`, `object`, or `bytes`.

```python
registration = await client.registration.register_subgrove({
    "dataset_id": "my-data",
    "name": "My Data",
    "schema": {
        "version": 1,
        "fields": {
            "name": {"type": "string", "required": True},
            "email": {"type": "string"},
            "age": {"type": "number"},
        },
    },
    "owner_did": did,
    "writers": [did],
    "readers": [],
})
await client.wait_until_landed(registration)  # before storing into it

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

### Private Subgroves (key grants)

```python
from willow import EncryptedKeyGrant

# Each is a transaction sent by the identity set on the client
await client.privacy.grant_subgrove_key("private-sg", grant)        # an EncryptedKeyGrant
await client.privacy.rotate_subgrove_key("private-sg", 2, new_grants)
await client.privacy.revoke_subgrove_key("private-sg", "did:willow:...")

mine = await client.privacy.get_my_key_grant("private-sg")
grantees = await client.privacy.list_key_grantees("private-sg")    # grantee DIDs
```

An `EncryptedKeyGrant`'s `ephemeral_public_key` and `encrypted_key` take bytes, hex, or a list of ints.

### Health Check

```python
health = await client.health()
print(f"Status: {health.status}")
print(f"Version: {health.version}")
for name, component in health.components.items():
    print(f"  {name}: {component.status}")
```

`GET /health` answers the health object itself (not an envelope), with `timestamp` as RFC 3339 text and its components under `checks`.

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
# Generate a new DID and save it locally, with its algorithm
willow-cli did generate --save
willow-cli did generate --algorithm secp256k1 --save

# Or save an existing identity (DID + private key + public key ID + algorithm,
# Ed25519 unless given; a login that keeps the saved DID and key keeps its algorithm)
willow-cli auth login --did <did> --key <private-key-hex> --key-id <key-id> --algorithm secp256k1

# Status / clear
willow-cli auth status
willow-cli auth logout

# Register a DID document, signed with the saved identity (pre-fund the DID first)
willow-cli did register did.json

# Data ops (reads the saved identity; stores are signed StoreData transactions)
willow-cli data store my-subgrove items.json
willow-cli data get my-subgrove user1

# Proof
willow-cli proof get my-subgrove user1
```

## License

MIT
