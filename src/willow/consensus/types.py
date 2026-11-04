"""
Consensus Client Types

Transaction structures and types for direct blockchain interaction.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union
from enum import Enum
import base64

from ..signed_messages import (
    _key_grant,
    delete_file_manifest_message,
    did_document_body,
    grant_subgrove_key_message,
    normalize_register_subgrove,
    register_did_message,
    register_subgrove_message,
    revoke_subgrove_key_message,
    rotate_subgrove_key_message,
    store_data_message,
    store_file_manifest_message,
)


class ConsensusError(Exception):
    """Base exception for consensus client operations.

    Raised by a write that failed after its nonce was chosen, it carries the
    ``did`` and ``nonce`` the transaction was signed under, and, when it may
    have reached the node, the signed ``transaction`` as sent (see
    ``ConsensusClient.resubmit``).
    """

    did: Optional[str] = None
    nonce: Optional[int] = None
    transaction: Optional[Dict[str, Any]] = None


class TransactionStatus(Enum):
    """Transaction status enumeration."""
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    NOT_FOUND = "not_found"


@dataclass
class ConsensusConfig:
    """Configuration for consensus client."""
    consensus_rpc_url: str
    api_url: Optional[str] = None  # REST API URL for account queries (nonce, etc.)
    chain_id: str = "willow-chain"
    request_timeout_secs: int = 30
    max_retries: int = 3
    retry_delay_secs: float = 1.0

    def __post_init__(self):
        if not self.consensus_rpc_url:
            raise ValueError("consensus_rpc_url is required")


@dataclass
class BroadcastResult:
    """Result of transaction broadcast.

    ``http_status`` is the API's HTTP status. ``resent`` is true when an
    earlier attempt of the same bytes failed in transit and may have reached
    the node. A write's result carries the ``did`` and ``nonce`` it was signed
    under, and, when it failed in a way that leaves open whether it reached
    the node (a gateway error, or a refusal after an earlier attempt of the
    same bytes may have reached it), the signed ``transaction`` to resubmit.
    """
    success: bool
    tx_hash: Optional[str] = None
    height: Optional[int] = None
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    raw_log: Optional[str] = None
    http_status: Optional[int] = None
    resent: bool = False
    did: Optional[str] = None
    nonce: Optional[int] = None
    transaction: Optional[Dict[str, Any]] = None
    
    @classmethod
    def from_response(cls, data: Dict[str, Any]) -> 'BroadcastResult':
        """Create result from CometBFT response."""
        if 'error' in data:
            return cls(
                success=False,
                error_message=data['error'].get('message', 'Unknown error')
            )
        
        result = data.get('result', {})
        code = result.get('code', 0)
        
        return cls(
            success=code == 0,
            tx_hash=result.get('hash'),
            height=result.get('height'),
            error_code=code if code != 0 else None,
            error_message=result.get('log') if code != 0 else None,
            raw_log=result.get('log')
        )


@dataclass
class RegisterDidTx:
    """DID registration transaction.

    It is signed over the node's compact JSON of the DID document
    (``register_did_message``) and sends that document as the node decodes
    it (``did_document_body``). The node takes a registration only at nonce 1.
    """
    did_document: Dict[str, Any]
    signature: str  # hex-encoded
    public_key_id: str
    nonce: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "did_document": did_document_body(self.did_document),
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce
        }


@dataclass
class SubgroveDataStorage:
    """DataStorage mode configuration for a subgrove."""
    name: str = ""
    writers: List[str] = field(default_factory=list)
    free_readers: List[str] = field(default_factory=list)
    read_pricing: Optional[Any] = None


@dataclass
class RetentionWindow:
    """How long real-time indexed data is retained on consensus nodes."""
    type: str  # "Blocks", "Seconds", "Indefinite", or "VerifyOnly"
    value: Optional[int] = None


@dataclass
class SubgroveBlockchainIndexing:
    """BlockchainIndexing mode configuration for a subgrove."""
    manifest_content: Optional[List[int]] = None
    wasm_modules: Optional[List[Any]] = None
    execution_mode: Optional[Any] = None
    indexer_config: Optional[Any] = None
    retention_window: Optional[RetentionWindow] = None


# SubgroveMode is represented as a dict with a single key: "DataStorage" or "BlockchainIndexing"
SubgroveMode = Union[Dict[str, Any], None]


@dataclass
class RegisterSubgroveTx:
    """Subgrove registration transaction.

    ``to_dict`` gives every field of the node's transaction explicitly (see
    ``normalize_register_subgrove``), and the transaction is signed over
    ``register_subgrove_message`` of exactly that, so its ``Config`` binds
    every field. ``mode`` is the node's JSON form, e.g.
    ``{"DataStorage": {"name": ..., "writers": [...], "free_readers": [...]}}``,
    ``{"FileStorage": {...}}``, or ``{"BlockchainIndexing": {...}}``; ``None``
    is DataStorage with an empty name, writers, and free readers. ``name``
    defaults to the mode's name. ``retention_window`` is a BlockchainIndexing
    mode's own field; set here, it goes into that mode.
    """
    subgrove_id: str
    schema: str  # JSON schema as string
    owner_did: str
    mode: SubgroveMode = None  # None defaults to DataStorage
    retention_window: Optional[RetentionWindow] = None
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0
    name: Optional[str] = None
    description: str = ""
    admins: List[str] = field(default_factory=list)
    initial_funding: Optional[int] = None
    required_tee: Optional[str] = None  # "AwsNitro", "IntelSgx", or "AmdSev"
    privacy: Optional[Any] = None  # willow.privacy.PrivacyConfig or its JSON form
    initial_owner_key_grant: Optional[Any] = None  # EncryptedKeyGrant or its JSON form
    template_config: Optional[Dict[str, Any]] = None
    confirmation_depth: int = 0
    cryptographic_completeness: bool = False

    def _mode(self) -> SubgroveMode:
        if self.retention_window is None:
            return self.mode
        indexing = self.mode.get("BlockchainIndexing") if isinstance(self.mode, dict) else None
        if not isinstance(indexing, dict):
            raise ValueError("retention_window applies only to a BlockchainIndexing mode")
        if indexing.get("retention_window") is not None:
            raise ValueError("retention_window is set both here and in the BlockchainIndexing mode")
        return {"BlockchainIndexing": {**indexing, "retention_window": self.retention_window}}

    def to_dict(self) -> Dict[str, Any]:
        """The transaction's JSON object, every field explicit, as the node decodes it."""
        mode = self._mode()
        name = self.name
        if name is None:
            payload = next(iter(mode.values()), None) if isinstance(mode, dict) and len(mode) == 1 else None
            name = payload.get("name", "") if isinstance(payload, dict) else ""
        return normalize_register_subgrove({
            "subgrove_id": self.subgrove_id,
            "name": name,
            "description": self.description,
            "schema": self.schema,
            "owner_did": self.owner_did,
            "admins": list(self.admins),
            "initial_funding": self.initial_funding,
            "checkpoint_verification": {"required_tee": self.required_tee},
            "mode": mode,
            "privacy": self.privacy,
            "initial_owner_key_grant": self.initial_owner_key_grant,
            "template_config": self.template_config,
            "confirmation_depth": self.confirmation_depth,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce,
            "cryptographic_completeness": self.cryptographic_completeness,
        })


@dataclass
class TransferTx:
    """Token transfer transaction."""
    from_did: str
    to_did: str
    amount: int  # Amount in smallest unit
    memo: Optional[str] = None
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "from_did": self.from_did,
            "to_did": self.to_did,
            "amount": self.amount,  # u128 on the wire — serde expects a JSON number
            "memo": self.memo,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce
        }


@dataclass
class DataStoreTx:
    """Data storage transaction (the chain's ``StoreData``).

    ``data`` is JSON text; the transaction carries its UTF-8 bytes.
    """
    subgrove_id: str
    key: str
    data: str  # JSON data as string
    owner_did: str
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "subgrove_id": self.subgrove_id,
            "key": self.key,
            "data": self.data,
            "owner_did": self.owner_did,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce
        }


@dataclass
class StoreFileManifestTx:
    """Store file manifest transaction."""
    subgrove_id: str
    file_key: str
    filename: str
    content_type: str
    total_size: int
    content_hash: str
    chunk_count: int
    chunk_size: int
    chunk_merkle_root: str
    owner_did: str
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "subgrove_id": self.subgrove_id,
            "file_key": self.file_key,
            "filename": self.filename,
            "content_type": self.content_type,
            "total_size": self.total_size,
            "content_hash": self.content_hash,
            "chunk_count": self.chunk_count,
            "chunk_size": self.chunk_size,
            "chunk_merkle_root": self.chunk_merkle_root,
            "owner_did": self.owner_did,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce,
        }


@dataclass
class DeleteFileManifestTx:
    """Delete file manifest transaction."""
    subgrove_id: str
    file_key: str
    owner_did: str
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "subgrove_id": self.subgrove_id,
            "file_key": self.file_key,
            "owner_did": self.owner_did,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce,
        }


@dataclass
class DeregisterSubgroveTx:
    """Deregister (delete) a subgrove transaction. Remaining funding is refunded to the owner."""
    subgrove_id: str
    owner_did: str
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "subgrove_id": self.subgrove_id,
            "owner_did": self.owner_did,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce,
        }


@dataclass
class GrantSubgroveKeyTx:
    """Grant a subgrove's encryption key to a DID (owner or admin).

    ``encrypted_key_grant`` is an ``EncryptedKeyGrant`` or its JSON form;
    byte fields go as bytes, hex, or lists of ints.
    """
    subgrove_id: str
    encrypted_key_grant: Any
    sender_did: str
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "subgrove_id": self.subgrove_id,
            "encrypted_key_grant": _key_grant("encrypted_key_grant", self.encrypted_key_grant),
            "sender_did": self.sender_did,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce,
        }


@dataclass
class RevokeSubgroveKeyTx:
    """Revoke a DID's subgrove key grant (owner or admin)."""
    subgrove_id: str
    revokee_did: str
    sender_did: str
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "subgrove_id": self.subgrove_id,
            "revokee_did": self.revokee_did,
            "sender_did": self.sender_did,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce,
        }


@dataclass
class RotateSubgroveKeyTx:
    """Rotate a subgrove's encryption key to ``new_epoch`` (owner), with a
    grant for every DID that keeps access."""
    subgrove_id: str
    new_epoch: int
    new_grants: List[Any]
    sender_did: str
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "subgrove_id": self.subgrove_id,
            "new_epoch": self.new_epoch,
            "new_grants": [
                _key_grant(f"new_grants[{i}]", g) for i, g in enumerate(self.new_grants)
            ],
            "sender_did": self.sender_did,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce,
        }


# Transaction type union
Transaction = Union[
    RegisterDidTx, RegisterSubgroveTx, TransferTx, DataStoreTx,
    StoreFileManifestTx, DeleteFileManifestTx, DeregisterSubgroveTx,
    GrantSubgroveKeyTx, RevokeSubgroveKeyTx, RotateSubgroveKeyTx,
]


def _hex_signature_to_bytes(hex_sig: str) -> List[int]:
    """Convert a hex-encoded signature to the list-of-ints wire format.

    The consensus `Transaction` enum stores `signature: Vec<u8>`; serde_json
    serializes that as a JSON number array, which is what the API server's
    `/tx/submit` expects. SDK call sites still hand us hex for ergonomics;
    convert at the boundary.
    """
    s = hex_sig[2:] if hex_sig.startswith("0x") else hex_sig
    if not s:
        return []
    return [int(s[i:i + 2], 16) for i in range(0, len(s), 2)]


def _data_bytes(tx: DataStoreTx) -> bytes:
    """The bytes a StoreData transaction's ``data`` field carries."""
    if isinstance(tx.data, (bytes, bytearray)):
        return bytes(tx.data)
    return tx.data.encode("utf-8")


def create_transaction_wrapper(tx_type: str, transaction: Transaction) -> Dict[str, Any]:
    """Create transaction wrapper for consensus submission.

    Converts the internal hex strings (`signature`, and a file manifest's
    `content_hash` and `chunk_merkle_root`) and a StoreData transaction's
    JSON text to the byte fields the validator reads (JSON number arrays).
    ``DataStore`` is sent as the chain's ``StoreData``. A RegisterSubgrove
    carries every field explicitly, as its ``Config`` hashed them.
    """
    body = transaction.to_dict()
    if isinstance(body.get("signature"), str):
        body["signature"] = _hex_signature_to_bytes(body["signature"])
    if tx_type in ("DataStore", "StoreData"):
        tx_type = "StoreData"
        body["data"] = list(_data_bytes(transaction))
    elif tx_type == "StoreFileManifest":
        for name in ("content_hash", "chunk_merkle_root"):
            if isinstance(body[name], str):
                body[name] = _hex_signature_to_bytes(body[name])
            elif isinstance(body[name], (bytes, bytearray)):
                body[name] = list(body[name])
    return {tx_type: body}


def create_sign_message(tx_type: str, transaction: Transaction) -> str:
    """Create canonical message for transaction signing.

    StoreData (``DataStore``), StoreFileManifest, DeleteFileManifest,
    RegisterSubgrove, GrantSubgroveKey, RotateSubgroveKey, and
    RevokeSubgroveKey use the builders in ``willow.signed_messages``, which
    bind the transaction's nonce and every field it writes; build the message
    after the nonce is set. RegisterDid signs the node's compact JSON of the
    DID document.
    """
    if tx_type == "RegisterDid":
        return register_did_message(transaction.did_document)

    elif tx_type == "RegisterSubgrove":
        return register_subgrove_message(transaction.to_dict())
    
    elif tx_type == "Transfer":
        tx = transaction
        memo = tx.memo or ""
        return (
            f"Transfer\n"
            f"From: {tx.from_did}\n"
            f"To: {tx.to_did}\n"
            f"Amount: {tx.amount}\n"
            f"Memo: {memo}\n"
            f"Nonce: {tx.nonce}"
        )
    
    elif tx_type in ("DataStore", "StoreData"):
        tx = transaction
        return store_data_message(
            tx.subgrove_id, tx.key, tx.owner_did, _data_bytes(tx), tx.nonce
        )

    elif tx_type == "StoreFileManifest":
        tx = transaction
        return store_file_manifest_message(
            tx.subgrove_id,
            tx.file_key,
            tx.owner_did,
            tx.filename,
            tx.content_type,
            tx.total_size,
            tx.content_hash,
            tx.chunk_count,
            tx.chunk_size,
            tx.chunk_merkle_root,
            tx.nonce,
        )

    elif tx_type == "DeleteFileManifest":
        tx = transaction
        return delete_file_manifest_message(tx.subgrove_id, tx.file_key, tx.owner_did, tx.nonce)

    elif tx_type == "DeregisterSubgrove":
        tx = transaction
        return f"DeregisterSubgrove:{tx.subgrove_id}:{tx.owner_did}:{tx.nonce}"

    elif tx_type == "GrantSubgroveKey":
        tx = transaction
        return grant_subgrove_key_message(
            tx.subgrove_id, tx.sender_did, tx.encrypted_key_grant, tx.nonce
        )

    elif tx_type == "RevokeSubgroveKey":
        tx = transaction
        return revoke_subgrove_key_message(tx.subgrove_id, tx.revokee_did, tx.sender_did, tx.nonce)

    elif tx_type == "RotateSubgroveKey":
        tx = transaction
        return rotate_subgrove_key_message(
            tx.subgrove_id, tx.sender_did, tx.new_epoch, tx.new_grants, tx.nonce
        )

    else:
        raise ValueError(f"Unknown transaction type: {tx_type}")