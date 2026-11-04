"""
Consensus Client Types

Transaction structures and types for direct blockchain interaction.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union
from enum import Enum
import base64
import json

from ..signed_messages import (
    delete_file_manifest_message,
    store_data_message,
    store_file_manifest_message,
)


class ConsensusError(Exception):
    """Base exception for consensus client operations."""
    pass


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
    """Result of transaction broadcast."""
    success: bool
    tx_hash: Optional[str] = None
    height: Optional[int] = None
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    raw_log: Optional[str] = None
    
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
    """DID registration transaction."""
    did_document: Dict[str, Any]
    signature: str  # hex-encoded
    public_key_id: str
    nonce: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "did_document": self.did_document,
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
    """Subgrove registration transaction."""
    subgrove_id: str
    schema: str  # JSON schema as string
    owner_did: str
    mode: SubgroveMode = None  # None defaults to DataStorage
    retention_window: Optional[RetentionWindow] = None
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "subgrove_id": self.subgrove_id,
            "schema": self.schema,
            "owner_did": self.owner_did,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce
        }
        if self.mode is not None:
            result["mode"] = self.mode
        if self.retention_window is not None:
            result["retention_window"] = {
                "type": self.retention_window.type,
                **({"value": self.retention_window.value} if self.retention_window.value is not None else {})
            }
        return result


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


# Transaction type union
Transaction = Union[
    RegisterDidTx, RegisterSubgroveTx, TransferTx, DataStoreTx,
    StoreFileManifestTx, DeleteFileManifestTx, DeregisterSubgroveTx,
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
    ``DataStore`` is sent as the chain's ``StoreData``.
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

    StoreData (``DataStore``), StoreFileManifest, and DeleteFileManifest use
    the builders in ``willow.signed_messages``, which bind the transaction's
    nonce and every field it writes; build the message after the nonce is set.
    """
    if tx_type == "RegisterDid":
        # For DID registration, sign the DID document directly
        return json.dumps(transaction.did_document, separators=(',', ':'), sort_keys=True)
    
    elif tx_type == "RegisterSubgrove":
        tx = transaction
        mode = tx.mode
        if mode and "BlockchainIndexing" in mode:
            bi = mode["BlockchainIndexing"]
            return (
                f"RegisterSubgrove\n"
                f"Subgrove ID: {tx.subgrove_id}\n"
                
                f"Mode: BlockchainIndexing\n"
                f"Schema: {tx.schema}\n"
                f"Owner: {tx.owner_did}\n"
                f"Nonce: {tx.nonce}"
            )
        # DataStorage mode (default)
        ds = mode.get("DataStorage", {}) if mode and "DataStorage" in mode else {}
        return (
            f"RegisterSubgrove\n"
            f"Subgrove ID: {tx.subgrove_id}\n"
            
            f"Name: {ds.get('name', '')}\n"
            f"Schema: {tx.schema}\n"
            f"Owner: {tx.owner_did}\n"
            f"Writers: {','.join(ds.get('writers', []))}\n"
            f"Readers: {','.join(ds.get('free_readers', []))}\n"
            f"Nonce: {tx.nonce}"
        )
    
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

    else:
        raise ValueError(f"Unknown transaction type: {tx_type}")