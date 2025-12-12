"""
Consensus Client Types

Transaction structures and types for direct blockchain interaction.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union
from enum import Enum
import base64
import json


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
class RegisterAppTx:
    """App registration transaction."""
    app_id: str
    name: str
    description: str
    app_type: str
    owner_did: str
    admins: List[str] = field(default_factory=list)
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "app_id": self.app_id,
            "name": self.name,
            "description": self.description,
            "app_type": self.app_type,
            "owner_did": self.owner_did,
            "admins": self.admins,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce
        }


@dataclass
class RegisterSubgroveTx:
    """Subgrove registration transaction."""
    subgrove_id: str
    app_id: str
    name: str
    schema: str  # JSON schema as string
    owner_did: str
    writers: List[str] = field(default_factory=list)
    readers: List[str] = field(default_factory=list)
    signature: str = ""  # hex-encoded
    public_key_id: str = ""
    nonce: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "subgrove_id": self.subgrove_id,
            "app_id": self.app_id,
            "name": self.name,
            "schema": self.schema,
            "owner_did": self.owner_did,
            "writers": self.writers,
            "readers": self.readers,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce
        }


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
            "amount": str(self.amount),  # Convert to string for large numbers
            "memo": self.memo,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce
        }


@dataclass
class DataStoreTx:
    """Data storage transaction."""
    app_id: str
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
            "app_id": self.app_id,
            "subgrove_id": self.subgrove_id,
            "key": self.key,
            "data": self.data,
            "owner_did": self.owner_did,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "nonce": self.nonce
        }


# Transaction type union
Transaction = Union[RegisterDidTx, RegisterAppTx, RegisterSubgroveTx, TransferTx, DataStoreTx]


def create_transaction_wrapper(tx_type: str, transaction: Transaction) -> Dict[str, Any]:
    """Create transaction wrapper for consensus submission."""
    return {tx_type: transaction.to_dict()}


def create_sign_message(tx_type: str, transaction: Transaction) -> str:
    """Create canonical message for transaction signing."""
    if tx_type == "RegisterDid":
        # For DID registration, sign the DID document directly
        return json.dumps(transaction.did_document, separators=(',', ':'), sort_keys=True)
    
    elif tx_type == "RegisterApp":
        tx = transaction
        return (
            f"RegisterApp\n"
            f"App ID: {tx.app_id}\n"
            f"Name: {tx.name}\n"
            f"Description: {tx.description}\n"
            f"Type: {tx.app_type}\n"
            f"Owner: {tx.owner_did}\n"
            f"Admins: {','.join(tx.admins)}\n"
            f"Nonce: {tx.nonce}"
        )
    
    elif tx_type == "RegisterSubgrove":
        tx = transaction
        return (
            f"RegisterSubgrove\n"
            f"Subgrove ID: {tx.subgrove_id}\n"
            f"App ID: {tx.app_id}\n"
            f"Name: {tx.name}\n"
            f"Schema: {tx.schema}\n"
            f"Owner: {tx.owner_did}\n"
            f"Writers: {','.join(tx.writers)}\n"
            f"Readers: {','.join(tx.readers)}\n"
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
    
    elif tx_type == "DataStore":
        tx = transaction
        return (
            f"DataStore\n"
            f"App ID: {tx.app_id}\n"
            f"Subgrove ID: {tx.subgrove_id}\n"
            f"Key: {tx.key}\n"
            f"Data: {tx.data}\n"
            f"Owner: {tx.owner_did}\n"
            f"Nonce: {tx.nonce}"
        )
    
    else:
        raise ValueError(f"Unknown transaction type: {tx_type}")