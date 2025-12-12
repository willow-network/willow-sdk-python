"""
Light Client Types

Core data structures for CometBFT light client protocol and GroveDB proof verification.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
import base64
import json


class LightClientError(Exception):
    """Base exception for light client operations."""
    pass


@dataclass
class TrustThreshold:
    """Trust threshold for validator consensus (e.g., 2/3+ validators)."""
    numerator: int = 2
    denominator: int = 3
    
    def __post_init__(self):
        if self.numerator <= 0 or self.denominator <= 0:
            raise ValueError("Trust threshold values must be positive")
        if self.numerator > self.denominator:
            raise ValueError("Numerator cannot exceed denominator")
    
    @property
    def fraction(self) -> float:
        """Get the threshold as a decimal fraction."""
        return self.numerator / self.denominator


@dataclass
class Validator:
    """Individual validator information."""
    address: bytes
    pub_key: bytes
    voting_power: int
    proposer_priority: int = 0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Validator':
        """Create validator from CometBFT JSON response."""
        return cls(
            address=base64.b64decode(data['address']),
            pub_key=base64.b64decode(data['pub_key']['value']),
            voting_power=int(data['voting_power']),
            proposer_priority=int(data.get('proposer_priority', 0))
        )


@dataclass
class ValidatorSet:
    """Set of validators for a specific block."""
    validators: List[Validator]
    proposer: Optional[Validator] = None
    total_voting_power: Optional[int] = None
    
    def __post_init__(self):
        if self.total_voting_power is None:
            self.total_voting_power = sum(v.voting_power for v in self.validators)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ValidatorSet':
        """Create validator set from CometBFT JSON response."""
        validators = [Validator.from_dict(v) for v in data['validators']]
        proposer = None
        if 'proposer' in data and data['proposer']:
            proposer = Validator.from_dict(data['proposer'])
        
        return cls(
            validators=validators,
            proposer=proposer,
            total_voting_power=int(data.get('total_voting_power', 0))
        )


@dataclass
class BlockId:
    """Block identifier containing hash and part set header."""
    hash: bytes
    part_set_header_total: int
    part_set_header_hash: bytes
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BlockId':
        """Create block ID from CometBFT JSON response."""
        return cls(
            hash=base64.b64decode(data['hash']),
            part_set_header_total=int(data['part_set_header']['total']),
            part_set_header_hash=base64.b64decode(data['part_set_header']['hash'])
        )


@dataclass
class Header:
    """Block header containing consensus metadata."""
    version: Dict[str, int]
    chain_id: str
    height: int
    time: datetime
    last_block_id: Optional[BlockId]
    last_commit_hash: bytes
    data_hash: bytes
    validators_hash: bytes
    next_validators_hash: bytes
    consensus_hash: bytes
    app_hash: bytes  # Critical for proof verification
    last_results_hash: bytes
    evidence_hash: bytes
    proposer_address: bytes
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Header':
        """Create header from CometBFT JSON response."""
        last_block_id = None
        if data.get('last_block_id') and data['last_block_id']['hash']:
            last_block_id = BlockId.from_dict(data['last_block_id'])
        
        return cls(
            version=data['version'],
            chain_id=data['chain_id'],
            height=int(data['height']),
            time=datetime.fromisoformat(data['time'].replace('Z', '+00:00')),
            last_block_id=last_block_id,
            last_commit_hash=base64.b64decode(data['last_commit_hash']),
            data_hash=base64.b64decode(data['data_hash']),
            validators_hash=base64.b64decode(data['validators_hash']),
            next_validators_hash=base64.b64decode(data['next_validators_hash']),
            consensus_hash=base64.b64decode(data['consensus_hash']),
            app_hash=base64.b64decode(data['app_hash']),
            last_results_hash=base64.b64decode(data['last_results_hash']),
            evidence_hash=base64.b64decode(data['evidence_hash']),
            proposer_address=base64.b64decode(data['proposer_address'])
        )


@dataclass
class CommitSig:
    """Individual validator's commit signature."""
    block_id_flag: int
    validator_address: bytes
    timestamp: datetime
    signature: Optional[bytes]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CommitSig':
        """Create commit signature from CometBFT JSON response."""
        signature = None
        if data.get('signature'):
            signature = base64.b64decode(data['signature'])
        
        return cls(
            block_id_flag=int(data['block_id_flag']),
            validator_address=base64.b64decode(data['validator_address']),
            timestamp=datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')),
            signature=signature
        )


@dataclass
class Commit:
    """Block commit containing validator signatures."""
    height: int
    round: int
    block_id: BlockId
    signatures: List[CommitSig]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Commit':
        """Create commit from CometBFT JSON response."""
        return cls(
            height=int(data['height']),
            round=int(data['round']),
            block_id=BlockId.from_dict(data['block_id']),
            signatures=[CommitSig.from_dict(sig) for sig in data['signatures']]
        )


@dataclass
class LightBlock:
    """Complete light block containing header, commit, and validator set."""
    header: Header
    commit: Commit
    validators: ValidatorSet
    next_validators: Optional[ValidatorSet] = None
    provider: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any], provider: Optional[str] = None) -> 'LightBlock':
        """Create light block from CometBFT JSON response."""
        return cls(
            header=Header.from_dict(data['header']),
            commit=Commit.from_dict(data['commit']),
            validators=ValidatorSet.from_dict(data['validators']),
            next_validators=ValidatorSet.from_dict(data['next_validators']) if 'next_validators' in data else None,
            provider=provider
        )


@dataclass
class TrustedHeader:
    """Trusted header for state export/import."""
    header: Header
    validators_hash: bytes
    next_validators_hash: bytes
    trusted_at: datetime
    provider: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize trusted header for storage."""
        return {
            'height': self.header.height,
            'chain_id': self.header.chain_id,
            'app_hash': base64.b64encode(self.header.app_hash).decode(),
            'validators_hash': base64.b64encode(self.validators_hash).decode(),
            'next_validators_hash': base64.b64encode(self.next_validators_hash).decode(),
            'trusted_at': self.trusted_at.isoformat(),
            'provider': self.provider
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TrustedHeader':
        """Deserialize trusted header from storage."""
        # Create minimal header for verification
        header = Header(
            version={'block': 11, 'app': 1},
            chain_id=data['chain_id'],
            height=data['height'],
            time=datetime.fromisoformat(data['trusted_at']),
            last_block_id=None,
            last_commit_hash=b'',
            data_hash=b'',
            validators_hash=base64.b64decode(data['validators_hash']),
            next_validators_hash=base64.b64decode(data['next_validators_hash']),
            consensus_hash=b'',
            app_hash=base64.b64decode(data['app_hash']),
            last_results_hash=b'',
            evidence_hash=b'',
            proposer_address=b''
        )
        
        return cls(
            header=header,
            validators_hash=base64.b64decode(data['validators_hash']),
            next_validators_hash=base64.b64decode(data['next_validators_hash']),
            trusted_at=datetime.fromisoformat(data['trusted_at']),
            provider=data.get('provider')
        )


@dataclass
class QueryProof:
    """GroveDB query proof with verification metadata."""
    proof: bytes
    path_query: Dict[str, Any]
    height: int
    query_result: List[bytes] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize query proof."""
        return {
            'proof': base64.b64encode(self.proof).decode(),
            'path_query': self.path_query,
            'height': self.height,
            'query_result': [base64.b64encode(result).decode() for result in self.query_result]
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QueryProof':
        """Deserialize query proof."""
        return cls(
            proof=base64.b64decode(data['proof']),
            path_query=data['path_query'],
            height=data['height'],
            query_result=[base64.b64decode(result) for result in data.get('query_result', [])]
        )


@dataclass
class VerificationResult:
    """Result of header or proof verification."""
    success: bool
    error: Optional[str] = None
    height: Optional[int] = None
    next_height: Optional[int] = None
    trust_level: Optional[float] = None
    
    @property
    def is_valid(self) -> bool:
        """Check if verification was successful."""
        return self.success and self.error is None


@dataclass
class LightClientConfig:
    """Configuration for light client operation."""
    chain_id: str
    validator_endpoints: List[str]
    trust_threshold: TrustThreshold = field(default_factory=TrustThreshold)
    trusting_period_secs: int = 86400  # 24 hours
    max_clock_drift_secs: int = 10
    min_validators_for_consensus: int = 2
    auto_sync: bool = True
    sync_interval_secs: int = 300  # 5 minutes
    max_retries: int = 3
    request_timeout_secs: int = 30
    
    def __post_init__(self):
        if not self.validator_endpoints:
            raise ValueError("At least one validator endpoint is required")
        if self.min_validators_for_consensus < 1:
            raise ValueError("Minimum validators must be at least 1")
        if len(self.validator_endpoints) < self.min_validators_for_consensus:
            raise ValueError("Not enough validator endpoints for consensus requirements")