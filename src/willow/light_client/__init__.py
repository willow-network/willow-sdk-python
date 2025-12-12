"""
Willow Light Client for Python

Provides cryptographically secure data verification through CometBFT light client protocol
and GroveDB proof verification, enabling trustless operation without running a full node.
"""

from .client import LightClient
from .types import (
    LightBlock,
    Header,
    Commit,
    ValidatorSet,
    Validator,
    TrustThreshold,
    TrustedHeader,
    QueryProof,
    VerificationResult,
    LightClientConfig,
    LightClientError,
)
from .verifier import HeaderVerifier, ProofVerifier
from .config import LightClientConfigBuilder

__all__ = [
    "LightClient",
    "LightBlock",
    "Header", 
    "Commit",
    "ValidatorSet",
    "Validator",
    "TrustThreshold",
    "TrustedHeader",
    "QueryProof",
    "VerificationResult",
    "LightClientConfig",
    "LightClientError",
    "HeaderVerifier",
    "ProofVerifier",
    "LightClientConfigBuilder",
]