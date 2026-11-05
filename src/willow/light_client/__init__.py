"""
Willow Light Client for Python

Holds CometBFT headers and checks GroveDB proofs against their app hashes. It
does not verify CometBFT commit signatures, so it verifies no header it
fetches: a proof checked against a header it holds is only as trustworthy as
that header's source (see ``LightClient``).
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