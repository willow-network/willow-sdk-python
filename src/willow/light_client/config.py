"""
Light Client Configuration Builder

Provides a fluent builder pattern for configuring the light client.
"""

from typing import List, Optional
from .types import LightClientConfig, TrustThreshold


class LightClientConfigBuilder:
    """Builder for creating light client configurations."""
    
    def __init__(self, chain_id: str):
        """Initialize builder with required chain ID."""
        self._chain_id = chain_id
        self._validator_endpoints: List[str] = []
        self._trust_threshold = TrustThreshold()
        self._trusting_period_secs = 86400  # 24 hours
        self._max_clock_drift_secs = 10
        self._min_validators_for_consensus = 2
        self._auto_sync = True
        self._sync_interval_secs = 300  # 5 minutes
        self._max_retries = 3
        self._request_timeout_secs = 30
    
    def validator_endpoints(self, endpoints: List[str]) -> 'LightClientConfigBuilder':
        """Set validator RPC endpoints."""
        self._validator_endpoints = endpoints.copy()
        return self
    
    def add_validator_endpoint(self, endpoint: str) -> 'LightClientConfigBuilder':
        """Add a single validator RPC endpoint."""
        self._validator_endpoints.append(endpoint)
        return self
    
    def trust_threshold(self, numerator: int, denominator: int) -> 'LightClientConfigBuilder':
        """Set trust threshold (e.g., 2/3 for 2/3+ consensus)."""
        self._trust_threshold = TrustThreshold(numerator, denominator)
        return self
    
    def trusting_period_secs(self, seconds: int) -> 'LightClientConfigBuilder':
        """Set trusting period in seconds."""
        self._trusting_period_secs = seconds
        return self
    
    def trusting_period_hours(self, hours: int) -> 'LightClientConfigBuilder':
        """Set trusting period in hours."""
        self._trusting_period_secs = hours * 3600
        return self
    
    def trusting_period_days(self, days: int) -> 'LightClientConfigBuilder':
        """Set trusting period in days."""
        self._trusting_period_secs = days * 86400
        return self
    
    def max_clock_drift_secs(self, seconds: int) -> 'LightClientConfigBuilder':
        """Set maximum allowed clock drift in seconds."""
        self._max_clock_drift_secs = seconds
        return self
    
    def min_validators_for_consensus(self, count: int) -> 'LightClientConfigBuilder':
        """Set minimum number of validators required for consensus."""
        self._min_validators_for_consensus = count
        return self
    
    def auto_sync(self, enabled: bool) -> 'LightClientConfigBuilder':
        """Enable or disable automatic header synchronization."""
        self._auto_sync = enabled
        return self
    
    def sync_interval_secs(self, seconds: int) -> 'LightClientConfigBuilder':
        """Set automatic sync interval in seconds."""
        self._sync_interval_secs = seconds
        return self
    
    def sync_interval_minutes(self, minutes: int) -> 'LightClientConfigBuilder':
        """Set automatic sync interval in minutes."""
        self._sync_interval_secs = minutes * 60
        return self
    
    def max_retries(self, retries: int) -> 'LightClientConfigBuilder':
        """Set maximum retry attempts for network requests."""
        self._max_retries = retries
        return self
    
    def request_timeout_secs(self, seconds: int) -> 'LightClientConfigBuilder':
        """Set request timeout in seconds."""
        self._request_timeout_secs = seconds
        return self
    
    def build(self) -> LightClientConfig:
        """Build the final configuration."""
        return LightClientConfig(
            chain_id=self._chain_id,
            validator_endpoints=self._validator_endpoints,
            trust_threshold=self._trust_threshold,
            trusting_period_secs=self._trusting_period_secs,
            max_clock_drift_secs=self._max_clock_drift_secs,
            min_validators_for_consensus=self._min_validators_for_consensus,
            auto_sync=self._auto_sync,
            sync_interval_secs=self._sync_interval_secs,
            max_retries=self._max_retries,
            request_timeout_secs=self._request_timeout_secs
        )


# Convenience functions for common configurations
def test_config(chain_id: str = "test-chain-consensus") -> LightClientConfigBuilder:
    """Create configuration for local testing."""
    return (LightClientConfigBuilder(chain_id)
            .validator_endpoints([
                "http://localhost:26657",
                "http://localhost:26757", 
                "http://localhost:26957"
            ])
            .min_validators_for_consensus(2)
            .trust_threshold(2, 3)
            .trusting_period_hours(24)
            .auto_sync(True))


def mainnet_config(chain_id: str) -> LightClientConfigBuilder:
    """Create configuration for mainnet deployment."""
    return (LightClientConfigBuilder(chain_id)
            .trust_threshold(2, 3)
            .trusting_period_days(14)  # 2 weeks
            .max_clock_drift_secs(30)
            .min_validators_for_consensus(3)
            .auto_sync(True)
            .sync_interval_minutes(10)
            .max_retries(5)
            .request_timeout_secs(60))


def fast_sync_config(chain_id: str) -> LightClientConfigBuilder:
    """Create configuration optimized for fast synchronization."""
    return (LightClientConfigBuilder(chain_id)
            .trust_threshold(1, 2)  # Lower threshold for faster sync
            .trusting_period_hours(6)  # Shorter period
            .auto_sync(True)
            .sync_interval_minutes(1)  # Frequent updates
            .max_retries(3)
            .request_timeout_secs(15))