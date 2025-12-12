"""
Consensus Client Configuration Builder

Provides a fluent builder pattern for configuring the consensus client.
"""

from .types import ConsensusConfig


class ConsensusConfigBuilder:
    """Builder for creating consensus client configurations."""
    
    def __init__(self, consensus_rpc_url: str):
        """Initialize builder with required consensus RPC URL."""
        self._consensus_rpc_url = consensus_rpc_url
        self._chain_id = "willow-chain"
        self._request_timeout_secs = 30
        self._max_retries = 3
        self._retry_delay_secs = 1.0
    
    def chain_id(self, chain_id: str) -> 'ConsensusConfigBuilder':
        """Set the blockchain chain ID."""
        self._chain_id = chain_id
        return self
    
    def request_timeout_secs(self, seconds: int) -> 'ConsensusConfigBuilder':
        """Set request timeout in seconds."""
        self._request_timeout_secs = seconds
        return self
    
    def max_retries(self, retries: int) -> 'ConsensusConfigBuilder':
        """Set maximum retry attempts."""
        self._max_retries = retries
        return self
    
    def retry_delay_secs(self, seconds: float) -> 'ConsensusConfigBuilder':
        """Set delay between retries in seconds."""
        self._retry_delay_secs = seconds
        return self
    
    def build(self) -> ConsensusConfig:
        """Build the final configuration."""
        return ConsensusConfig(
            consensus_rpc_url=self._consensus_rpc_url,
            chain_id=self._chain_id,
            request_timeout_secs=self._request_timeout_secs,
            max_retries=self._max_retries,
            retry_delay_secs=self._retry_delay_secs
        )


# Convenience functions for common configurations
def local_config(port: int = 26657) -> ConsensusConfigBuilder:
    """Create configuration for local testing."""
    return ConsensusConfigBuilder(f"http://localhost:{port}")


def testnet_config(rpc_url: str) -> ConsensusConfigBuilder:
    """Create configuration for testnet deployment."""
    return (ConsensusConfigBuilder(rpc_url)
            .chain_id("willow-testnet")
            .request_timeout_secs(30)
            .max_retries(3)
            .retry_delay_secs(2.0))


def mainnet_config(rpc_url: str) -> ConsensusConfigBuilder:
    """Create configuration for mainnet deployment."""
    return (ConsensusConfigBuilder(rpc_url)
            .chain_id("willow-mainnet")
            .request_timeout_secs(60)
            .max_retries(5)
            .retry_delay_secs(3.0))