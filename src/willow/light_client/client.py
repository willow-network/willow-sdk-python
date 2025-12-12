"""
Light Client Implementation

Provides cryptographically secure data verification through CometBFT light client protocol
and GroveDB proof verification.
"""

import asyncio
import aiohttp
import json
import time
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone
import logging

from .types import (
    LightBlock, Header, TrustedHeader, QueryProof, VerificationResult,
    LightClientConfig, LightClientError
)
from .verifier import HeaderVerifier, ProofVerifier

logger = logging.getLogger(__name__)


class LightClient:
    """
    CometBFT light client with GroveDB proof verification.
    
    Provides cryptographically secure data verification without running a full node.
    """
    
    def __init__(self, config: LightClientConfig):
        """Initialize light client with configuration."""
        self.config = config
        self.header_verifier = HeaderVerifier(config.chain_id, config.trust_threshold)
        self.proof_verifier = ProofVerifier()
        
        # State management
        self._trusted_headers: Dict[int, LightBlock] = {}
        self._latest_height: Optional[int] = None
        self._sync_task: Optional[asyncio.Task] = None
        self._session: Optional[aiohttp.ClientSession] = None
        
        # Track verification status
        self._verified_height_range: Optional[Tuple[int, int]] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
    
    async def start(self):
        """Start the light client and begin synchronization."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.request_timeout_secs)
        )
        
        if self.config.auto_sync:
            self._sync_task = asyncio.create_task(self._sync_loop())
        
        logger.info("Light client started")
    
    async def stop(self):
        """Stop the light client and cleanup resources."""
        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
        
        if self._session:
            await self._session.close()
        
        logger.info("Light client stopped")
    
    async def initialize_with_trusted_header(self, trusted_header: LightBlock):
        """
        Initialize the light client with a trusted header.
        
        This is the bootstrap process that establishes initial trust.
        The trusted header should be obtained through a secure channel.
        """
        # Validate the trusted header
        result = self.header_verifier.verify_header(
            trusted_header,
            max_clock_drift_secs=self.config.max_clock_drift_secs
        )
        
        if not result.success:
            raise LightClientError(f"Trusted header validation failed: {result.error}")
        
        # Store as trusted
        height = trusted_header.header.height
        self._trusted_headers[height] = trusted_header
        self._latest_height = height
        self._verified_height_range = (height, height)
        
        logger.info(f"Initialized with trusted header at height {height}")
    
    async def verify_header(self, header: LightBlock) -> VerificationResult:
        """
        Verify a header against the current trusted state.
        
        Args:
            header: Header to verify
            
        Returns:
            VerificationResult indicating success/failure
        """
        if not self._trusted_headers:
            return VerificationResult(
                success=False,
                error="No trusted headers available. Initialize first.",
                height=header.header.height
            )
        
        # Find the best trusted header for verification
        trusted_header = self._find_best_trusted_header(header.header.height)
        
        if trusted_header is None:
            return VerificationResult(
                success=False,
                error="No suitable trusted header found",
                height=header.header.height
            )
        
        # Verify against trusted state
        result = self.header_verifier.verify_header(
            header,
            trusted_header,
            max_clock_drift_secs=self.config.max_clock_drift_secs
        )
        
        # If verification succeeds, add to trusted set
        if result.success:
            self._add_trusted_header(header)
        
        return result
    
    async def get_header_by_height(self, height: int) -> Optional[LightBlock]:
        """Get a verified header by height."""
        # Check if we already have it
        if height in self._trusted_headers:
            return self._trusted_headers[height]
        
        # Try to fetch and verify it
        try:
            header = await self._fetch_header_from_validators(height)
            if header:
                result = await self.verify_header(header)
                if result.success:
                    return header
        except Exception as e:
            logger.warning(f"Failed to fetch header {height}: {e}")
        
        return None
    
    async def get_latest_header(self) -> Optional[LightBlock]:
        """Get the latest verified header."""
        if self._latest_height is not None:
            return self._trusted_headers.get(self._latest_height)
        return None
    
    async def sync_to_latest(self) -> VerificationResult:
        """Synchronize to the latest blockchain state."""
        try:
            # Get latest height from validators
            latest_height = await self._get_latest_height_from_validators()
            if latest_height is None:
                return VerificationResult(
                    success=False,
                    error="Could not determine latest height"
                )
            
            # If we're already at latest, return success
            if self._latest_height is not None and latest_height <= self._latest_height:
                return VerificationResult(
                    success=True,
                    height=self._latest_height
                )
            
            # Sync to latest height
            start_height = (self._latest_height or 1) + 1
            
            for height in range(start_height, latest_height + 1):
                header = await self._fetch_header_from_validators(height)
                if header is None:
                    return VerificationResult(
                        success=False,
                        error=f"Could not fetch header at height {height}",
                        height=height
                    )
                
                result = await self.verify_header(header)
                if not result.success:
                    return result
            
            return VerificationResult(
                success=True,
                height=latest_height
            )
            
        except Exception as e:
            return VerificationResult(
                success=False,
                error=f"Sync failed: {str(e)}"
            )
    
    async def verify_query_proof(
        self,
        proof: QueryProof,
        height: Optional[int] = None
    ) -> VerificationResult:
        """
        Verify a GroveDB query proof against verified headers.
        
        Args:
            proof: Query proof to verify
            height: Specific height to verify against (uses proof height if None)
            
        Returns:
            VerificationResult indicating success/failure
        """
        verify_height = height or proof.height
        
        # Get trusted header for the height
        trusted_header = await self.get_header_by_height(verify_height)
        if trusted_header is None:
            return VerificationResult(
                success=False,
                error=f"No verified header available for height {verify_height}",
                height=verify_height
            )
        
        # Verify the proof against the trusted app hash
        return self.proof_verifier.verify_query_proof(
            proof,
            trusted_header.header.app_hash
        )
    
    async def export_trusted_state(self) -> List[TrustedHeader]:
        """Export trusted headers for state persistence."""
        trusted_state = []
        
        for height, light_block in self._trusted_headers.items():
            trusted_header = TrustedHeader(
                header=light_block.header,
                validators_hash=light_block.header.validators_hash,
                next_validators_hash=light_block.header.next_validators_hash,
                trusted_at=datetime.now(timezone.utc),
                provider=light_block.provider
            )
            trusted_state.append(trusted_header)
        
        return trusted_state
    
    async def import_trusted_state(self, headers: List[TrustedHeader]):
        """Import trusted headers from exported state."""
        for trusted_header in headers:
            # Convert TrustedHeader back to LightBlock (minimal)
            light_block = LightBlock(
                header=trusted_header.header,
                commit=None,  # Not needed for verification
                validators=None,  # Not needed for verification
                provider=trusted_header.provider
            )
            
            height = trusted_header.header.height
            self._trusted_headers[height] = light_block
            
            if self._latest_height is None or height > self._latest_height:
                self._latest_height = height
        
        # Update verified range
        if self._trusted_headers:
            heights = list(self._trusted_headers.keys())
            self._verified_height_range = (min(heights), max(heights))
        
        logger.info(f"Imported {len(headers)} trusted headers")
    
    async def get_latest_height(self) -> Optional[int]:
        """Get the latest verified height."""
        return self._latest_height
    
    async def get_verified_height_range(self) -> Optional[Tuple[int, int]]:
        """Get the range of verified heights (min, max)."""
        return self._verified_height_range
    
    async def is_height_verified(self, height: int) -> bool:
        """Check if a specific height has been verified."""
        return height in self._trusted_headers
    
    # Private methods
    
    def _find_best_trusted_header(self, target_height: int) -> Optional[LightBlock]:
        """Find the best trusted header for verifying target height."""
        if not self._trusted_headers:
            return None
        
        # Find the highest trusted header below target height
        candidates = [(h, header) for h, header in self._trusted_headers.items() if h < target_height]
        
        if candidates:
            best_height, best_header = max(candidates, key=lambda x: x[0])
            return best_header
        
        # If target is lower than all trusted headers, use the lowest
        min_height = min(self._trusted_headers.keys())
        return self._trusted_headers[min_height]
    
    def _add_trusted_header(self, header: LightBlock):
        """Add a verified header to the trusted set."""
        height = header.header.height
        self._trusted_headers[height] = header
        
        if self._latest_height is None or height > self._latest_height:
            self._latest_height = height
        
        # Update verified range
        if self._verified_height_range is None:
            self._verified_height_range = (height, height)
        else:
            min_height, max_height = self._verified_height_range
            self._verified_height_range = (
                min(min_height, height),
                max(max_height, height)
            )
        
        logger.debug(f"Added trusted header at height {height}")
    
    async def _sync_loop(self):
        """Background sync loop for automatic header updates."""
        while True:
            try:
                await asyncio.sleep(self.config.sync_interval_secs)
                await self.sync_to_latest()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Sync loop error: {e}")
    
    async def _fetch_header_from_validators(self, height: int) -> Optional[LightBlock]:
        """Fetch header from validators with consensus verification."""
        headers = []
        
        # Query multiple validators
        for endpoint in self.config.validator_endpoints:
            try:
                header = await self._fetch_header_from_endpoint(endpoint, height)
                if header:
                    headers.append((endpoint, header))
            except Exception as e:
                logger.debug(f"Failed to fetch header from {endpoint}: {e}")
        
        if len(headers) < self.config.min_validators_for_consensus:
            logger.warning(f"Only {len(headers)} validators responded, need {self.config.min_validators_for_consensus}")
            return None
        
        # Find consensus header (majority agreement)
        return self._find_consensus_header(headers)
    
    async def _fetch_header_from_endpoint(self, endpoint: str, height: int) -> Optional[LightBlock]:
        """Fetch header from a specific validator endpoint."""
        url = f"{endpoint}/block"
        params = {"height": str(height)} if height > 0 else {}
        
        async with self._session.get(url, params=params) as response:
            if response.status != 200:
                raise Exception(f"HTTP {response.status}")
            
            data = await response.json()
            
            if 'result' not in data or 'block' not in data['result']:
                raise Exception("Invalid response format")
            
            block_data = data['result']['block']
            return LightBlock.from_dict(block_data, provider=endpoint)
    
    async def _get_latest_height_from_validators(self) -> Optional[int]:
        """Get latest height from validators."""
        heights = []
        
        for endpoint in self.config.validator_endpoints:
            try:
                header = await self._fetch_header_from_endpoint(endpoint, 0)  # 0 = latest
                if header:
                    heights.append(header.header.height)
            except Exception as e:
                logger.debug(f"Failed to get latest height from {endpoint}: {e}")
        
        if not heights:
            return None
        
        # Return the most common height (consensus)
        from collections import Counter
        height_counts = Counter(heights)
        most_common_height, count = height_counts.most_common(1)[0]
        
        if count >= self.config.min_validators_for_consensus:
            return most_common_height
        
        return None
    
    def _find_consensus_header(self, headers: List[Tuple[str, LightBlock]]) -> Optional[LightBlock]:
        """Find consensus header from multiple validator responses."""
        # Group by header hash (simplified - should use full header comparison)
        from collections import defaultdict
        
        header_groups = defaultdict(list)
        
        for endpoint, header in headers:
            # Use app_hash as identifier (could use full header hash)
            key = header.header.app_hash.hex()
            header_groups[key].append((endpoint, header))
        
        # Find the group with most validators
        largest_group = max(header_groups.values(), key=len)
        
        if len(largest_group) >= self.config.min_validators_for_consensus:
            # Return the first header from the consensus group
            return largest_group[0][1]
        
        return None