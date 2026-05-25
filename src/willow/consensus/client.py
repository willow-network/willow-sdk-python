"""
Consensus Client Implementation

Provides direct transaction broadcasting to CometBFT consensus layer.
"""

import asyncio
import aiohttp
import json
import time
from typing import Optional, Dict, Any, Tuple
import logging

from ..auth import sign_message, detect_algorithm_from_did
from .types import (
    RegisterDidTx, RegisterSubgroveTx, TransferTx, DataStoreTx,
    StoreFileManifestTx, DeleteFileManifestTx, DeregisterSubgroveTx,
    BroadcastResult, TransactionStatus, ConsensusConfig, ConsensusError,
    create_transaction_wrapper, create_sign_message, Transaction
)

logger = logging.getLogger(__name__)


class ConsensusClient:
    """
    CometBFT consensus client for direct transaction broadcasting.
    
    Enables full-featured blockchain interactions without relying on data nodes.
    """
    
    def __init__(self, config: ConsensusConfig):
        """Initialize consensus client with configuration."""
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._nonce_cache: Dict[str, int] = {}
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
    
    async def start(self):
        """Start the consensus client."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.request_timeout_secs)
        )
        logger.info("Consensus client started")
    
    async def stop(self):
        """Stop the consensus client and cleanup resources."""
        if self._session:
            await self._session.close()
        logger.info("Consensus client stopped")
    
    async def register_did(
        self,
        did_document: Dict[str, Any],
        private_key: str,
        public_key_id: str
    ) -> BroadcastResult:
        """
        Register a DID on the blockchain.
        
        Args:
            did_document: DID document to register
            private_key: Private key for signing (hex-encoded)
            public_key_id: Public key identifier in the DID document
            
        Returns:
            BroadcastResult with transaction status
        """
        # Create transaction
        tx = RegisterDidTx(
            did_document=did_document,
            signature="",  # Will be filled by signing
            public_key_id=public_key_id,
            nonce=await self._get_next_nonce(did_document.get('id', ''))
        )
        
        # Sign and broadcast
        return await self._sign_and_broadcast("RegisterDid", tx, private_key)
    
    async def register_subgrove(
        self,
        subgrove_id: str,
        schema: str,
        owner_did: str,
        private_key: str,
        public_key_id: str,
        mode: Optional[Dict[str, Any]] = None
    ) -> BroadcastResult:
        """
        Register a subgrove (dataset) on the blockchain.

        Args:
            subgrove_id: Unique subgrove identifier
            schema: JSON schema definition
            owner_did: DID of the subgrove owner
            private_key: Private key for signing (hex-encoded)
            public_key_id: Public key identifier in the DID document
            mode: SubgroveMode dict, e.g. {"DataStorage": {"name": "...", ...}}
                  or {"BlockchainIndexing": {"manifest_content": [...], ...}}.
                  Defaults to DataStorage when omitted.

        Returns:
            BroadcastResult with transaction status
        """
        tx = RegisterSubgroveTx(
            subgrove_id=subgrove_id,
            schema=schema,
            owner_did=owner_did,
            mode=mode,
            signature="",
            public_key_id=public_key_id,
            nonce=await self._get_next_nonce(owner_did)
        )

        return await self._sign_and_broadcast("RegisterSubgrove", tx, private_key)
    
    async def transfer(
        self,
        from_did: str,
        to_did: str,
        amount: int,
        private_key: str,
        public_key_id: str,
        memo: Optional[str] = None
    ) -> BroadcastResult:
        """
        Transfer tokens between DIDs.
        
        Args:
            from_did: Sender DID
            to_did: Recipient DID
            amount: Amount to transfer (in smallest unit)
            private_key: Private key for signing (hex-encoded)
            public_key_id: Public key identifier in the DID document
            memo: Optional transfer memo
            
        Returns:
            BroadcastResult with transaction status
        """
        tx = TransferTx(
            from_did=from_did,
            to_did=to_did,
            amount=amount,
            memo=memo,
            signature="",
            public_key_id=public_key_id,
            nonce=await self._get_next_nonce(from_did)
        )
        
        return await self._sign_and_broadcast("Transfer", tx, private_key)
    
    async def store_data(
        self,
        subgrove_id: str,
        key: str,
        data: Dict[str, Any],
        owner_did: str,
        private_key: str,
        public_key_id: str
    ) -> BroadcastResult:
        """
        Store data on the blockchain.
        
        Args:
            subgrove_id: Subgrove ID
            key: Data key
            data: Data to store
            owner_did: DID of the data owner
            private_key: Private key for signing (hex-encoded)
            public_key_id: Public key identifier in the DID document
            
        Returns:
            BroadcastResult with transaction status
        """
        tx = DataStoreTx(
            subgrove_id=subgrove_id,
            key=key,
            data=json.dumps(data, separators=(',', ':'), sort_keys=True),
            owner_did=owner_did,
            signature="",
            public_key_id=public_key_id,
            nonce=await self._get_next_nonce(owner_did)
        )
        
        return await self._sign_and_broadcast("DataStore", tx, private_key)

    async def store_file_manifest(
        self,
        subgrove_id: str,
        file_key: str,
        filename: str,
        content_type: str,
        total_size: int,
        content_hash: str,
        chunk_count: int,
        chunk_size: int,
        chunk_merkle_root: str,
        owner_did: str,
        private_key: str,
        public_key_id: str,
    ) -> BroadcastResult:
        """
        Store a file manifest on the blockchain.

        Args:
            subgrove_id: Subgrove ID
            file_key: Unique key for the file
            filename: Original filename
            content_type: MIME content type
            total_size: Total file size in bytes
            content_hash: SHA-256 hash of the file content
            chunk_count: Number of chunks
            chunk_size: Size of each chunk in bytes
            chunk_merkle_root: Merkle root of chunk hashes
            owner_did: DID of the file owner
            private_key: Private key for signing (hex-encoded)
            public_key_id: Public key identifier in the DID document

        Returns:
            BroadcastResult with transaction status
        """
        tx = StoreFileManifestTx(
            subgrove_id=subgrove_id,
            file_key=file_key,
            filename=filename,
            content_type=content_type,
            total_size=total_size,
            content_hash=content_hash,
            chunk_count=chunk_count,
            chunk_size=chunk_size,
            chunk_merkle_root=chunk_merkle_root,
            owner_did=owner_did,
            signature="",
            public_key_id=public_key_id,
            nonce=await self._get_next_nonce(owner_did),
        )

        return await self._sign_and_broadcast("StoreFileManifest", tx, private_key)

    async def delete_file_manifest(
        self,
        subgrove_id: str,
        file_key: str,
        owner_did: str,
        private_key: str,
        public_key_id: str,
    ) -> BroadcastResult:
        """
        Delete a file manifest from the blockchain.

        Args:
            subgrove_id: Subgrove ID
            file_key: Key of the file to delete
            owner_did: DID of the file owner
            private_key: Private key for signing (hex-encoded)
            public_key_id: Public key identifier in the DID document

        Returns:
            BroadcastResult with transaction status
        """
        tx = DeleteFileManifestTx(
            subgrove_id=subgrove_id,
            file_key=file_key,
            owner_did=owner_did,
            signature="",
            public_key_id=public_key_id,
            nonce=await self._get_next_nonce(owner_did),
        )

        return await self._sign_and_broadcast("DeleteFileManifest", tx, private_key)

    async def deregister_subgrove(
        self,
        subgrove_id: str,
        owner_did: str,
        private_key: str,
        public_key_id: str,
    ) -> BroadcastResult:
        """
        Deregister (delete) a subgrove. Remaining funding is refunded to the owner.

        Args:
            subgrove_id: Subgrove to deregister
            owner_did: DID of the subgrove owner
            private_key: Private key for signing (hex-encoded)
            public_key_id: Public key identifier in the DID document

        Returns:
            BroadcastResult with transaction status
        """
        tx = DeregisterSubgroveTx(
            subgrove_id=subgrove_id,
            owner_did=owner_did,
            signature="",
            public_key_id=public_key_id,
            nonce=await self._get_next_nonce(owner_did),
        )

        return await self._sign_and_broadcast("DeregisterSubgrove", tx, private_key)

    async def get_transaction_status(self, tx_hash: str) -> TransactionStatus:
        """
        Get the status of a transaction.
        
        Args:
            tx_hash: Transaction hash
            
        Returns:
            TransactionStatus enum value
        """
        try:
            # Query transaction from CometBFT
            result = await self._query_transaction(tx_hash)
            
            if result is None:
                return TransactionStatus.NOT_FOUND
            
            # Check if transaction succeeded
            if result.get('tx_result', {}).get('code', 0) == 0:
                return TransactionStatus.SUCCESS
            else:
                return TransactionStatus.FAILED
                
        except Exception as e:
            logger.warning(f"Failed to get transaction status: {e}")
            return TransactionStatus.NOT_FOUND
    
    async def wait_for_transaction(
        self,
        tx_hash: str,
        timeout_secs: int = 60,
        poll_interval: float = 2.0
    ) -> TransactionStatus:
        """
        Wait for a transaction to be confirmed.
        
        Args:
            tx_hash: Transaction hash to wait for
            timeout_secs: Maximum time to wait
            poll_interval: How often to poll for status
            
        Returns:
            Final TransactionStatus
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout_secs:
            status = await self.get_transaction_status(tx_hash)
            
            if status in [TransactionStatus.SUCCESS, TransactionStatus.FAILED]:
                return status
            
            await asyncio.sleep(poll_interval)
        
        return TransactionStatus.PENDING
    
    async def get_chain_id(self) -> str:
        """Get the blockchain chain ID."""
        try:
            result = await self._rpc_request("status", {})
            return result['node_info']['network']
        except Exception as e:
            logger.warning(f"Failed to get chain ID: {e}")
            return self.config.chain_id
    
    async def get_latest_height(self) -> Optional[int]:
        """Get the latest blockchain height."""
        try:
            result = await self._rpc_request("status", {})
            return int(result['sync_info']['latest_block_height'])
        except Exception as e:
            logger.warning(f"Failed to get latest height: {e}")
            return None
    
    # Private methods
    
    async def _sign_and_broadcast(
        self,
        tx_type: str,
        transaction: Transaction,
        private_key: str
    ) -> BroadcastResult:
        """Sign a transaction and broadcast it."""
        # Create canonical message for signing
        sign_message_text = create_sign_message(tx_type, transaction)
        
        # Detect signature algorithm and sign
        algorithm = detect_algorithm_from_did(getattr(transaction, 'owner_did', ''))
        signature_hex = sign_message(sign_message_text, private_key, algorithm)
        
        # Update transaction with signature
        transaction.signature = signature_hex
        
        # Create transaction wrapper
        tx_wrapper = create_transaction_wrapper(tx_type, transaction)
        
        # Broadcast transaction
        return await self._broadcast_transaction(tx_wrapper)
    
    async def _broadcast_transaction(self, transaction: Dict[str, Any]) -> BroadcastResult:
        """Submit a transaction via the API server's /tx/submit endpoint.

        The chain's on-the-wire format is bincode. The API server accepts
        JSON, bincode-encodes it, and forwards to CometBFT's
        broadcast_tx_sync — so SDKs can keep sending JSON without a
        per-language bincode encoder.
        """
        if not self.config.api_url:
            raise ConsensusError(
                "api_url is required for transaction submission. Set it in the SDK config."
            )

        url = f"{self.config.api_url.rstrip('/')}/tx/submit"
        last_error: Optional[str] = None
        for attempt in range(self.config.max_retries + 1):
            try:
                async with self._session.post(url, json=transaction) as response:
                    body = await response.json()
                    if not response.status == 200 or not body.get('success') or 'data' not in body:
                        msg = body.get('error') or f"HTTP {response.status}"
                        return BroadcastResult(success=False, error_message=msg, raw_log=msg)

                    data = body['data']
                    code = data.get('code', 0)
                    return BroadcastResult(
                        success=code == 0,
                        tx_hash=data.get('tx_hash'),
                        error_code=code if code != 0 else None,
                        error_message=data.get('log') if code != 0 else None,
                        raw_log=data.get('log'),
                    )
            except Exception as e:
                last_error = str(e)
                if attempt == self.config.max_retries:
                    raise ConsensusError(
                        f"tx submit failed after {self.config.max_retries + 1} attempts: {e}"
                    )
                logger.warning(f"tx submit attempt {attempt + 1} failed: {e}")

        raise ConsensusError(f"tx submit exhausted retries: {last_error}")
    
    async def _rpc_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make a JSON-RPC request to CometBFT."""
        rpc_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }
        
        for attempt in range(self.config.max_retries + 1):
            try:
                async with self._session.post(
                    self.config.consensus_rpc_url,
                    json=rpc_request
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if 'error' in data:
                            raise ConsensusError(f"RPC error: {data['error']}")
                        
                        return data.get('result', {})
                    else:
                        error_text = await response.text()
                        raise ConsensusError(f"HTTP {response.status}: {error_text}")
                        
            except Exception as e:
                if attempt == self.config.max_retries:
                    raise ConsensusError(f"RPC request failed after {self.config.max_retries + 1} attempts: {e}")
                
                logger.warning(f"RPC attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(self.config.retry_delay_secs * (attempt + 1))
    
    async def _query_transaction(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Query a transaction by hash."""
        try:
            result = await self._rpc_request("tx", {"hash": tx_hash, "prove": False})
            return result
        except Exception:
            return None
    
    async def _get_next_nonce(self, did: str) -> int:
        """
        Get the next nonce for a DID.

        Fetches the current nonce from the blockchain and returns the next value.
        Falls back to in-memory cache if API is unavailable.
        """
        try:
            current_nonce = await self._get_account_nonce(did)
            next_nonce = current_nonce + 1
            self._nonce_cache[did] = next_nonce
            return next_nonce
        except Exception as e:
            # Fall back to cache if API unavailable
            logger.warning(f"Failed to fetch nonce from API, using cache: {e}")
            current_nonce = self._nonce_cache.get(did, 0)
            next_nonce = current_nonce + 1
            self._nonce_cache[did] = next_nonce
            return next_nonce

    async def _get_account_nonce(self, did: str) -> int:
        """
        Get the current nonce for an account from the blockchain.

        Args:
            did: The DID to get the nonce for

        Returns:
            Current nonce value from the blockchain

        Raises:
            ConsensusError: If nonce cannot be fetched
        """
        if not self.config.api_url:
            # No API URL configured, use cache
            return self._nonce_cache.get(did, 0)

        from urllib.parse import quote
        url = f"{self.config.api_url}/account/{quote(did, safe='')}/nonce"

        try:
            async with self._session.get(url) as response:
                if response.status != 200:
                    raise ConsensusError(f"Failed to fetch nonce: HTTP {response.status}")

                data = await response.json()

                if not data.get('success') or 'data' not in data:
                    raise ConsensusError(data.get('error', 'Failed to fetch nonce'))

                return data['data'].get('nonce', 0)
        except aiohttp.ClientError as e:
            raise ConsensusError(f"Failed to fetch nonce: {e}")