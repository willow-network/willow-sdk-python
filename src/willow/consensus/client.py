"""
Consensus Client Implementation

Provides direct transaction broadcasting to CometBFT consensus layer.
"""

import asyncio
import aiohttp
import json
import time
from typing import Optional, Dict, Any, List, Tuple
import logging

from ..auth import sign_message, SignatureAlgorithm
from ..errors import NonceWindowFullError, TransactionError
from ..nonces import USED, WINDOW, NonceTracker, refusal_outcome
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
        # The nonces handed out per signing DID (see ``willow.nonces``).
        self._nonces = NonceTracker()
        self._nonce_poll_interval = 1.0
        self._nonce_wait_timeout = 60.0
    
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
        public_key_id: str,
        algorithm: SignatureAlgorithm = "Ed25519",
    ) -> BroadcastResult:
        """
        Register a DID on the blockchain.

        The chain's RegisterDid check requires ``did_document['id']`` to be the
        self-certifying id derived from the public key (see ``derive_did``); a
        chosen or legacy-format id is rejected. Since the id is bound to the
        key, it must be pre-funded before registration: transfer >= the
        registration fee to the derived id first (see ``transfer``), then call
        this method so the fee is paid from that balance.

        The node takes a registration only under nonce 1, so it is signed
        under nonce 1.

        Args:
            did_document: DID document to register (self-certifying ``id``)
            private_key: Private key for signing (hex-encoded)
            public_key_id: Public key identifier in the DID document

        Returns:
            BroadcastResult with transaction status
        """
        tx = RegisterDidTx(
            did_document=did_document,
            signature="",  # Will be filled by signing
            public_key_id=public_key_id,
            nonce=1,
        )
        return await self._sign_and_broadcast(
            "RegisterDid", tx, private_key, algorithm, signer=did_document.get('id', '')
        )
    
    async def register_subgrove(
        self,
        subgrove_id: str,
        schema: str,
        owner_did: str,
        private_key: str,
        public_key_id: str,
        mode: Optional[Dict[str, Any]] = None,
        algorithm: SignatureAlgorithm = "Ed25519",
        *,
        name: Optional[str] = None,
        description: str = "",
        admins: Optional[List[str]] = None,
        initial_funding: Optional[int] = None,
        required_tee: Optional[str] = None,
        privacy: Optional[Any] = None,
        initial_owner_key_grant: Optional[Any] = None,
        template_config: Optional[Dict[str, Any]] = None,
        confirmation_depth: int = 0,
        cryptographic_completeness: bool = False,
    ) -> BroadcastResult:
        """
        Register a subgrove (dataset) on the blockchain.

        The transaction carries every field explicitly and is signed over
        ``register_subgrove_message``, whose ``Config`` is the SHA-256 of its
        bincode with an empty signature, so the signature binds every field
        and the nonce.

        Args:
            subgrove_id: Unique subgrove identifier
            schema: The subgrove's schema, as JSON text
            owner_did: DID of the subgrove owner
            private_key: Private key for signing (hex-encoded)
            public_key_id: Public key identifier in the DID document
            mode: SubgroveMode in its JSON form, e.g.
                  {"DataStorage": {"name": "...", "writers": [...], "free_readers": [...]}},
                  {"FileStorage": {...}}, or
                  {"BlockchainIndexing": {"manifest_content": [...], ...}}.
                  Defaults to DataStorage with no name, writers, or free readers.
            name: The subgrove's name; defaults to the mode's name
            description, admins, initial_funding, required_tee, privacy,
            initial_owner_key_grant, template_config, confirmation_depth,
            cryptographic_completeness: The transaction's other fields

        Returns:
            BroadcastResult with transaction status

        Raises:
            ValueError, TypeError: A field is missing or out of range, or the
                subgrove ID or owner DID holds a line break; nothing is sent.
        """
        tx = RegisterSubgroveTx(
            subgrove_id=subgrove_id,
            schema=schema,
            owner_did=owner_did,
            mode=mode,
            signature="",
            public_key_id=public_key_id,
            name=name,
            description=description,
            admins=list(admins or []),
            initial_funding=initial_funding,
            required_tee=required_tee,
            privacy=privacy,
            initial_owner_key_grant=initial_owner_key_grant,
            template_config=template_config,
            confirmation_depth=confirmation_depth,
            cryptographic_completeness=cryptographic_completeness,
        )
        return await self._sign_and_broadcast(
            "RegisterSubgrove", tx, private_key, algorithm, signer=owner_did
        )
    
    async def transfer(
        self,
        from_did: str,
        to_did: str,
        amount: int,
        private_key: str,
        public_key_id: str,
        memo: Optional[str] = None,
        algorithm: SignatureAlgorithm = "Ed25519",
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
        )

        return await self._sign_and_broadcast("Transfer", tx, private_key, algorithm, signer=from_did)
    
    async def store_data(
        self,
        subgrove_id: str,
        key: str,
        data: Dict[str, Any],
        owner_did: str,
        private_key: str,
        public_key_id: str,
        algorithm: SignatureAlgorithm = "Ed25519",
    ) -> BroadcastResult:
        """
        Store data on the blockchain.
        
        Args:
            subgrove_id: Subgrove ID
            key: Data key
            data: Data to store, a JSON object (``dict``)
            owner_did: DID of the data owner
            private_key: Private key for signing (hex-encoded)
            public_key_id: Public key identifier in the DID document
            
        Returns:
            BroadcastResult with transaction status

        Raises:
            TypeError: ``data`` is not a ``dict``: the node stores only a JSON
                object. Nothing is sent.
        """
        if not isinstance(data, dict):
            raise TypeError("data must be a JSON object (a dict)")
        tx = DataStoreTx(
            subgrove_id=subgrove_id,
            key=key,
            data=json.dumps(data, separators=(',', ':'), sort_keys=True, allow_nan=False),
            owner_did=owner_did,
            signature="",
            public_key_id=public_key_id,
        )

        return await self._sign_and_broadcast("DataStore", tx, private_key, algorithm, signer=owner_did)

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
        algorithm: SignatureAlgorithm = "Ed25519",
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
        )

        return await self._sign_and_broadcast(
            "StoreFileManifest", tx, private_key, algorithm, signer=owner_did
        )

    async def delete_file_manifest(
        self,
        subgrove_id: str,
        file_key: str,
        owner_did: str,
        private_key: str,
        public_key_id: str,
        algorithm: SignatureAlgorithm = "Ed25519",
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
        )

        return await self._sign_and_broadcast(
            "DeleteFileManifest", tx, private_key, algorithm, signer=owner_did
        )

    async def deregister_subgrove(
        self,
        subgrove_id: str,
        owner_did: str,
        private_key: str,
        public_key_id: str,
        algorithm: SignatureAlgorithm = "Ed25519",
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
        )

        return await self._sign_and_broadcast(
            "DeregisterSubgrove", tx, private_key, algorithm, signer=owner_did
        )

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
        private_key: str,
        algorithm: SignatureAlgorithm = "Ed25519",
        *,
        signer: str,
    ) -> BroadcastResult:
        """Sign a transaction under a nonce of ``signer``'s and broadcast it.

        The nonce is the lowest one in the node's window this client hasn't
        handed out (see ``willow.nonces``); RegisterDid signs nonce 1. A
        transaction CheckTx refuses gives its nonce back, unless the refusal
        says the nonce is held by a pending transaction or already used. When
        it is already used, no transaction under it can run, so it is signed
        again under a fresh nonce.

        ``algorithm`` selects the signing algorithm. It must be supplied by the
        caller because the self-certifying DID no longer encodes it; it cannot
        be recovered from the transaction's ``owner_did``.
        """
        # Refuse what can't be signed (a line break, a field out of range)
        # before taking a nonce.
        create_sign_message(tx_type, transaction)
        fixed_nonce = tx_type == "RegisterDid"
        result: Optional[BroadcastResult] = None
        for _ in range(WINDOW):
            if fixed_nonce:
                self._nonces.hold(signer, transaction.nonce)
            else:
                transaction.nonce = await self._take_nonce(signer)
            try:
                transaction.signature = sign_message(
                    create_sign_message(tx_type, transaction), private_key, algorithm
                )
                tx_wrapper = create_transaction_wrapper(tx_type, transaction)
            except BaseException:
                self._nonces.release(signer, transaction.nonce)
                raise
            # A submission that raises may have reached the node: its nonce
            # stays taken until its lease runs out.
            result = await self._broadcast_transaction(tx_wrapper)
            if result.success:
                return result
            outcome = refusal_outcome(TransactionError(
                result.error_message or "", error_code=result.error_code, raw_log=result.raw_log
            ))
            self._nonces.settle(signer, transaction.nonce, outcome)
            if outcome != USED or fixed_nonce:
                return result
        return result

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
                    try:
                        body = await response.json(content_type=None)
                    except ValueError:
                        # A body the API refused to decode answers in plain text.
                        body = None
                    if not isinstance(body, dict):
                        text = (await response.text()).strip()
                        msg = text or f"HTTP {response.status}"
                        return BroadcastResult(success=False, error_message=msg, raw_log=msg)
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
    
    async def _take_nonce(self, did: str) -> int:
        """A nonce for ``did``'s next transaction: the lowest one in the
        node's window this client hasn't handed out. While every one is
        taken, waits for the account's base to advance.

        Raises:
            NonceWindowFullError: The window stayed full for
                ``_nonce_wait_timeout`` seconds.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._nonce_wait_timeout
        while True:
            nonce = self._nonces.take(did, await self._get_account_nonce(did))
            if nonce is not None:
                return nonce
            if loop.time() >= deadline:
                raise NonceWindowFullError(
                    f"every nonce the node accepts for {did} is taken by a transaction "
                    f"that hasn't landed; wait for earlier ones to land"
                )
            await asyncio.sleep(self._nonce_poll_interval)

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
            raise ConsensusError(
                "api_url is required to read the account nonce. Set it in the SDK config."
            )

        from urllib.parse import quote
        url = f"{self.config.api_url}/account/{quote(did, safe='')}/nonce"

        try:
            async with self._session.get(url) as response:
                if response.status != 200:
                    raise ConsensusError(f"Failed to fetch nonce: HTTP {response.status}")

                data = await response.json()

                if not data.get('success') or 'data' not in data:
                    raise ConsensusError(data.get('error', 'Failed to fetch nonce'))

                nonce = data['data'].get('nonce') if isinstance(data['data'], dict) else None
                if isinstance(nonce, bool) or not isinstance(nonce, int):
                    raise ConsensusError(f"The API answered no nonce for {did}")
                return nonce
        except aiohttp.ClientError as e:
            raise ConsensusError(f"Failed to fetch nonce: {e}")