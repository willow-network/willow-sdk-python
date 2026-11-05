"""
Consensus Client Implementation

Provides direct transaction broadcasting to CometBFT consensus layer.
"""

import asyncio
import aiohttp
import base64
import json
import time
from typing import Callable, Optional, Dict, Any, List, Tuple
import logging

from .. import _body
from ..auth import _key_algorithm, sign_message, SignatureAlgorithm
from ..errors import (
    NonceWindowFullError, ResponseEncodingError, ResponseTooLargeError, TransactionError,
)
from ..nonces import (
    FREE, HELD, UNKNOWN, USED, InterruptedWrite, NonceTracker, already_in_cache, refusal_outcome,
)
from ..signed_messages import did_document_body
from .types import (
    RegisterDidTx, RegisterSubgroveTx, TransferTx, DataStoreTx,
    StoreFileManifestTx, DeleteFileManifestTx, DeregisterSubgroveTx,
    BroadcastResult, TransactionStatus, ConsensusConfig, ConsensusError,
    create_transaction_wrapper, create_sign_message, Transaction
)

logger = logging.getLogger(__name__)

def _tx_hash_bytes(tx_hash: str) -> bytes:
    """A transaction hash's bytes, from hex with or without ``0x``.

    Raises:
        ValueError: It isn't hex.
    """
    if not isinstance(tx_hash, str):
        raise ValueError(f"a transaction hash is hex text, not {type(tx_hash).__name__}")
    text = tx_hash[2:] if tx_hash.startswith(("0x", "0X")) else tx_hash
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise ValueError(f"a transaction hash is hex: {tx_hash!r}") from None


# Transport failures before a request is sent: it never reached the API.
_NEVER_SENT = tuple(
    t for t in (
        aiohttp.ClientConnectorError,
        getattr(aiohttp, "ConnectionTimeoutError", None),
        aiohttp.InvalidURL,
    ) if t is not None
)


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
        #: Writes cancelled after they were signed, while their submission
        #: was in flight, keyed by ``(did, nonce)`` (see ``InterruptedWrite``
        #: and ``resubmit``).
        self.interrupted_writes: Dict[Tuple[str, int], InterruptedWrite] = {}
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
    
    async def start(self):
        """Start the consensus client."""
        self._session = _body.aiohttp_session(
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
        algorithm: Optional[SignatureAlgorithm] = None,
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
            algorithm: The key's algorithm. Defaults to the one the
                document's key type names (``Ed25519VerificationKey2018`` or
                ``EcdsaSecp256k1VerificationKey2019``), else "Ed25519".

        Returns:
            BroadcastResult with transaction status
        """
        algorithm = algorithm or _key_algorithm(did_document_body(did_document), public_key_id) or "Ed25519"
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
            schema: The subgrove's schema, as JSON text: for a data or file
                subgrove, the node's ``SchemaDefinition`` (``version``,
                ``fields`` mapping each name to "string", "number",
                "boolean", "array", "object", or "bytes", and
                ``required_fields``)
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
            ValueError, TypeError: A field is missing or out of range, the
                subgrove ID or owner DID holds a line break, or, for a data or
                file subgrove, the subgrove ID is not one the node takes, the
                admins, writers, or free readers aren't DIDs, or the schema
                does not parse as the node's ``SchemaDefinition`` (or
                declares indexes), or a private data subgrove's
                ``initial_owner_key_grant`` is not key epoch 0 to the owner;
                nothing is sent.
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
        Get the status of a transaction, as the consensus RPC's ``tx``
        method answers it (its word: nothing in the answer is verified).

        Args:
            tx_hash: Transaction hash, as hex (``0x`` optional): the
                ``tx_hash`` a submission answers

        Returns:
            TransactionStatus enum value: ``NOT_FOUND`` while the RPC has no
            such transaction in a block (or can't be read)

        Raises:
            ValueError: ``tx_hash`` isn't hex. Nothing is sent.
        """
        hash_bytes = _tx_hash_bytes(tx_hash)
        try:
            # Query transaction from CometBFT
            result = await self._query_transaction(hash_bytes)
            
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
            tx_hash: Transaction hash to wait for, as hex (see
                ``get_transaction_status``)
            timeout_secs: Maximum time to wait
            poll_interval: How often to poll for status

        Returns:
            Final TransactionStatus

        Raises:
            ValueError: ``tx_hash`` isn't hex. Nothing is sent.
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
        says the nonce is held by a pending transaction, already used, or
        spent. The write is never signed again under another nonce: a
        refusal can follow from this very transaction having reached the
        node (an earlier attempt failed in transit, or an API passed it on
        and answered that its nonce is used), and a second copy under
        another nonce would run it twice. A refusal that the nonce is used
        raises (a RegisterDid's returns the refused result); one that leaves
        open whether it reached the node carries ``transaction``, for
        ``resubmit``. See ``_broadcast_signed``.

        ``algorithm`` selects the signing algorithm. It must be supplied by the
        caller because the self-certifying DID no longer encodes it; it cannot
        be recovered from the transaction's ``owner_did``.

        Raises:
            ConsensusError: The submission failed in transit, or CheckTx
                refused it because its nonce is already used, at or below
                the base, or spent: some transaction used the nonce, which
                may be this one, so read what the write wrote before sending
                it again. It carries the ``did`` and ``nonce``, and the
                signed ``transaction`` when it may have reached the node or
                its nonce is used.
        """
        # Refuse what can't be signed (a line break, a field out of range)
        # before taking a nonce.
        create_sign_message(tx_type, transaction)
        if tx_type == "RegisterDid":
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
        nonce = transaction.nonce
        result = await self._broadcast_signed(signer, nonce, tx_wrapper)
        if not getattr(result, "_nonce_used", False) or tx_type == "RegisterDid":
            return result
        how = (
            "an earlier attempt of this transaction failed in transit and may have landed under it"
            if result.resent
            else "some transaction used it, which may be this one"
        )
        error = ConsensusError(
            f"nonce {nonce} of {signer} is used ({result.raw_log}): {how}, so it was not signed "
            f"again under another nonce; read what it wrote before sending it again"
        )
        error.did, error.nonce, error.transaction = signer, nonce, tx_wrapper
        error._handout = self._nonces.handout(signer, nonce)  # type: ignore[attr-defined]
        raise error

    async def _broadcast_signed(
        self, did: str, nonce: int, transaction: Dict[str, Any], resubmission: bool = False
    ) -> BroadcastResult:
        """Broadcast a transaction signed under ``nonce`` of ``did``, and
        record what its answer leaves the nonce as.

        Its retries send the same bytes, renewing the nonce's lease before
        each. When every attempt fails in transit, the nonce is given back if
        none can have left (the connection was refused or timed out) and this
        is not a ``resubmission``; otherwise it stays taken until its lease
        runs out, and the ``ConsensusError`` carries the signed
        ``transaction``. A gateway error with no CheckTx answer keeps the
        nonce too, and its result carries ``transaction``. So does any
        refusal other than the nonce being used once these bytes may have
        reached the node before (an earlier attempt failed in transit, or
        this is a ``resubmission``): the earlier copy may be pending or have
        landed, whatever the refusal says. A cancellation records the write
        in ``interrupted_writes`` before it propagates.
        """
        handout = self._nonces.handout(did, nonce)
        renew: Callable[[], bool] = lambda: self._nonces.reclaim(did, nonce, handout)
        try:
            result = await self._broadcast_transaction(transaction, renew)
        except asyncio.CancelledError as e:
            write = InterruptedWrite(did, nonce, transaction, handout)
            self.interrupted_writes[(did, nonce)] = write
            e.did, e.nonce, e.transaction = did, nonce, transaction  # type: ignore[attr-defined]
            e._handout = handout  # type: ignore[attr-defined]
            raise
        except ConsensusError as e:
            e.did, e.nonce = did, nonce
            if getattr(e, "_sent", True) or resubmission:
                e.transaction = transaction
                e._handout = handout  # type: ignore[attr-defined]
            else:
                self._nonces.release(did, nonce, handout)
            raise
        result.did, result.nonce = did, nonce
        if result.success:
            return result
        outcome = refusal_outcome(
            TransactionError(result.error_message or "", error_code=result.error_code, raw_log=result.raw_log),
            result.http_status,
            nonce,
        )
        if (result.resent or resubmission) and outcome in (FREE, HELD):
            outcome = UNKNOWN
        self._nonces.settle(did, nonce, outcome, handout)
        if outcome == UNKNOWN:
            result.transaction = transaction
            result._handout = handout  # type: ignore[attr-defined]
        result._nonce_used = outcome == USED  # type: ignore[attr-defined]
        return result

    async def resubmit(self, failed: Any) -> BroadcastResult:
        """Send again, under its own nonce, a write that may have reached the node.

        ``failed`` is the ``ConsensusError`` a write raised, or the
        ``BroadcastResult`` it returned, with its ``transaction`` set: it
        failed in transit, or the API answered a gateway error, so the
        transaction may have reached the node. It can also be an
        ``InterruptedWrite`` from ``interrupted_writes`` (a write cancelled
        while its submission was in flight); resubmitting a write removes it
        from there. This sends those exact bytes again: whichever copy lands
        first spends the nonce, and the other is refused, so the write runs
        at most once. Don't send it again as a new write: under another nonce
        both copies could run.

        Returns:
            The ``BroadcastResult``. When the node already holds an identical
            copy ("tx already exists in cache"), that counts as success, with
            no ``tx_hash``. A refusal that its nonce is already used, or at or
            below the base, means some transaction used that nonce: this
            write's earlier copy, or another one signed by the same DID
            elsewhere. Read what the write wrote to learn whether it took
            effect; a copy refused in its block spends its nonce too. Any
            other refusal leaves the result's ``transaction`` set and the
            nonce taken: CheckTx checks some rules before the nonce, so it
            can follow from the earlier copy having landed, or the earlier
            copy may still be pending.

        Raises:
            ValueError: ``failed`` carries no ``transaction``.
            ConsensusError: This client has handed the nonce to another write
                since (``resubmit`` came after the 120 s lease ran out),
                whether or not that write has landed, so nothing is sent;
                or it failed in transit again (``resubmit`` it again).
        """
        transaction = getattr(failed, "transaction", None)
        did = getattr(failed, "did", None)
        nonce = getattr(failed, "nonce", None)
        if (
            not isinstance(transaction, dict)
            or not isinstance(did, str)
            or isinstance(nonce, bool)
            or not isinstance(nonce, int)
        ):
            raise ValueError(
                "resubmit takes the error or result of a write that may have reached "
                "the node (its transaction set)"
            )
        interrupted = self.interrupted_writes.get((did, nonce))
        if interrupted is not None and interrupted.transaction == transaction:
            del self.interrupted_writes[(did, nonce)]
        if not self._nonces.reclaim(did, nonce, getattr(failed, "_handout", None)):
            raise ConsensusError(
                f"nonce {nonce} of {did} was handed to another write after this one's "
                f"lease ran out, so it can't be resubmitted under it; read what the write "
                f"wrote to learn whether it took effect"
            )
        failed._handout = self._nonces.handout(did, nonce)
        return await self._broadcast_signed(did, nonce, transaction, resubmission=True)

    async def _broadcast_transaction(
        self, transaction: Dict[str, Any], renew: Optional[Callable[[], bool]] = None
    ) -> BroadcastResult:
        """Submit a transaction via the API server's /tx/submit endpoint.

        The chain's on-the-wire format is bincode. The API server accepts
        JSON, bincode-encodes it, and forwards to CometBFT's
        broadcast_tx_sync — so SDKs can keep sending JSON without a
        per-language bincode encoder.

        An attempt that fails in transit is retried with the same bytes, up to
        ``max_retries`` times. CometBFT's "tx already exists in cache" (it
        holds these exact bytes, which CheckTx admitted) counts as success.
        The result's ``resent`` says whether an earlier attempt failed after
        it may have reached the node. ``renew``, called before each attempt,
        renews the nonce's lease; when it answers ``False`` (the nonce went
        to another write) no further attempt is made.

        Raises:
            ConsensusError: Every attempt failed in transit, or ``renew``
                stopped the retries. Its ``_sent`` is whether any attempt may
                have reached the node.
        """
        if not self.config.api_url:
            error = ConsensusError(
                "api_url is required for transaction submission. Set it in the SDK config."
            )
            error._sent = False  # type: ignore[attr-defined]
            raise error

        url = f"{self.config.api_url.rstrip('/')}/tx/submit"
        maybe_sent = False
        for attempt in range(self.config.max_retries + 1):
            if renew is not None and not renew():
                error = ConsensusError(
                    "tx submit stopped: the nonce's lease ran out and it was handed to another write"
                )
                error._sent = maybe_sent  # type: ignore[attr-defined]
                raise error
            try:
                async with self._session.post(url, json=transaction) as response:
                    status = response.status
                    raw = await _body.read_aiohttp(response, _body.SMALL)
                    try:
                        body = json.loads(raw)
                    except (ValueError, RecursionError):
                        # A body the API refused to decode answers in plain text.
                        body = None
                    if not isinstance(body, dict):
                        text = raw.decode("utf-8", "replace").strip()
                        msg = text or f"HTTP {status}"
                        return BroadcastResult(
                            success=False, error_message=msg, raw_log=msg,
                            http_status=status, resent=maybe_sent,
                        )
                    if not status == 200 or not body.get('success') or 'data' not in body:
                        msg = body.get('error') or f"HTTP {status}"
                        return BroadcastResult(
                            success=already_in_cache(msg),
                            error_message=None if already_in_cache(msg) else msg,
                            raw_log=msg,
                            http_status=status,
                            resent=maybe_sent,
                        )

                    data = body['data']
                    code = data.get('code', 0)
                    return BroadcastResult(
                        success=code == 0,
                        tx_hash=data.get('tx_hash'),
                        error_code=code if code != 0 else None,
                        error_message=data.get('log') if code != 0 else None,
                        raw_log=data.get('log'),
                        http_status=status,
                        resent=maybe_sent,
                    )
            except Exception as e:
                maybe_sent = maybe_sent or not isinstance(e, _NEVER_SENT)
                if attempt == self.config.max_retries:
                    error = ConsensusError(
                        f"tx submit failed after {self.config.max_retries + 1} attempts: {e}"
                    )
                    error._sent = maybe_sent  # type: ignore[attr-defined]
                    raise error from e
                logger.warning(f"tx submit attempt {attempt + 1} failed: {e}")

        error = ConsensusError("tx submit made no attempt: max_retries is negative")
        error._sent = False  # type: ignore[attr-defined]
        raise error
    
    async def _rpc_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make a JSON-RPC request to CometBFT, reading at most
        ``willow._body.TX`` bytes of a ``tx`` answer and ``SMALL`` of any
        other."""
        limit = _body.TX if method == "tx" else _body.SMALL
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
                        data = await _body.json_aiohttp(response, limit)

                        if 'error' in data:
                            raise ConsensusError(f"RPC error: {data['error']}")
                        
                        return data.get('result', {})
                    else:
                        error_text = (await _body.read_aiohttp(response, _body.SMALL)).decode("utf-8", "replace")
                        raise ConsensusError(f"HTTP {response.status}: {error_text}")
                        
            except Exception as e:
                if attempt == self.config.max_retries:
                    raise ConsensusError(f"RPC request failed after {self.config.max_retries + 1} attempts: {e}")
                
                logger.warning(f"RPC attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(self.config.retry_delay_secs * (attempt + 1))
    
    async def _query_transaction(self, tx_hash: bytes) -> Optional[Dict[str, Any]]:
        """The consensus RPC's ``tx`` answer for the transaction whose hash is
        ``tx_hash``; ``None`` when it answers none, or one for another hash.

        A JSON-RPC body carries the ``hash`` parameter, a ``[]byte``, in
        base64 (only the URI form, ``/tx?hash=0x...``, takes hex)."""
        try:
            result = await self._rpc_request(
                "tx", {"hash": base64.b64encode(tx_hash).decode("ascii"), "prove": False}
            )
        except Exception:
            return None
        answered = result.get("hash") if isinstance(result, dict) else None
        try:
            if not isinstance(answered, str) or bytes.fromhex(answered) != tx_hash:
                return None
        except ValueError:
            return None
        return result
    
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

                data = await _body.json_aiohttp(response, _body.SMALL)

                if not data.get('success') or 'data' not in data:
                    raise ConsensusError(data.get('error', 'Failed to fetch nonce'))

                nonce = data['data'].get('nonce') if isinstance(data['data'], dict) else None
                if isinstance(nonce, bool) or not isinstance(nonce, int):
                    raise ConsensusError(f"The API answered no nonce for {did}")
                return nonce
        except (aiohttp.ClientError, ResponseEncodingError, ResponseTooLargeError, ValueError) as e:
            raise ConsensusError(f"Failed to fetch nonce: {e}")