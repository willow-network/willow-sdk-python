"""Privacy operations for Willow SDK.

This module provides privacy-related functionality including encryption key
management for subgroves. Key grants allow subgrove owners to share encrypted
access with other DIDs, enabling privacy-preserving data storage where only
authorized parties can decrypt the stored data.

Typical workflow:
    1. Create a subgrove with privacy enabled
    2. Grant encryption keys to authorized DIDs via `grant_subgrove_key`
    3. Grantees retrieve their key grant via `get_my_key_grant`
    4. Rotate keys periodically via `rotate_subgrove_key`
    5. Revoke access when needed via `revoke_subgrove_key`
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from .consensus.types import GrantSubgroveKeyTx, RevokeSubgroveKeyTx, RotateSubgroveKeyTx
from .errors import WillowError
from .utils import require_auth

if TYPE_CHECKING:
    from .client import WillowClient

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================


class CommitmentFrequency:
    """How often the provider must publish state root commitments on-chain.

    Produces JSON matching Rust serde serialization:
    - ``CommitmentFrequency.every_update()`` → ``"EveryUpdate"``
    - ``CommitmentFrequency.every_n_blocks(10)`` → ``{"EveryNBlocks": 10}``
    - ``CommitmentFrequency.every_n_seconds(60)`` → ``{"EveryNSeconds": 60}``
    - ``CommitmentFrequency.never()`` → ``"Never"``
    """

    def __init__(self, value: Union[str, Dict[str, int]]):
        self._value = value

    @staticmethod
    def every_update() -> "CommitmentFrequency":
        """Commit after every write/block update (default, strongest freshness)."""
        return CommitmentFrequency("EveryUpdate")

    @staticmethod
    def every_n_blocks(n: int) -> "CommitmentFrequency":
        """Commit every ``n`` blocks processed."""
        return CommitmentFrequency({"EveryNBlocks": n})

    @staticmethod
    def every_n_seconds(n: int) -> "CommitmentFrequency":
        """Commit at least every ``n`` seconds."""
        return CommitmentFrequency({"EveryNSeconds": n})

    @staticmethod
    def never() -> "CommitmentFrequency":
        """No on-chain commitments."""
        return CommitmentFrequency("Never")

    def to_json(self) -> Union[str, Dict[str, int]]:
        """Return the JSON-serializable representation."""
        return self._value

    def __repr__(self) -> str:
        return f"CommitmentFrequency({self._value!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CommitmentFrequency):
            return self._value == other._value
        return NotImplemented


# ============================================================================
# Data Types
# ============================================================================


@dataclass
class PrivacyConfig:
    """Privacy configuration for a subgrove.

    Attributes:
        allowed_indexers: Optional list of indexer DIDs permitted to index
            this subgrove. When None, any indexer may participate.
        commitment_frequency: How often privacy commitments are posted
            on-chain for verification.
    """

    allowed_indexers: Optional[List[str]] = None
    commitment_frequency: CommitmentFrequency = field(
        default_factory=CommitmentFrequency.every_update
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result: Dict[str, Any] = {
            "commitment_frequency": self.commitment_frequency.to_json(),
        }
        if self.allowed_indexers is not None:
            result["allowed_indexers"] = self.allowed_indexers
        return result


@dataclass
class EncryptedKeyGrant:
    """An encrypted key grant for subgrove access.

    Represents an encryption key that has been granted to a specific DID,
    allowing them to decrypt data stored in a privacy-enabled subgrove.

    Mirrors the Rust ``EncryptedKeyGrant`` struct from ``willow-types``.

    Attributes:
        grantee_did: The DID that received the key grant.
        key_epoch: The key epoch this grant belongs to.
        grantee_public_key_id: ID of the grantee's public key used for ECDH.
        ephemeral_public_key: The 32-byte X25519 ephemeral public key: hex,
            bytes, or a list of ints (the API answers a list of ints).
        encrypted_key: nonce || ciphertext || auth_tag, as hex, bytes, or a
            list of ints.
        granted_by: The DID that issued the grant.
        granted_at: Unix timestamp of when the grant was issued.
    """

    grantee_did: str
    key_epoch: int
    grantee_public_key_id: str
    ephemeral_public_key: Union[str, bytes, List[int]]
    encrypted_key: Union[str, bytes, List[int]]
    granted_by: str
    granted_at: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "grantee_did": self.grantee_did,
            "key_epoch": self.key_epoch,
            "grantee_public_key_id": self.grantee_public_key_id,
            "ephemeral_public_key": self.ephemeral_public_key,
            "encrypted_key": self.encrypted_key,
            "granted_by": self.granted_by,
            "granted_at": self.granted_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EncryptedKeyGrant":
        """Create an EncryptedKeyGrant from a dictionary.

        Args:
            data: Dictionary with grant fields.

        Returns:
            EncryptedKeyGrant instance.
        """
        return cls(
            grantee_did=data["grantee_did"],
            key_epoch=data["key_epoch"],
            grantee_public_key_id=data["grantee_public_key_id"],
            ephemeral_public_key=data["ephemeral_public_key"],
            encrypted_key=data["encrypted_key"],
            granted_by=data["granted_by"],
            granted_at=data["granted_at"],
        )


# ============================================================================
# Privacy Operations
# ============================================================================


class PrivacyOperations:
    """Privacy operations for Willow client.

    Provides methods for managing encryption key grants on privacy-enabled
    subgroves, including granting, revoking, rotating, and querying keys.
    """

    def __init__(self, client: "WillowClient"):
        self.client = client

    @require_auth
    async def get_my_key_grant(
        self, subgrove_id: str
    ) -> EncryptedKeyGrant:
        """Get the current user's key grant for a subgrove.

        Retrieves the encryption key grant issued to the identity's DID for
        the specified subgrove (``GET /key-grants/{subgrove_id}/{did}``,
        nonce-signed: the node names a caller only for that form). The
        grant is what the API serves; it is not verified.

        Args:
            subgrove_id: Subgrove identifier.

        Returns:
            The authenticated user's EncryptedKeyGrant.

        Raises:
            NotAuthenticatedError: If the client is not authenticated.
            NotFoundError: If no key grant exists for the authenticated DID.
        """
        did = self.client._did
        response = await self.client._request(
            "GET",
            f"/key-grants/{subgrove_id}/{did}",
            authenticated=True,
            read=True,
        )
        return EncryptedKeyGrant.from_dict(response["data"])

    @require_auth
    async def list_key_grantees(
        self, subgrove_id: str
    ) -> List[str]:
        """List the DIDs holding a key grant for a subgrove.

        ``GET /key-grants/{subgrove_id}``, nonce-signed: only the subgrove's
        owner can list grantees. Read one grantee's grant with
        ``GET /key-grants/{subgrove_id}/{did}`` (the grantee's own through
        ``get_my_key_grant``). The list is what the API serves; it is not
        verified.

        Args:
            subgrove_id: Subgrove identifier.

        Returns:
            The grantee DIDs.

        Raises:
            NotAuthenticatedError: If the client is not authenticated.
            PermissionDeniedError: If the caller lacks permission to list grants.
        """
        response = await self.client._request(
            "GET",
            f"/key-grants/{subgrove_id}",
            authenticated=True,
            read=True,
        )
        return list(response.get("data") or [])

    @require_auth
    async def get_key_grant_proof(
        self, subgrove_id: str, did: str
    ) -> Dict[str, Any]:
        """Get the API's GroveDB proof for a key grant.

        ``GET /proof/key-grant/{subgrove_id}/{did}``, nonce-signed: only the
        grantee or the subgrove's owner may read it. The SDK does not verify
        the proof, and it binds nothing until checked against a trusted root.

        Args:
            subgrove_id: Subgrove identifier.
            did: The grantee DID.

        Returns:
            ``{"proof": <hex>, "subgrove_id", "grantee_did"}`` as the API
            serves it.

        Raises:
            NotAuthenticatedError: If the client is not authenticated.
        """
        response = await self.client._request(
            "GET",
            f"/proof/key-grant/{subgrove_id}/{did}",
            authenticated=True,
            read=True,
        )
        return response["data"]

    @require_auth
    async def grant_subgrove_key(
        self,
        subgrove_id: str,
        grant: EncryptedKeyGrant,
    ) -> Dict[str, Any]:
        """Grant an encryption key to a DID for a subgrove.

        Submits a GrantSubgroveKey transaction to ``POST /tx/submit``, sent
        by the identity set on the client and signed over
        ``grant_subgrove_key_message``, which binds every field of the grant
        and the nonce.

        Args:
            subgrove_id: Subgrove identifier.
            grant: The EncryptedKeyGrant to issue.

        Returns:
            The ``{tx_hash, code, log, did, nonce}`` of the accepted
            transaction.

        Raises:
            NotAuthenticatedError: If the client is not authenticated.
            ValueError: A signed text field holds a line break, a field is
                out of range, or the node would refuse the grant: the
                subgrove ID is empty or holds ':', the grantee isn't a DID,
                the ephemeral public key isn't 32 bytes, or the encrypted key
                isn't 1 to 128 bytes. Nothing is sent.
            TransactionError: CheckTx refused the transaction.
        """
        tx = GrantSubgroveKeyTx(
            subgrove_id=subgrove_id,
            encrypted_key_grant=grant,
            sender_did=self.client._did,
            public_key_id=self.client._public_key_id or "",
        )
        return await self.client._sign_and_submit("GrantSubgroveKey", tx)

    @require_auth
    async def revoke_subgrove_key(
        self,
        subgrove_id: str,
        revokee_did: str,
    ) -> Dict[str, Any]:
        """Revoke a DID's encryption key for a subgrove.

        Submits a RevokeSubgroveKey transaction to ``POST /tx/submit``, sent
        by the identity set on the client and signed over
        ``revoke_subgrove_key_message``.

        Args:
            subgrove_id: Subgrove identifier.
            revokee_did: The DID whose key grant should be revoked.

        Returns:
            The ``{tx_hash, code, log, did, nonce}`` of the accepted
            transaction.

        Raises:
            NotAuthenticatedError: If the client is not authenticated.
            ValueError: The subgrove ID is empty or holds ':', or the revokee
                isn't a DID: the node refuses either. Nothing is sent.
            TransactionError: CheckTx refused the transaction.
        """
        tx = RevokeSubgroveKeyTx(
            subgrove_id=subgrove_id,
            revokee_did=revokee_did,
            sender_did=self.client._did,
            public_key_id=self.client._public_key_id or "",
        )
        return await self.client._sign_and_submit("RevokeSubgroveKey", tx)

    @require_auth
    async def rotate_subgrove_key(
        self,
        subgrove_id: str,
        new_epoch: int,
        new_grants: List[EncryptedKeyGrant],
    ) -> Dict[str, Any]:
        """Rotate the encryption key for a subgrove.

        Submits a RotateSubgroveKey transaction to ``POST /tx/submit`` that
        advances the key epoch and re-issues encrypted keys to all authorized
        DIDs, sent by the identity set on the client and signed over
        ``rotate_subgrove_key_message``, which binds every grant, their
        count and order, and the nonce. Previous epoch keys become invalid
        for new data.

        Args:
            subgrove_id: Subgrove identifier.
            new_epoch: The new key epoch number (the current one plus one).
            new_grants: List of EncryptedKeyGrant instances for the new epoch,
                one per authorized DID.

        Returns:
            The ``{tx_hash, code, log, did, nonce}`` of the accepted
            transaction.

        Raises:
            NotAuthenticatedError: If the client is not authenticated.
            ValueError: A signed text field holds a line break, a field is
                out of range, or the node would refuse the rotation: the
                subgrove ID is empty or holds ':', there are not 1 to 1000
                grants, or a grant's grantee isn't a DID or its key material
                isn't the size CheckTx takes. Nothing is sent.
            TransactionError: CheckTx refused the transaction.
        """
        tx = RotateSubgroveKeyTx(
            subgrove_id=subgrove_id,
            new_epoch=new_epoch,
            new_grants=list(new_grants),
            sender_did=self.client._did,
            public_key_id=self.client._public_key_id or "",
        )
        return await self.client._sign_and_submit("RotateSubgroveKey", tx)
