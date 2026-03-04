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
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from .errors import WillowError
from .utils import require_auth

if TYPE_CHECKING:
    from .client import WillowClient

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================


class CommitmentFrequency(str, Enum):
    """Frequency at which privacy commitments are posted on-chain.

    Controls the trade-off between privacy overhead and verification latency.
    """

    EVERY_BLOCK = "every_block"
    EVERY_EPOCH = "every_epoch"
    ON_DEMAND = "on_demand"


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
    commitment_frequency: CommitmentFrequency = CommitmentFrequency.EVERY_EPOCH

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result: Dict[str, Any] = {
            "commitment_frequency": self.commitment_frequency.value,
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
        ephemeral_public_key: Hex-encoded 32-byte X25519 ephemeral public key.
        encrypted_key: Hex-encoded nonce || ciphertext || auth_tag.
        granted_by: The DID that issued the grant.
        granted_at: Unix timestamp of when the grant was issued.
    """

    grantee_did: str
    key_epoch: int
    grantee_public_key_id: str
    ephemeral_public_key: str
    encrypted_key: str
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
        self, app_id: str, subgrove_id: str
    ) -> EncryptedKeyGrant:
        """Get the current user's key grant for a subgrove.

        Retrieves the encryption key grant issued to the authenticated DID
        for the specified subgrove.

        Args:
            app_id: Application identifier.
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
            f"/key-grants/{app_id}/{subgrove_id}/{did}",
            authenticated=True,
        )
        return EncryptedKeyGrant.from_dict(response["data"])

    @require_auth
    async def list_key_grantees(
        self, app_id: str, subgrove_id: str
    ) -> List[EncryptedKeyGrant]:
        """List all key grants for a subgrove.

        Returns all encryption key grants that have been issued for the
        specified subgrove. Typically only the subgrove owner or admins
        can list all grantees.

        Args:
            app_id: Application identifier.
            subgrove_id: Subgrove identifier.

        Returns:
            List of EncryptedKeyGrant instances.

        Raises:
            NotAuthenticatedError: If the client is not authenticated.
            PermissionDeniedError: If the caller lacks permission to list grants.
        """
        response = await self.client._request(
            "GET",
            f"/key-grants/{app_id}/{subgrove_id}",
            authenticated=True,
        )
        grants_data = response.get("data", [])
        return [EncryptedKeyGrant.from_dict(g) for g in grants_data]

    async def get_key_grant_proof(
        self, app_id: str, subgrove_id: str, did: str
    ) -> Dict[str, Any]:
        """Get a Merkle proof for a key grant.

        Retrieves a cryptographic proof that a specific key grant exists
        (or does not exist) in the authenticated data store, enabling
        trustless verification of grant status.

        Args:
            app_id: Application identifier.
            subgrove_id: Subgrove identifier.
            did: The DID to get the key grant proof for.

        Returns:
            Proof data dictionary including proof hex and value.
        """
        response = await self.client._request(
            "GET",
            f"/proof/key-grant/{app_id}/{subgrove_id}/{did}",
        )
        return response["data"]

    @require_auth
    async def grant_subgrove_key(
        self,
        app_id: str,
        subgrove_id: str,
        grant: EncryptedKeyGrant,
    ) -> Dict[str, Any]:
        """Grant an encryption key to a DID for a subgrove.

        Broadcasts a GrantSubgroveKey transaction to the consensus layer,
        recording the encrypted key grant on-chain.

        Args:
            app_id: Application identifier.
            subgrove_id: Subgrove identifier.
            grant: The EncryptedKeyGrant to issue.

        Returns:
            Transaction result dictionary with broadcast status.

        Raises:
            NotAuthenticatedError: If the client is not authenticated.
            PermissionDeniedError: If the caller is not the subgrove owner.
        """
        payload = {
            "app_id": app_id,
            "subgrove_id": subgrove_id,
            "grant": grant.to_dict(),
        }
        response = await self.client._request(
            "POST",
            "/tx/grant-subgrove-key",
            json=payload,
            authenticated=True,
        )
        return response.get("data", {})

    @require_auth
    async def revoke_subgrove_key(
        self,
        app_id: str,
        subgrove_id: str,
        revokee_did: str,
    ) -> Dict[str, Any]:
        """Revoke a DID's encryption key for a subgrove.

        Broadcasts a RevokeSubgroveKey transaction to the consensus layer,
        removing the specified DID's key grant.

        Args:
            app_id: Application identifier.
            subgrove_id: Subgrove identifier.
            revokee_did: The DID whose key grant should be revoked.

        Returns:
            Transaction result dictionary with broadcast status.

        Raises:
            NotAuthenticatedError: If the client is not authenticated.
            PermissionDeniedError: If the caller is not the subgrove owner.
        """
        payload = {
            "app_id": app_id,
            "subgrove_id": subgrove_id,
            "revokee_did": revokee_did,
        }
        response = await self.client._request(
            "POST",
            "/tx/revoke-subgrove-key",
            json=payload,
            authenticated=True,
        )
        return response.get("data", {})

    @require_auth
    async def rotate_subgrove_key(
        self,
        app_id: str,
        subgrove_id: str,
        new_epoch: int,
        new_grants: List[EncryptedKeyGrant],
    ) -> Dict[str, Any]:
        """Rotate the encryption key for a subgrove.

        Broadcasts a RotateSubgroveKey transaction that advances the key
        epoch and re-issues encrypted keys to all authorized DIDs. Previous
        epoch keys become invalid for new data.

        Args:
            app_id: Application identifier.
            subgrove_id: Subgrove identifier.
            new_epoch: The new key epoch number (must be greater than current).
            new_grants: List of EncryptedKeyGrant instances for the new epoch,
                one per authorized DID.

        Returns:
            Transaction result dictionary with broadcast status.

        Raises:
            NotAuthenticatedError: If the client is not authenticated.
            PermissionDeniedError: If the caller is not the subgrove owner.
            ValidationError: If new_epoch is not greater than the current epoch.
        """
        payload = {
            "app_id": app_id,
            "subgrove_id": subgrove_id,
            "new_epoch": new_epoch,
            "new_grants": [g.to_dict() for g in new_grants],
        }
        response = await self.client._request(
            "POST",
            "/tx/rotate-subgrove-key",
            json=payload,
            authenticated=True,
        )
        return response.get("data", {})
