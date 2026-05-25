"""File storage operations for Willow.

Upload, download, and manage files in FileStorage subgroves.
Files are chunked locally, manifests go through consensus,
and chunks are uploaded to storage nodes.
"""

import hashlib
import math
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import httpx

DEFAULT_CHUNK_SIZE = 262_144  # 256 KB


@dataclass
class FileManifest:
    """File manifest metadata."""

    file_key: str
    filename: str
    content_type: str
    total_size: int
    content_hash: str
    chunk_count: int
    chunk_size: int
    chunk_merkle_root: str
    owner_did: str
    created_at: int = 0
    updated_at: int = 0
    encrypted: bool = False
    storage_nodes: List[str] = field(default_factory=list)


class FileOperations:
    """File storage operations."""

    def __init__(self, api_url: str, get_headers=None, api_key: Optional[str] = None):
        self._api_url = api_url
        self._api_key = api_key
        base_headers = get_headers or (lambda: {})
        if api_key:
            self._get_headers = lambda: {**base_headers(), "X-API-Key": api_key}
        else:
            self._get_headers = base_headers

    async def upload(
        self,
        subgrove_id: str,
        file_key: str,
        filename: str,
        data: bytes,
        storage_node_endpoint: str,
        signing: Optional[Dict[str, Any]] = None,
    ) -> FileManifest:
        """Upload a file to a FileStorage subgrove.

        Args:
            subgrove_id: Subgrove ID.
            file_key: Unique key for the file.
            filename: Original filename.
            data: Raw file bytes.
            storage_node_endpoint: URL of the storage node for chunk uploads.
            signing: Optional signing parameters dict with keys:
                owner_did, private_key, public_key_id, sign_function, nonce.
                sign_function should accept (message: str, private_key: str)
                and return a hex-encoded signature string.
        """
        chunk_size = DEFAULT_CHUNK_SIZE
        chunks = _chunk_data(data, chunk_size)
        chunk_count = len(chunks)

        content_hash = hashlib.sha256(data).hexdigest()
        chunk_hashes = [hashlib.sha256(c).digest() for c in chunks]
        chunk_merkle_root = _compute_merkle_root(chunk_hashes).hex()

        # Build signing fields
        owner_did = ""
        signature: Any = []
        public_key_id = ""
        nonce = 0
        if signing:
            owner_did = signing["owner_did"]
            public_key_id = signing["public_key_id"]
            nonce = signing.get("nonce", 0)
            message = f"store_file:{subgrove_id}:{file_key}:{content_hash}:{len(data)}"
            signature = signing["sign_function"](message, signing["private_key"])

        # Submit StoreFileManifestTx to consensus
        manifest_tx = {
            "StoreFileManifest": {
                "subgrove_id": subgrove_id,
                "file_key": file_key,
                "filename": filename,
                "content_type": _guess_content_type(filename),
                "total_size": len(data),
                "content_hash": content_hash,
                "chunk_count": chunk_count,
                "chunk_size": chunk_size,
                "chunk_merkle_root": chunk_merkle_root,
                "owner_did": owner_did,
                "signature": signature,
                "public_key_id": public_key_id,
                "nonce": nonce,
            }
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._api_url}/broadcast_tx",
                json=manifest_tx,
                headers=self._get_headers(),
            )
            resp.raise_for_status()

        # Upload chunks to storage node
        async with httpx.AsyncClient() as client:
            for i, chunk in enumerate(chunks):
                url = (
                    f"{storage_node_endpoint}/upload/{subgrove_id}/{file_key}"
                    f"?chunk_index={i}&chunk_count={chunk_count}&content_hash={content_hash}"
                )
                await client.post(url, content=chunk)

        return FileManifest(
            file_key=file_key,
            filename=filename,
            content_type=_guess_content_type(filename),
            total_size=len(data),
            content_hash=content_hash,
            chunk_count=chunk_count,
            chunk_size=chunk_size,
            chunk_merkle_root=chunk_merkle_root,
            owner_did=owner_did,
            storage_nodes=[storage_node_endpoint],
        )

    async def download(
        self,
        subgrove_id: str,
        file_key: str,
        storage_node_endpoint: str,
    ) -> bytes:
        """Download a file from a FileStorage subgrove."""
        manifest = await self.metadata(subgrove_id, file_key)

        chunks = []
        async with httpx.AsyncClient() as client:
            for i in range(manifest.chunk_count):
                url = (
                    f"{storage_node_endpoint}/chunk/{subgrove_id}/{file_key}/{i}"
                    f"?content_hash={manifest.content_hash}"
                )
                resp = await client.get(url)
                resp.raise_for_status()
                chunks.append(resp.content)

        # Verify chunk Merkle root
        chunk_hashes = [hashlib.sha256(c).digest() for c in chunks]
        computed_merkle_root = _compute_merkle_root(chunk_hashes).hex()
        if computed_merkle_root != manifest.chunk_merkle_root:
            raise ValueError("Chunk Merkle root mismatch")

        file_data = b"".join(chunks)

        # Verify content hash
        computed_hash = hashlib.sha256(file_data).hexdigest()
        if computed_hash != manifest.content_hash:
            raise ValueError("Content hash mismatch")

        return file_data

    async def metadata(
        self, subgrove_id: str, file_key: str
    ) -> FileManifest:
        """Get file manifest metadata."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self._api_url}/files/{subgrove_id}/{file_key}",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            data = resp.json()
            return FileManifest(**data)

    async def list(self, subgrove_id: str) -> List[FileManifest]:
        """List all files in a subgrove."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self._api_url}/files/{subgrove_id}",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            data = resp.json()
            return [FileManifest(**f) for f in data.get("files", [])]

    async def delete(
        self,
        subgrove_id: str,
        file_key: str,
        signing: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Delete a file (submits DeleteFileManifestTx to consensus).

        Args:
            subgrove_id: Subgrove ID.
            file_key: Key of the file to delete.
            signing: Optional signing parameters dict with keys:
                owner_did, private_key, public_key_id, sign_function, nonce.
                sign_function should accept (message: str, private_key: str)
                and return a hex-encoded signature string.
        """
        owner_did = ""
        signature: Any = []
        public_key_id = ""
        nonce = 0
        if signing:
            owner_did = signing["owner_did"]
            public_key_id = signing["public_key_id"]
            nonce = signing.get("nonce", 0)
            message = f"delete_file:{subgrove_id}:{file_key}"
            signature = signing["sign_function"](message, signing["private_key"])

        delete_tx = {
            "DeleteFileManifest": {
                "subgrove_id": subgrove_id,
                "file_key": file_key,
                "owner_did": owner_did,
                "signature": signature,
                "public_key_id": public_key_id,
                "nonce": nonce,
            }
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._api_url}/broadcast_tx",
                json=delete_tx,
                headers=self._get_headers(),
            )
            resp.raise_for_status()


    async def unregister_storage_node(
        self,
        node_did: str,
        signing: Dict[str, Any],
    ) -> None:
        """Unregister a storage node (submits UnregisterStorageNode to consensus).

        Args:
            node_did: DID of the storage node to unregister.
            signing: Signing parameters dict with keys:
                private_key, public_key_id, sign_function, nonce.
                sign_function should accept (message: str, private_key: str)
                and return a hex-encoded signature string.
        """
        message = f"unregister_storage_node:{node_did}"
        signature = signing["sign_function"](message, signing["private_key"])

        tx = {
            "UnregisterStorageNode": {
                "node_did": node_did,
                "signature": signature,
                "public_key_id": signing["public_key_id"],
                "nonce": signing.get("nonce", 0),
            }
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._api_url}/broadcast_tx",
                json=tx,
                headers=self._get_headers(),
            )
            resp.raise_for_status()


def _chunk_data(data: bytes, chunk_size: int) -> List[bytes]:
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def _compute_merkle_root(hashes: List[bytes]) -> bytes:
    if not hashes:
        return b"\x00" * 32
    # No early return for single-leaf: pad to [leaf, leaf] and hash.
    # This prevents availability proof forgery for single-chunk files.

    current = list(hashes)
    if len(current) == 1:
        current.append(current[0])
    while len(current) > 1:
        if len(current) % 2 != 0:
            current.append(current[-1])
        next_level = []
        for i in range(0, len(current), 2):
            h = hashlib.sha256(current[i] + current[i + 1]).digest()
            next_level.append(h)
        current = next_level
    return current[0]


_CONTENT_TYPES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "pdf": "application/pdf",
    "json": "application/json",
    "txt": "text/plain",
    "html": "text/html",
    "css": "text/css",
    "js": "application/javascript",
    "wasm": "application/wasm",
    "zip": "application/zip",
    "mp4": "video/mp4",
    "mp3": "audio/mpeg",
}


def encrypt_file(data: bytes, key: bytes) -> tuple:
    """Encrypt file data using XChaCha20-Poly1305.

    IMPORTANT: Uses XChaCha20-Poly1305 with a 24-byte nonce to match the
    Rust SDK and consensus layer. Files encrypted with this function are
    interoperable across all Willow SDKs.

    Requires the ``pynacl`` package: ``pip install pynacl``

    Args:
        data: Plaintext file data.
        key: 32-byte symmetric key from the subgrove key grant system.

    Returns:
        Tuple of (ciphertext_with_tag, nonce).
    """
    import os
    import nacl.bindings

    nonce = os.urandom(24)
    ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        data, None, nonce, key
    )
    return ciphertext, nonce


def decrypt_file(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt file data using XChaCha20-Poly1305.

    Requires the ``pynacl`` package: ``pip install pynacl``

    Args:
        ciphertext: Encrypted data (includes auth tag).
        key: 32-byte symmetric key.
        nonce: 24-byte nonce used during encryption.

    Returns:
        Decrypted plaintext bytes.
    """
    import nacl.bindings

    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext, None, nonce, key
    )


def _guess_content_type(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return _CONTENT_TYPES.get(ext, "application/octet-stream")
