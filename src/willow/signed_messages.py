"""The messages data and file write transactions are signed over.

Each message is a set of lines joined by ``\\n`` (the byte 0x0A), with no
trailing newline, as UTF-8: the kind first, then one ``Label: value`` line
per field, the nonce last. It binds the transaction's nonce and every field
the transaction writes. Text fields go in verbatim, with no escaping or
normalization. Variable-length bytes appear as the lowercase hex SHA-256 of
the exact bytes the transaction carries; 32-byte fields appear as their
lowercase hex. Numbers are unsigned decimal.

A text field holding a line break (the byte 0x0A) is refused
(``ValueError``): the node refuses such a transaction, and the lines must read
back one way only.

The nonce in the message is the nonce in the transaction. A write that lands
in a block and is refused there after its signature and nonce verify still
spends its nonce; to retry, sign again under the next free nonce.

Ed25519 signs the message's UTF-8 bytes; secp256k1 signs their Keccak-256
(see ``willow.auth.sign_challenge``).
"""

import hashlib
from typing import Optional, Sequence, Tuple, Union

ByteField = Union[bytes, bytearray, str, Sequence[int]]

__all__ = [
    "store_data_message",
    "store_file_manifest_message",
    "delete_file_manifest_message",
]


def _field(label: str, value: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    # U+000A is the only code point whose UTF-8 holds the byte 0x0A.
    if "\n" in value:
        raise ValueError(f"{label} holds a line break, which a signed field can't")
    return f"{label}: {value}"


_U32_MAX = 2**32 - 1
_U64_MAX = 2**64 - 1


def _unsigned(label: str, value: int, maximum: int = _U64_MAX) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{label} must be an integer from 0 to {maximum}")
    return value


def _hex(label: str, value: ByteField, length: int) -> str:
    """``value`` (hex with or without ``0x``, bytes, or a list of ints) as lowercase hex."""
    if isinstance(value, str):
        raw = bytes.fromhex(value[2:] if value.startswith(("0x", "0X")) else value)
    elif isinstance(value, int):
        raise TypeError(f"{label} must be bytes, hex, or a list of ints")
    else:
        raw = bytes(value)
    if len(raw) != length:
        raise ValueError(f"{label} must be {length} bytes, got {len(raw)}")
    return raw.hex()


def store_data_message(
    subgrove_id: str,
    key: str,
    owner_did: str,
    data: Union[bytes, bytearray, str],
    nonce: int,
) -> str:
    """The message a StoreData transaction is signed over.

    ``data`` is the exact bytes the transaction's ``data`` field carries (a
    ``str`` is taken as its UTF-8 bytes); the message binds their SHA-256::

        StoreData
        Subgrove: <subgrove_id>
        Key: <key>
        Owner: <owner_did>
        DataHash: <hex SHA-256 of data>
        Nonce: <nonce>
    """
    if isinstance(data, str):
        data_bytes = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray, memoryview)):
        data_bytes = bytes(data)
    else:
        raise TypeError("data must be bytes or str")
    return "\n".join([
        "StoreData",
        _field("Subgrove", subgrove_id),
        _field("Key", key),
        _field("Owner", owner_did),
        f"DataHash: {hashlib.sha256(data_bytes).hexdigest()}",
        f"Nonce: {_unsigned('Nonce', nonce)}",
    ])


def store_file_manifest_message(
    subgrove_id: str,
    file_key: str,
    owner_did: str,
    filename: str,
    content_type: str,
    total_size: int,
    content_hash: ByteField,
    chunk_count: int,
    chunk_size: int,
    chunk_merkle_root: ByteField,
    nonce: int,
    encryption: Optional[Tuple[int, ByteField]] = None,
) -> str:
    """The message a StoreFileManifest transaction is signed over.

    ``content_hash`` and ``chunk_merkle_root`` are 32 bytes (bytes, hex, or a
    list of ints). ``encryption`` is ``None`` when the transaction carries no
    ``encryption``, else ``(key_epoch, nonce)`` with the 24-byte XChaCha20
    nonce::

        StoreFileManifest
        Subgrove: <subgrove_id>
        Key: <file_key>
        Owner: <owner_did>
        Filename: <filename>
        ContentType: <content_type>
        TotalSize: <total_size>
        ContentHash: <hex content_hash>
        ChunkCount: <chunk_count>
        ChunkSize: <chunk_size>
        ChunkMerkleRoot: <hex chunk_merkle_root>
        Encryption: none | <key_epoch>:<hex nonce>
        Nonce: <nonce>
    """
    if encryption is None:
        encryption_line = "Encryption: none"
    else:
        key_epoch, encryption_nonce = encryption
        encryption_line = (
            f"Encryption: {_unsigned('Encryption key epoch', key_epoch)}:"
            f"{_hex('Encryption nonce', encryption_nonce, 24)}"
        )
    return "\n".join([
        "StoreFileManifest",
        _field("Subgrove", subgrove_id),
        _field("Key", file_key),
        _field("Owner", owner_did),
        _field("Filename", filename),
        _field("ContentType", content_type),
        f"TotalSize: {_unsigned('TotalSize', total_size)}",
        f"ContentHash: {_hex('ContentHash', content_hash, 32)}",
        f"ChunkCount: {_unsigned('ChunkCount', chunk_count, _U32_MAX)}",
        f"ChunkSize: {_unsigned('ChunkSize', chunk_size, _U32_MAX)}",
        f"ChunkMerkleRoot: {_hex('ChunkMerkleRoot', chunk_merkle_root, 32)}",
        encryption_line,
        f"Nonce: {_unsigned('Nonce', nonce)}",
    ])


def delete_file_manifest_message(
    subgrove_id: str,
    file_key: str,
    owner_did: str,
    nonce: int,
) -> str:
    """The message a DeleteFileManifest transaction is signed over::

        DeleteFileManifest
        Subgrove: <subgrove_id>
        Key: <file_key>
        Owner: <owner_did>
        Nonce: <nonce>
    """
    return "\n".join([
        "DeleteFileManifest",
        _field("Subgrove", subgrove_id),
        _field("Key", file_key),
        _field("Owner", owner_did),
        f"Nonce: {_unsigned('Nonce', nonce)}",
    ])
