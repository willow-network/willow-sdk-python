"""
GroveDB Hash Functions

All hash functions use BLAKE3, matching the Rust implementation.
"""

from typing import Union
from blake3 import blake3
from .types import CryptoHash, HASH_LENGTH, NULL_HASH, GroveDBVerificationError
from .varint import encode_varint


def blake3_hash(data: bytes) -> CryptoHash:
    """
    Compute BLAKE3 hash of data.

    Args:
        data: Data to hash

    Returns:
        32-byte hash
    """
    return blake3(data).digest()


def value_hash(value: bytes) -> CryptoHash:
    """
    Hash a value with its length prefix.

    value_hash(value) = BLAKE3(varint(value.length) || value)

    Args:
        value: Value to hash

    Returns:
        32-byte hash
    """
    length_prefix = encode_varint(len(value))
    return blake3_hash(length_prefix + value)


def kv_hash(key: bytes, value: bytes) -> CryptoHash:
    """
    Hash a key-value pair.

    kv_hash(key, value) = BLAKE3(varint(key.length) || key || value_hash(value))

    Args:
        key: Key bytes
        value: Value bytes

    Returns:
        32-byte hash
    """
    key_length_prefix = encode_varint(len(key))
    val_hash = value_hash(value)
    return blake3_hash(key_length_prefix + key + val_hash)


def kv_digest_to_kv_hash(key: bytes, val_hash: CryptoHash) -> CryptoHash:
    """
    Compute kv_hash from key and pre-computed value hash.

    kv_digest_to_kv_hash(key, value_hash) = BLAKE3(varint(key.length) || key || value_hash)

    Args:
        key: Key bytes
        val_hash: Pre-computed value hash

    Returns:
        32-byte hash
    """
    key_length_prefix = encode_varint(len(key))
    return blake3_hash(key_length_prefix + key + val_hash)


def node_hash(kv: CryptoHash, left: CryptoHash, right: CryptoHash) -> CryptoHash:
    """
    Hash a node with its children.

    node_hash(kv, left, right) = BLAKE3(kv || left || right)

    Args:
        kv: Key-value hash
        left: Left child hash
        right: Right child hash

    Returns:
        32-byte hash
    """
    return blake3_hash(kv + left + right)


def combine_hash(a: CryptoHash, b: CryptoHash) -> CryptoHash:
    """
    Combine two hashes.

    combine_hash(a, b) = BLAKE3(a || b)

    Args:
        a: First hash
        b: Second hash

    Returns:
        32-byte hash
    """
    return blake3_hash(a + b)


def hash_equals(a: CryptoHash, b: CryptoHash) -> bool:
    """
    Check if two hashes are equal.

    Args:
        a: First hash
        b: Second hash

    Returns:
        True if equal, False otherwise
    """
    if len(a) != len(b):
        return False
    return a == b


def is_null_hash(h: CryptoHash) -> bool:
    """
    Check if a hash is the null hash (all zeros).

    Args:
        h: Hash to check

    Returns:
        True if null hash, False otherwise
    """
    return hash_equals(h, NULL_HASH)


def hash_to_hex(h: CryptoHash) -> str:
    """
    Convert hash to hex string.

    Args:
        h: Hash bytes

    Returns:
        Hex string
    """
    return h.hex()


def hex_to_hash(hex_str: str) -> CryptoHash:
    """
    Convert hex string to hash.

    Args:
        hex_str: Hex string (with or without 0x prefix)

    Returns:
        Hash bytes

    Raises:
        GroveDBVerificationError: If invalid hex length
    """
    clean = hex_str.replace("0x", "").replace("0X", "")
    if len(clean) != HASH_LENGTH * 2:
        raise GroveDBVerificationError(
            f"Invalid hash hex length: {len(clean)}, expected {HASH_LENGTH * 2}"
        )
    return bytes.fromhex(clean)


def bytes_to_hex(data: bytes) -> str:
    """
    Convert bytes to hex string.

    Args:
        data: Bytes to convert

    Returns:
        Hex string
    """
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert hex string to bytes.

    Args:
        hex_str: Hex string (with or without 0x prefix)

    Returns:
        Bytes
    """
    clean = hex_str.replace("0x", "").replace("0X", "")
    return bytes.fromhex(clean)
