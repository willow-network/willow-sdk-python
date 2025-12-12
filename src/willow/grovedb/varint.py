"""
Varint Encoding/Decoding

LEB128-style variable-length integer encoding used by GroveDB.
"""

from typing import Tuple
from .types import GroveDBVerificationError


class VarintError(GroveDBVerificationError):
    """Error raised during varint decoding."""
    pass


def encode_varint(value: int) -> bytes:
    """
    Encode a number as a varint.

    Args:
        value: Non-negative integer to encode

    Returns:
        Encoded bytes
    """
    if value < 0:
        raise VarintError("Cannot encode negative value as unsigned varint")

    result = bytearray()
    while value > 0x7f:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Decode a varint from bytes.

    Args:
        data: Bytes to decode from
        offset: Starting offset

    Returns:
        Tuple of (value, bytes_read)

    Raises:
        VarintError: If varint is malformed
    """
    value = 0
    shift = 0
    bytes_read = 0

    while offset + bytes_read < len(data):
        byte = data[offset + bytes_read]
        bytes_read += 1

        value |= (byte & 0x7f) << shift

        if (byte & 0x80) == 0:
            return value, bytes_read

        shift += 7

        if shift > 35:
            raise VarintError("Varint too long")

    raise VarintError("Unexpected end of varint")


def decode_signed_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Decode a signed varint (zigzag encoded).

    Args:
        data: Bytes to decode from
        offset: Starting offset

    Returns:
        Tuple of (value, bytes_read)
    """
    unsigned, bytes_read = decode_varint(data, offset)
    # Zigzag decode: (n >> 1) ^ -(n & 1)
    signed = (unsigned >> 1) ^ -(unsigned & 1)
    return signed, bytes_read


def decode_varint64(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Decode an unsigned 64-bit varint.

    Args:
        data: Bytes to decode from
        offset: Starting offset

    Returns:
        Tuple of (value, bytes_read)
    """
    value = 0
    shift = 0
    bytes_read = 0

    while offset + bytes_read < len(data):
        byte = data[offset + bytes_read]
        bytes_read += 1

        value |= (byte & 0x7f) << shift

        if (byte & 0x80) == 0:
            return value, bytes_read

        shift += 7

        if shift > 70:
            raise VarintError("Varint too long")

    raise VarintError("Unexpected end of varint")


def decode_signed_varint64(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Decode a 64-bit signed varint (zigzag encoded).

    Args:
        data: Bytes to decode from
        offset: Starting offset

    Returns:
        Tuple of (value, bytes_read)
    """
    value = 0
    shift = 0
    bytes_read = 0

    while offset + bytes_read < len(data):
        byte = data[offset + bytes_read]
        bytes_read += 1

        value |= (byte & 0x7f) << shift

        if (byte & 0x80) == 0:
            # Zigzag decode for signed
            signed = (value >> 1) ^ -(value & 1)
            return signed, bytes_read

        shift += 7

        if shift > 70:
            raise VarintError("Varint too long")

    raise VarintError("Unexpected end of varint")
