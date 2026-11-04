"""
Bincode Decoder for GroveDB Proofs

Decodes the outer bincode-encoded GroveDBProof structure, and the element
bytes inside it. grovedb encodes both with bincode 2's standard
configuration, big-endian: every integer wider than a byte (an enum's
variant, a length, a sum or count) is a variable-length integer (see
``read_varint``), and a ``u8`` or ``bool`` is one byte.
"""

from typing import Dict
from .types import (
    GroveDBProof,
    GroveDBProofV0,
    LayerProof,
    ProveOptions,
    GroveDBVerificationError
)
from .hash import bytes_to_hex


class BincodeReader:
    """Bincode reader for big-endian encoded data."""

    def __init__(self, data: bytes):
        """
        Initialize reader with data.

        Args:
            data: Bytes to read from
        """
        self.data = data
        self.offset = 0

    def position(self) -> int:
        """Get current position."""
        return self.offset

    def has_more(self) -> bool:
        """Check if there's more data."""
        return self.offset < len(self.data)

    def read_u8(self) -> int:
        """Read a single byte."""
        if self.offset >= len(self.data):
            raise GroveDBVerificationError("Unexpected end of data reading u8")
        value = self.data[self.offset]
        self.offset += 1
        return value

    def read_u16(self) -> int:
        """Read a big-endian u16."""
        if self.offset + 2 > len(self.data):
            raise GroveDBVerificationError("Unexpected end of data reading u16")
        value = (self.data[self.offset] << 8) | self.data[self.offset + 1]
        self.offset += 2
        return value

    def read_u32(self) -> int:
        """Read a big-endian u32."""
        if self.offset + 4 > len(self.data):
            raise GroveDBVerificationError("Unexpected end of data reading u32")
        value = (
            (self.data[self.offset] << 24) |
            (self.data[self.offset + 1] << 16) |
            (self.data[self.offset + 2] << 8) |
            self.data[self.offset + 3]
        )
        self.offset += 4
        return value & 0xFFFFFFFF  # Ensure unsigned

    def read_u64(self) -> int:
        """Read a big-endian u64."""
        if self.offset + 8 > len(self.data):
            raise GroveDBVerificationError("Unexpected end of data reading u64")
        value = 0
        for i in range(8):
            value = (value << 8) | self.data[self.offset + i]
        self.offset += 8
        return value

    def read_bool(self) -> bool:
        """Read a boolean."""
        value = self.read_u8()
        if value not in (0, 1):
            raise GroveDBVerificationError(f"Invalid boolean value: {value}")
        return value == 1

    def read_option_tag(self) -> bool:
        """Read an Option's tag: whether a value follows."""
        tag = self.read_u8()
        if tag not in (0, 1):
            raise GroveDBVerificationError(f"Invalid Option tag: {tag}")
        return tag == 1

    def read_varint(self, max_bytes: int = 8) -> int:
        """Read a bincode variable-length unsigned integer.

        A first byte below 251 is the value; 251, 252, 253, and 254 are
        followed by the value as a big-endian u16, u32, u64, and u128.
        ``max_bytes`` is the width of the integer read (4 for a u32 such as
        an enum's variant, 8 for a u64 or a length, 16 for a u128): a wider
        form is refused, as bincode refuses it.
        """
        first = self.read_u8()
        if first < 251:
            return first
        width = {251: 2, 252: 4, 253: 8, 254: 16}.get(first)
        if width is None or width > max_bytes:
            raise GroveDBVerificationError(
                f"Invalid varint discriminant {first} for a {max_bytes * 8}-bit integer"
            )
        return int.from_bytes(self.read_raw_bytes(width), byteorder="big")

    def read_signed_varint(self, max_bytes: int = 8) -> int:
        """Read a bincode variable-length signed integer (zigzag-encoded)."""
        n = self.read_varint(max_bytes)
        return (n >> 1) if n % 2 == 0 else -((n >> 1) + 1)

    def read_bytes(self) -> bytes:
        """Read a length-prefixed byte array (the length a varint)."""
        length = self.read_varint()
        if length > 1_000_000_000:
            raise GroveDBVerificationError(f"Suspiciously large byte array length: {length}")
        if self.offset + length > len(self.data):
            raise GroveDBVerificationError(f"Unexpected end of data reading {length} bytes")
        result = self.data[self.offset:self.offset + length]
        self.offset += length
        return result

    def read_raw_bytes(self, length: int) -> bytes:
        """Read raw bytes without length prefix."""
        if self.offset + length > len(self.data):
            raise GroveDBVerificationError(f"Unexpected end of data reading {length} raw bytes")
        result = self.data[self.offset:self.offset + length]
        self.offset += length
        return result


def decode_layer_proof(reader: BincodeReader) -> LayerProof:
    """
    Decode a LayerProof from bincode.

    Args:
        reader: BincodeReader instance

    Returns:
        Decoded LayerProof
    """
    # merk_proof: Vec<u8>
    merk_proof = reader.read_bytes()

    # lower_layers: BTreeMap<Key, LayerProof>
    map_length = reader.read_varint()
    lower_layers: Dict[str, LayerProof] = {}

    for _ in range(map_length):
        # Key is Vec<u8>
        key = reader.read_bytes()
        key_hex = bytes_to_hex(key)

        # Value is LayerProof (recursive)
        layer_proof = decode_layer_proof(reader)

        lower_layers[key_hex] = layer_proof

    return LayerProof(merk_proof=merk_proof, lower_layers=lower_layers)


def decode_prove_options(reader: BincodeReader) -> ProveOptions:
    """
    Decode ProveOptions from bincode.

    Args:
        reader: BincodeReader instance

    Returns:
        Decoded ProveOptions
    """
    return ProveOptions(
        decrease_limit_on_empty_sub_query_result=reader.read_bool()
    )


def decode_grovedb_proof_v0(reader: BincodeReader) -> GroveDBProofV0:
    """
    Decode GroveDBProofV0 from bincode.

    Args:
        reader: BincodeReader instance

    Returns:
        Decoded GroveDBProofV0
    """
    root_layer = decode_layer_proof(reader)
    prove_options = decode_prove_options(reader)

    return GroveDBProofV0(root_layer=root_layer, prove_options=prove_options)


def decode_grovedb_proof(data: bytes) -> GroveDBProof:
    """
    Decode a GroveDBProof from bincode-encoded bytes.

    Args:
        data: Raw proof bytes

    Returns:
        Decoded GroveDBProof

    Raises:
        GroveDBVerificationError: If proof format is invalid
    """
    reader = BincodeReader(data)

    # The enum's variant: a u32 varint
    variant = reader.read_varint(max_bytes=4)

    if variant != 0:
        raise GroveDBVerificationError(f"Unknown GroveDBProof version: {variant}")

    proof = decode_grovedb_proof_v0(reader)

    if reader.has_more():
        raise GroveDBVerificationError(
            f"Trailing bytes after the proof: {len(data) - reader.position()} at offset {reader.position()}"
        )

    return GroveDBProof(version=0, proof=proof)
