"""
Merk Operation Decoder

Decodes the binary format of Merk proof operations.
"""

from typing import Iterator, Optional, List
from .types import (
    MerkOp,
    MerkNode,
    TreeFeatureType,
    PushOp,
    PushInvertedOp,
    ParentOp,
    ChildOp,
    ParentInvertedOp,
    ChildInvertedOp,
    HashNode,
    KVHashNode,
    KVNode,
    KVValueHashNode,
    KVDigestNode,
    KVRefValueHashNode,
    KVValueHashFeatureTypeNode,
    BasicMerkNode,
    SummedMerkNode,
    BigSummedMerkNode,
    CountedMerkNode,
    CountedSummedMerkNode,
    CryptoHash,
    HASH_LENGTH,
    GroveDBVerificationError
)
from .varint import decode_signed_varint64, decode_varint64

# Op codes for Merk operations
OP_PUSH_HASH = 0x01
OP_PUSH_KVHASH = 0x02
OP_PUSH_KV = 0x03
OP_PUSH_KVVALUEHASH = 0x04
OP_PUSH_KVDIGEST = 0x05
OP_PUSH_KVREFVALUEHASH = 0x06
OP_PUSH_KVVALUEHASH_FEATURE_TYPE = 0x07
OP_PUSH_INVERTED_HASH = 0x08
OP_PUSH_INVERTED_KVHASH = 0x09
OP_PUSH_INVERTED_KV = 0x0a
OP_PUSH_INVERTED_KVVALUEHASH = 0x0b
OP_PUSH_INVERTED_KVDIGEST = 0x0c
OP_PUSH_INVERTED_KVREFVALUEHASH = 0x0d
OP_PUSH_INVERTED_KVVALUEHASH_FEATURE_TYPE = 0x0e
OP_PARENT = 0x10
OP_CHILD = 0x11
OP_PARENT_INVERTED = 0x12
OP_CHILD_INVERTED = 0x13

# Feature type encoding
FEATURE_BASIC = 0x00
FEATURE_SUMMED = 0x01
FEATURE_BIG_SUMMED = 0x02
FEATURE_COUNTED = 0x03
FEATURE_COUNTED_SUMMED = 0x04


class MerkDecoder:
    """Decoder class for iterating through Merk operations."""

    def __init__(self, data: bytes):
        """
        Initialize decoder with proof bytes.

        Args:
            data: Merk proof bytes
        """
        self.data = data
        self.offset = 0

    def has_more(self) -> bool:
        """Check if there are more operations to decode."""
        return self.offset < len(self.data)

    def next(self) -> Optional[MerkOp]:
        """
        Decode the next operation.

        Returns:
            Next MerkOp or None if at end
        """
        if not self.has_more():
            return None

        op_code = self.data[self.offset]
        self.offset += 1

        # Push variants
        if op_code == OP_PUSH_HASH:
            return PushOp(node=self._decode_hash())
        elif op_code == OP_PUSH_KVHASH:
            return PushOp(node=self._decode_kv_hash())
        elif op_code == OP_PUSH_KV:
            return PushOp(node=self._decode_kv())
        elif op_code == OP_PUSH_KVVALUEHASH:
            return PushOp(node=self._decode_kv_value_hash())
        elif op_code == OP_PUSH_KVDIGEST:
            return PushOp(node=self._decode_kv_digest())
        elif op_code == OP_PUSH_KVREFVALUEHASH:
            return PushOp(node=self._decode_kv_ref_value_hash())
        elif op_code == OP_PUSH_KVVALUEHASH_FEATURE_TYPE:
            return PushOp(node=self._decode_kv_value_hash_feature_type())

        # PushInverted variants
        elif op_code == OP_PUSH_INVERTED_HASH:
            return PushInvertedOp(node=self._decode_hash())
        elif op_code == OP_PUSH_INVERTED_KVHASH:
            return PushInvertedOp(node=self._decode_kv_hash())
        elif op_code == OP_PUSH_INVERTED_KV:
            return PushInvertedOp(node=self._decode_kv())
        elif op_code == OP_PUSH_INVERTED_KVVALUEHASH:
            return PushInvertedOp(node=self._decode_kv_value_hash())
        elif op_code == OP_PUSH_INVERTED_KVDIGEST:
            return PushInvertedOp(node=self._decode_kv_digest())
        elif op_code == OP_PUSH_INVERTED_KVREFVALUEHASH:
            return PushInvertedOp(node=self._decode_kv_ref_value_hash())
        elif op_code == OP_PUSH_INVERTED_KVVALUEHASH_FEATURE_TYPE:
            return PushInvertedOp(node=self._decode_kv_value_hash_feature_type())

        # Tree operations
        elif op_code == OP_PARENT:
            return ParentOp()
        elif op_code == OP_CHILD:
            return ChildOp()
        elif op_code == OP_PARENT_INVERTED:
            return ParentInvertedOp()
        elif op_code == OP_CHILD_INVERTED:
            return ChildInvertedOp()

        else:
            raise GroveDBVerificationError(f"Unknown op code: 0x{op_code:02x}")

    def _decode_hash(self) -> MerkNode:
        """Decode a Hash node."""
        hash_bytes = self._read_bytes(HASH_LENGTH)
        return HashNode(hash=hash_bytes)

    def _decode_kv_hash(self) -> MerkNode:
        """Decode a KVHash node."""
        kv_hash = self._read_bytes(HASH_LENGTH)
        return KVHashNode(kv_hash=kv_hash)

    def _decode_kv(self) -> MerkNode:
        """Decode a KV node."""
        key_len = self.data[self.offset]
        self.offset += 1
        key = self._read_bytes(key_len)
        value_len = self._read_u16()
        value = self._read_bytes(value_len)
        return KVNode(key=key, value=value)

    def _decode_kv_value_hash(self) -> MerkNode:
        """Decode a KVValueHash node."""
        key_len = self.data[self.offset]
        self.offset += 1
        key = self._read_bytes(key_len)
        value_len = self._read_u16()
        value = self._read_bytes(value_len)
        value_hash = self._read_bytes(HASH_LENGTH)
        return KVValueHashNode(key=key, value=value, value_hash=value_hash)

    def _decode_kv_digest(self) -> MerkNode:
        """Decode a KVDigest node."""
        key_len = self.data[self.offset]
        self.offset += 1
        key = self._read_bytes(key_len)
        value_hash = self._read_bytes(HASH_LENGTH)
        return KVDigestNode(key=key, value_hash=value_hash)

    def _decode_kv_ref_value_hash(self) -> MerkNode:
        """Decode a KVRefValueHash node."""
        key_len = self.data[self.offset]
        self.offset += 1
        key = self._read_bytes(key_len)
        value_len = self._read_u16()
        value = self._read_bytes(value_len)
        value_hash = self._read_bytes(HASH_LENGTH)
        return KVRefValueHashNode(key=key, value=value, value_hash=value_hash)

    def _decode_kv_value_hash_feature_type(self) -> MerkNode:
        """Decode a KVValueHashFeatureType node."""
        key_len = self.data[self.offset]
        self.offset += 1
        key = self._read_bytes(key_len)
        value_len = self._read_u16()
        value = self._read_bytes(value_len)
        value_hash = self._read_bytes(HASH_LENGTH)
        feature_type = self._decode_feature_type()
        return KVValueHashFeatureTypeNode(
            key=key,
            value=value,
            value_hash=value_hash,
            feature_type=feature_type
        )

    def _decode_feature_type(self) -> TreeFeatureType:
        """Decode TreeFeatureType."""
        feature_code = self.data[self.offset]
        self.offset += 1

        if feature_code == FEATURE_BASIC:
            return BasicMerkNode()

        elif feature_code == FEATURE_SUMMED:
            value, bytes_read = decode_signed_varint64(self.data, self.offset)
            self.offset += bytes_read
            return SummedMerkNode(sum=value)

        elif feature_code == FEATURE_BIG_SUMMED:
            # Big sum is encoded as 16 bytes (i128) in little-endian
            sum_bytes = self._read_bytes(16)
            sum_value = int.from_bytes(sum_bytes, byteorder='little', signed=True)
            return BigSummedMerkNode(sum=sum_value)

        elif feature_code == FEATURE_COUNTED:
            value, bytes_read = decode_varint64(self.data, self.offset)
            self.offset += bytes_read
            return CountedMerkNode(count=value)

        elif feature_code == FEATURE_COUNTED_SUMMED:
            count, count_bytes = decode_varint64(self.data, self.offset)
            self.offset += count_bytes
            sum_val, sum_bytes = decode_signed_varint64(self.data, self.offset)
            self.offset += sum_bytes
            return CountedSummedMerkNode(count=count, sum=sum_val)

        else:
            raise GroveDBVerificationError(f"Unknown feature type: 0x{feature_code:02x}")

    def _read_u16(self) -> int:
        """Read a big-endian u16."""
        if self.offset + 2 > len(self.data):
            raise GroveDBVerificationError("Unexpected end of data reading u16")
        value = (self.data[self.offset] << 8) | self.data[self.offset + 1]
        self.offset += 2
        return value

    def _read_bytes(self, length: int) -> bytes:
        """Read a fixed number of bytes."""
        if self.offset + length > len(self.data):
            raise GroveDBVerificationError(
                f"Unexpected end of data reading {length} bytes"
            )
        result = self.data[self.offset:self.offset + length]
        self.offset += length
        return result

    def __iter__(self) -> Iterator[MerkOp]:
        """Iterator implementation."""
        while True:
            op = self.next()
            if op is None:
                break
            yield op


def decode_merk_ops(data: bytes) -> List[MerkOp]:
    """
    Decode all Merk operations from bytes.

    Args:
        data: Merk proof bytes

    Returns:
        List of MerkOp
    """
    decoder = MerkDecoder(data)
    return list(decoder)
