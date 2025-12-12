"""
GroveDB Element Deserialization

Deserializes GroveDB Element types from their binary encoding.
"""

from typing import Optional, List
from .types import (
    Element,
    ItemElement,
    ReferenceElement,
    TreeElement,
    SumTreeElement,
    SumItemElement,
    BigSumTreeElement,
    CountTreeElement,
    CountSumTreeElement,
    GroveDBVerificationError
)
from .bincode import BincodeReader

# Element type discriminants
ELEMENT_ITEM = 0
ELEMENT_REFERENCE = 1
ELEMENT_TREE = 2
ELEMENT_SUM_ITEM = 3
ELEMENT_SUM_TREE = 4
ELEMENT_BIG_SUM_TREE = 5
ELEMENT_COUNT_TREE = 6
ELEMENT_COUNT_SUM_TREE = 7


def deserialize_element(data: bytes) -> Element:
    """
    Deserialize a GroveDB Element from bytes.

    Args:
        data: Binary-encoded element

    Returns:
        Deserialized Element
    """
    reader = BincodeReader(data)
    return _read_element(reader)


def _read_element(reader: BincodeReader) -> Element:
    """Read an Element from a BincodeReader."""
    element_type = reader.read_u8()

    if element_type == ELEMENT_ITEM:
        value = reader.read_bytes()
        flags = _read_option_bytes(reader)
        return ItemElement(value=value, flags=flags)

    elif element_type == ELEMENT_REFERENCE:
        path = _read_reference_path(reader)
        flags = _read_option_bytes(reader)
        return ReferenceElement(path=path, flags=flags)

    elif element_type == ELEMENT_TREE:
        root_key = _read_option_bytes(reader)
        flags = _read_option_bytes(reader)
        return TreeElement(root_key=root_key, flags=flags)

    elif element_type == ELEMENT_SUM_ITEM:
        value = _read_i64(reader)
        flags = _read_option_bytes(reader)
        return SumItemElement(value=value, flags=flags)

    elif element_type == ELEMENT_SUM_TREE:
        root_key = _read_option_bytes(reader)
        sum_value = _read_i64(reader)
        flags = _read_option_bytes(reader)
        return SumTreeElement(root_key=root_key, sum_value=sum_value, flags=flags)

    elif element_type == ELEMENT_BIG_SUM_TREE:
        root_key = _read_option_bytes(reader)
        sum_value = _read_i128(reader)
        flags = _read_option_bytes(reader)
        return BigSumTreeElement(root_key=root_key, sum_value=sum_value, flags=flags)

    elif element_type == ELEMENT_COUNT_TREE:
        root_key = _read_option_bytes(reader)
        count = _read_u64(reader)
        flags = _read_option_bytes(reader)
        return CountTreeElement(root_key=root_key, count=count, flags=flags)

    elif element_type == ELEMENT_COUNT_SUM_TREE:
        root_key = _read_option_bytes(reader)
        count = _read_u64(reader)
        sum_val = _read_i64(reader)
        flags = _read_option_bytes(reader)
        return CountSumTreeElement(root_key=root_key, count=count, sum=sum_val, flags=flags)

    else:
        raise GroveDBVerificationError(f"Unknown element type: {element_type}")


def _read_option_bytes(reader: BincodeReader) -> Optional[bytes]:
    """Read Option<Vec<u8>>."""
    has_value = reader.read_bool()
    if has_value:
        return reader.read_bytes()
    return None


def _read_reference_path(reader: BincodeReader) -> List[List[bytes]]:
    """Read reference path (Vec<Vec<u8>>)."""
    length = reader.read_u64()
    path: List[List[bytes]] = []

    for _ in range(length):
        segment_length = reader.read_u64()
        segment: List[bytes] = []
        for _ in range(segment_length):
            segment.append(reader.read_bytes())
        path.append(segment)

    return path


def _read_i64(reader: BincodeReader) -> int:
    """Read i64 (big-endian)."""
    raw = reader.read_raw_bytes(8)
    return int.from_bytes(raw, byteorder='big', signed=True)


def _read_u64(reader: BincodeReader) -> int:
    """Read u64 (big-endian)."""
    raw = reader.read_raw_bytes(8)
    return int.from_bytes(raw, byteorder='big', signed=False)


def _read_i128(reader: BincodeReader) -> int:
    """Read i128 (big-endian)."""
    raw = reader.read_raw_bytes(16)
    return int.from_bytes(raw, byteorder='big', signed=True)


def is_tree_element(element: Element) -> bool:
    """
    Check if an element is a tree type (has subtrees).

    Args:
        element: Element to check

    Returns:
        True if element is a tree type
    """
    return isinstance(element, (
        TreeElement,
        SumTreeElement,
        BigSumTreeElement,
        CountTreeElement,
        CountSumTreeElement
    ))


def has_root_key(element: Element) -> bool:
    """
    Check if an element has a root key (non-empty tree).

    Args:
        element: Element to check

    Returns:
        True if element has a root key
    """
    if isinstance(element, (TreeElement, SumTreeElement, BigSumTreeElement,
                           CountTreeElement, CountSumTreeElement)):
        return element.root_key is not None
    return False


def get_tree_feature_type(element: Element) -> Optional[str]:
    """
    Get the tree feature type from an element.

    Args:
        element: Element to get feature type from

    Returns:
        Feature type string or None
    """
    if isinstance(element, TreeElement):
        return "BasicMerkNode"
    elif isinstance(element, SumTreeElement):
        return "SummedMerkNode"
    elif isinstance(element, BigSumTreeElement):
        return "BigSummedMerkNode"
    elif isinstance(element, CountTreeElement):
        return "CountedMerkNode"
    elif isinstance(element, CountSumTreeElement):
        return "CountedSummedMerkNode"
    return None
