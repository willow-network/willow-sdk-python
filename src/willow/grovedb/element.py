"""
GroveDB Element Deserialization

Deserializes GroveDB Element types from their binary encoding.
"""

from typing import Optional, List, Tuple
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

    grovedb encodes an element with bincode 2's standard configuration,
    big-endian: the variant, lengths, sums, and counts are variable-length
    integers (signed ones zigzag-encoded). The whole input must be one
    element: trailing bytes are refused, not ignored.

    Args:
        data: Binary-encoded element

    Returns:
        Deserialized Element
    """
    reader = BincodeReader(data)
    element = _read_element(reader)
    if reader.has_more():
        raise GroveDBVerificationError(
            f"Trailing bytes after element: {len(data) - reader.position()} at offset {reader.position()}"
        )
    return element


def _read_element(reader: BincodeReader) -> Element:
    """Read an Element from a BincodeReader."""
    element_type = reader.read_varint(max_bytes=4)

    if element_type == ELEMENT_ITEM:
        value = reader.read_bytes()
        flags = _read_option_bytes(reader)
        return ItemElement(value=value, flags=flags)

    elif element_type == ELEMENT_REFERENCE:
        reference_type, height, path = _read_reference_path_type(reader)
        max_hop = reader.read_u8() if reader.read_option_tag() else None
        flags = _read_option_bytes(reader)
        return ReferenceElement(
            path=path, flags=flags, reference_type=reference_type, height=height, max_hop=max_hop
        )

    elif element_type == ELEMENT_TREE:
        root_key = _read_option_bytes(reader)
        flags = _read_option_bytes(reader)
        return TreeElement(root_key=root_key, flags=flags)

    elif element_type == ELEMENT_SUM_ITEM:
        value = reader.read_signed_varint()
        flags = _read_option_bytes(reader)
        return SumItemElement(value=value, flags=flags)

    elif element_type == ELEMENT_SUM_TREE:
        root_key = _read_option_bytes(reader)
        sum_value = reader.read_signed_varint()
        flags = _read_option_bytes(reader)
        return SumTreeElement(root_key=root_key, sum_value=sum_value, flags=flags)

    elif element_type == ELEMENT_BIG_SUM_TREE:
        root_key = _read_option_bytes(reader)
        sum_value = reader.read_signed_varint(max_bytes=16)
        flags = _read_option_bytes(reader)
        return BigSumTreeElement(root_key=root_key, sum_value=sum_value, flags=flags)

    elif element_type == ELEMENT_COUNT_TREE:
        root_key = _read_option_bytes(reader)
        count = reader.read_varint()
        flags = _read_option_bytes(reader)
        return CountTreeElement(root_key=root_key, count=count, flags=flags)

    elif element_type == ELEMENT_COUNT_SUM_TREE:
        root_key = _read_option_bytes(reader)
        count = reader.read_varint()
        sum_val = reader.read_signed_varint()
        flags = _read_option_bytes(reader)
        return CountSumTreeElement(root_key=root_key, count=count, sum=sum_val, flags=flags)

    else:
        raise GroveDBVerificationError(f"Unknown element type: {element_type}")


def _read_option_bytes(reader: BincodeReader) -> Optional[bytes]:
    """Read Option<Vec<u8>>."""
    if reader.read_option_tag():
        return reader.read_bytes()
    return None


def _read_segments(reader: BincodeReader) -> List[bytes]:
    """Read Vec<Vec<u8>>."""
    return [reader.read_bytes() for _ in range(reader.read_varint())]


# ReferencePathType variants, in grovedb's order: those with a u8 height
# before their path segments, and those with one key instead of a path.
_REFERENCE_WITH_HEIGHT = (1, 2, 3)
_REFERENCE_WITH_KEY = (4, 6)
_REFERENCE_TYPES = 7


def _read_reference_path_type(reader: BincodeReader) -> Tuple[int, Optional[int], List[bytes]]:
    """Read a ReferencePathType: its variant, its u8 height (for the variants
    that carry one), and its path segments (one key for a cousin or sibling
    reference)."""
    variant = reader.read_varint(max_bytes=4)
    if variant >= _REFERENCE_TYPES:
        raise GroveDBVerificationError(f"Unknown reference path type: {variant}")
    height = reader.read_u8() if variant in _REFERENCE_WITH_HEIGHT else None
    if variant in _REFERENCE_WITH_KEY:
        return variant, height, [reader.read_bytes()]
    return variant, height, _read_segments(reader)


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
